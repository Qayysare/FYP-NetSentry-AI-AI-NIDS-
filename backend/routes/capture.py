from flask import Blueprint, current_app, request
from database import database_cursor
from services.live_ai_service import (
    ContinuousMonitoringSession,
    LiveAIAnalysisError,
    analyse_completed_live_capture,
)
from services.tshark_service import TSharkError, TSharkService
from utils.helpers import admin_required, analyst_or_admin_required, failure, success
from services.security_log import log_security_event

capture_bp = Blueprint("capture", __name__, url_prefix="/api/capture")
service = None
monitoring_session = None
monitoring_mode = "manual"
monitoring_interface = None
monitoring_interface_name = None
monitoring_last_error = None
monitoring_stopped_by_operator = False


def get_service():
    global service
    if service is None:
        service = TSharkService(current_app.config["TSHARK_PATH"])
    return service


def store_flows(records):
    flows = get_service().aggregate(records)
    if not flows:
        return 0
    with database_cursor() as (_connection, cursor):
        for flow in flows:
            cursor.execute("INSERT INTO network_traffic (source_ip, destination_ip, source_port, destination_port, protocol, packet_count, bytes_transferred) VALUES (%s, %s, %s, %s, %s, %s, %s)", tuple(flow.values()))
    return len(flows)


def _monitoring_status(capture_status, after_result_id=0):
    """Add safe sensor-mode context to the existing Stage 5F status payload."""
    if monitoring_session is None:
        data = {
            **capture_status,
            "worker_running": False,
            "active_flows": 0,
            "completed_flows": 0,
            "prediction_count": 0,
            "malicious_flow_count": 0,
            "stored_threat_count": 0,
            "duplicate_suppressed_count": 0,
            "ai_flows": [],
            "latest_result_id": 0,
        }
    else:
        data = {
            **monitoring_session.snapshot(after_result_id),
            "interface_id": capture_status["interface_id"],
            "packet_buffer_count": capture_status["packet_count"],
        }
    return {
        **data,
        "mode": monitoring_mode,
        "interface": monitoring_interface,
        "interface_name": monitoring_interface_name,
        "last_error": monitoring_last_error,
        "stopped_by_operator": monitoring_stopped_by_operator,
    }


def start_monitoring(interface_id, mode="manual"):
    """Start the one shared Stage 5F monitoring pipeline for either mode."""
    global monitoring_session, monitoring_mode, monitoring_interface
    global monitoring_interface_name, monitoring_last_error, monitoring_stopped_by_operator
    if mode not in {"manual", "autonomous"}:
        raise LiveAIAnalysisError("Monitoring mode is not supported.")
    if current_app.extensions.get("flow_predictor") is None:
        raise LiveAIAnalysisError("The AI prediction service is unavailable.")

    configured_id = str(interface_id or "").strip()
    if not configured_id:
        raise TSharkError("A monitoring interface must be configured.")
    interfaces = get_service().interfaces()
    selected_interface = TSharkService.resolve_interface(configured_id, interfaces)
    if selected_interface is None:
        raise TSharkError("The configured monitoring interface is unavailable.")
    if get_service().status()["running"]:
        raise TSharkError("A monitoring session is already running.")

    session = ContinuousMonitoringSession(
        current_app._get_current_object(),
        current_app.extensions["flow_predictor"],
        current_app.config["FLOW_TIMEOUT_SECONDS"],
        current_app.config["THREAT_DEDUP_WINDOW_SECONDS"],
        current_app.config["MAX_MONITOR_ACTIVE_FLOWS"],
        current_app.config["MAX_MONITOR_RESULTS"],
        current_app.config["MAX_MONITOR_QUEUE"],
        current_app.config["MONITOR_POLL_SECONDS"],
    )
    session.start()
    try:
        # Capture uses the current discovered ID. Status retains the configured
        # friendly value so operators can recognise the intended adapter.
        get_service().start(selected_interface["id"], session.submit_packet)
    except TSharkError:
        session.stop()
        raise

    monitoring_session = session
    monitoring_mode = mode
    monitoring_interface = configured_id
    monitoring_interface_name = selected_interface.get("friendly_name") or selected_interface["name"]
    monitoring_last_error = None
    monitoring_stopped_by_operator = False
    event_type = "MONITORING_AUTONOMOUS_STARTED" if mode == "autonomous" else "MONITORING_STARTED"
    log_security_event(event_type, "AI-NIDS Sensor", f"{mode.title()} monitoring started on the configured interface.", "Low")
    return _monitoring_status(get_service().status())


def stop_monitoring(stopped_by_operator=True):
    """Stop the one shared pipeline and preserve Stage 3 flow storage."""
    global monitoring_stopped_by_operator
    records = get_service().stop()
    stored = store_flows(records)
    if monitoring_session is not None:
        ai_result = monitoring_session.stop()
    else:
        # Preserve the original stop-time batch path for a capture created
        # before continuous-session state is available.
        ai_result = analyse_completed_live_capture(
            records,
            current_app.extensions.get("flow_predictor"),
            current_app.config["FLOW_TIMEOUT_SECONDS"],
            current_app.config["THREAT_DEDUP_WINDOW_SECONDS"],
        )
    monitoring_stopped_by_operator = stopped_by_operator
    log_security_event("MONITORING_STOPPED", "AI-NIDS Sensor", "Monitoring stopped and remaining flows were processed.", "Low")
    return {
        "captured_packets": ai_result.get("packets_captured", len(records)),
        "stored_flows": stored,
        "ai_flow_count": ai_result["completed_flows"] if "completed_flows" in ai_result else ai_result["ai_flow_count"],
        **ai_result,
        **_monitoring_status(get_service().status()),
    }


def _record_autonomous_failure(app, message):
    """Keep the web application usable when sensor configuration is invalid."""
    global monitoring_mode, monitoring_interface, monitoring_interface_name
    global monitoring_last_error, monitoring_stopped_by_operator
    monitoring_mode = "autonomous"
    monitoring_interface = app.config.get("MONITOR_INTERFACE") or None
    monitoring_interface_name = None
    monitoring_last_error = message
    monitoring_stopped_by_operator = False
    log_security_event("MONITORING_START_FAILED", "AI-NIDS Sensor", "Autonomous monitoring could not start. Check the configured interface.", "Medium")


def start_autonomous_monitoring(app, allow_testing=False):
    """Opt-in sensor startup, called only by the real serving process."""
    if not app.config.get("AUTO_MONITORING"):
        return False
    if app.config.get("TESTING") and not allow_testing:
        return False
    with app.app_context():
        try:
            start_monitoring(app.config.get("MONITOR_INTERFACE"), "autonomous")
            app.logger.info("Autonomous AI-NIDS monitoring started successfully")
            return True
        except (TSharkError, LiveAIAnalysisError) as error:
            safe_message = str(error)
            _record_autonomous_failure(app, safe_message)
            app.logger.error("Autonomous AI-NIDS monitoring could not start: %s", safe_message)
            return False


def shutdown_monitoring(app):
    """Best-effort cleanup for the direct Flask server process on shutdown."""
    with app.app_context():
        try:
            if get_service().status()["running"]:
                stop_monitoring(stopped_by_operator=False)
        except (TSharkError, LiveAIAnalysisError):
            app.logger.exception("AI-NIDS monitoring could not be stopped during shutdown")


@capture_bp.get("/interfaces")
@analyst_or_admin_required
def interfaces():
    try:
        return success(get_service().interfaces(), "Capture interfaces retrieved successfully")
    except TSharkError as error:
        return failure(str(error), 503)


@capture_bp.get("/status")
@analyst_or_admin_required
def status():
    after_result_id = max(request.args.get("after", default=0, type=int) or 0, 0)
    capture_status = get_service().status()
    return success(_monitoring_status(capture_status, after_result_id), "Capture monitoring status retrieved successfully")


@capture_bp.post("/start")
@admin_required
def start_capture():
    interface_id = str((request.get_json(silent=True) or {}).get("interface_id", ""))
    if not interface_id:
        return failure("A capture interface is required")
    try:
        return success(start_monitoring(interface_id, "manual"), "Continuous monitoring started")
    except TSharkError as error:
        log_security_event("MONITORING_START_FAILED", "AI-NIDS Sensor", "Manual monitoring could not start. Check the selected interface.", "Medium")
        return failure(str(error), 409)
    except LiveAIAnalysisError as error:
        return failure(str(error), 503)


@capture_bp.post("/stop")
@admin_required
def stop_capture():
    try:
        return success(stop_monitoring(), "Monitoring stopped, remaining flows were analysed, and summaries stored")
    except TSharkError as error:
        return failure(str(error), 409)
    except LiveAIAnalysisError as error:
        current_app.logger.exception("Live capture stopped but AI analysis could not complete")
        return failure(str(error), 503)
