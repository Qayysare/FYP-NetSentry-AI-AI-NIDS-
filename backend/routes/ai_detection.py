"""Flask endpoint for Stage 4 AI analysis of uploaded PCAP files."""
from pathlib import Path

from flask import Blueprint, current_app, request
from werkzeug.utils import secure_filename

from ml.predictor import PredictionInputError
from routes.capture import get_service
from routes.pcap import ALLOWED_EXTENSIONS
from services.held_out_validation import HeldOutValidationError, build_validation_summary
from services.threat_persistence import ThreatPersistenceError, persist_malicious_predictions
from services.threat_priority import ThreatPriorityError, assess_threat
from services.tshark_service import TSharkError
from utils.helpers import analyst_or_admin_required, failure, success
from services.security_log import log_security_event


ai_detection_bp = Blueprint("ai_detection", __name__, url_prefix="/api/ai")
SUPPORTED_CLASSES = ("BENIGN", "DDoS", "FTP-Patator", "PortScan", "SSH-Patator")


def _predictor():
    """Return the single predictor created by the Flask application factory."""
    return current_app.extensions.get("flow_predictor")


@ai_detection_bp.get("/validation-summary")
@analyst_or_admin_required
def validation_summary():
    """Return read-only held-out dataset evidence using the app-level predictor."""
    predictor = _predictor()
    if predictor is None:
        return failure("AI prediction service is unavailable", 503)
    try:
        return success(build_validation_summary(predictor), "Held-out validation completed")
    except HeldOutValidationError as error:
        current_app.logger.error("Held-out validation is unavailable: %s", error)
        return failure("Held-out validation data is unavailable", 503)
    except Exception:
        current_app.logger.exception("Held-out validation prediction failed")
        return failure("Held-out validation could not be completed", 503)


@ai_detection_bp.post("/analyze-pcap")
@analyst_or_admin_required
def analyze_pcap():
    """Parse one PCAP, aggregate completed flows, and return model predictions."""
    uploaded = request.files.get("capture_file")
    if not uploaded or not uploaded.filename:
        return failure("Choose a .pcap or .pcapng file")

    filename = secure_filename(uploaded.filename)
    if not filename or Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        return failure("Only .pcap and .pcapng files are supported")

    predictor = _predictor()
    if predictor is None:
        current_app.logger.error(
            "AI analysis requested while predictor is unavailable: %s",
            current_app.extensions.get("flow_predictor_error", "unknown reason"),
        )
        return failure("AI prediction service is unavailable", 503)

    folder = Path(current_app.config["PCAP_UPLOAD_FOLDER"])
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / filename
    uploaded.save(path)

    try:
        packets = get_service().analyse_file(str(path), current_app.config["MAX_PCAP_PACKETS"])
    except TSharkError as error:
        path.unlink(missing_ok=True)
        return failure(str(error), 400)
    if not packets:
        return failure("The capture contains no analysable packets", 422)

    try:
        flows = get_service().aggregate_bidirectional(packets, current_app.config["FLOW_TIMEOUT_SECONDS"])
    except Exception:
        current_app.logger.exception("Flow aggregation failed for AI PCAP analysis")
        return failure("Completed network flows could not be generated", 422)
    if not flows:
        return failure("The capture contains no analysable network flows", 422)

    try:
        predictions = predictor.predict_flows(flows)
    except PredictionInputError:
        current_app.logger.exception("Completed flow failed AI feature validation")
        return failure("Completed flow data is not valid for AI prediction", 422)
    except Exception:
        current_app.logger.exception("AI prediction failed")
        return failure("AI prediction could not be completed", 503)

    try:
        predictions = [
            {**prediction, **assess_threat(prediction["classification"], prediction["confidence"], flow)}
            for flow, prediction in zip(flows, predictions)
        ]
    except ThreatPriorityError:
        current_app.logger.exception("AI result could not be evaluated by the threat policy")
        return failure("AI prediction could not be evaluated by the threat policy", 503)

    summary = {label: 0 for label in SUPPORTED_CLASSES}
    for prediction in predictions:
        classification = prediction["classification"]
        if classification in summary:
            summary[classification] += 1

    malicious_count = sum(item["classification"] != "BENIGN" for item in predictions)
    severity_summary = {"Informational": 0, "Medium": 0, "High": 0, "Critical": 0}
    for prediction in predictions:
        severity_summary[prediction["severity"]] += 1
    requires_attention_count = sum(item["priority"] != "Monitor" for item in predictions)
    try:
        persistence = persist_malicious_predictions(
            predictions, current_app.config["THREAT_DEDUP_WINDOW_SECONDS"]
        )
    except ThreatPersistenceError:
        current_app.logger.exception("Validated AI threats could not be persisted")
        return failure("AI threats could not be stored", 503)
    data = {
        "filename": filename,
        "packet_count": len(packets),
        "flow_count": len(flows),
        "prediction_count": len(predictions),
        "summary": summary,
        "malicious_flow_count": malicious_count,
        "severity_summary": severity_summary,
        "requires_attention_count": requires_attention_count,
        "stored_threat_count": persistence["stored_threat_count"],
        "duplicate_suppressed_count": persistence["duplicate_suppressed_count"],
        "predictions": predictions,
    }
    log_security_event("PCAP_ANALYSIS", "AI Detection", f"PCAP analysis completed: {len(flows)} flows analysed, {malicious_count} malicious classifications.", "Low")
    return success(data, "AI analysis completed successfully")
