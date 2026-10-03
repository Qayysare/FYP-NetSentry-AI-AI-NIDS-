"""Safe Stage 5F monitoring-worker verification with exact database cleanup."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from database import database_cursor  # noqa: E402
from routes import capture as capture_routes  # noqa: E402
from services.live_ai_service import ContinuousMonitoringSession  # noqa: E402


class ControlledPredictor:
    """Deterministic safe outputs used only to test orchestration and policy."""

    labels = {80: "PortScan", 21: "FTP-Patator", 22: "SSH-Patator", 443: "DDoS"}

    def predict_flow(self, flow):
        return {
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],
            "source_port": flow["source_port"],
            "destination_port": flow["destination_port"],
            "protocol": flow["protocol"],
            "classification": self.labels.get(flow["destination_port"], "BENIGN"),
            "confidence": 0.95,
        }


def packet(source, destination, source_port, destination_port, timestamp, tcp_fin=False, protocol="TCP"):
    return {
        "source_ip": source,
        "destination_ip": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "timestamp": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "packet_length": 80,
        "payload_length": 40,
        "tcp_fin": tcp_fin,
    }


def wait_for(session, expected, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if session.snapshot(0)["prediction_count"] >= expected:
            return True
        time.sleep(0.05)
    return False


def main():
    app = create_app()
    app.config["TESTING"] = True
    source_ips = [f"198.51.100.{value}" for value in range(241, 246)]
    before_ids = set()
    with app.app_context():
        with database_cursor() as (_connection, cursor):
            placeholders = ", ".join(["%s"] * len(source_ips))
            cursor.execute(f"SELECT threat_id FROM threats WHERE source_ip IN ({placeholders})", source_ips)
            before_ids = {row["threat_id"] for row in cursor.fetchall()}

    session = ContinuousMonitoringSession(app, ControlledPredictor(), 1, 300, 10, 20, 20, 0.5)
    session.start()
    timestamp = time.time()
    # Four malicious and one BENIGN bidirectional TCP flows are completed by FIN.
    for offset, port in enumerate((80, 21, 22, 443, 53)):
        source = source_ips[offset]
        session.submit_packet(packet(source, "203.0.113.240", 50000 + offset, port, timestamp + offset * 0.01, True))
        session.submit_packet(packet("203.0.113.240", source, port, 50000 + offset, timestamp + offset * 0.01 + 0.001, True))
    # Duplicate PortScan verifies existing persistence deduplication.
    session.submit_packet(packet(source_ips[0], "203.0.113.240", 50100, 80, timestamp + 0.1, True))
    session.submit_packet(packet("203.0.113.240", source_ips[0], 80, 50100, timestamp + 0.101, True))
    active_before_timeout = session.snapshot(0)["active_flows"]
    # A UDP flow remains active and is completed by periodic timeout processing.
    session.submit_packet(packet(source_ips[4], "203.0.113.241", 53000, 53, time.time(), protocol="UDP"))
    time.sleep(0.1)
    active_after_submit = session.snapshot(0)["active_flows"]
    before_stop_ready = wait_for(session, 7)
    before_stop = session.snapshot(0)
    route_client = app.test_client()
    with route_client.session_transaction() as browser_session:
        browser_session["user_id"] = 1
        browser_session["username"] = "stage5f-test"
        browser_session["role"] = "admin"
    capture_routes.monitoring_session = session
    live_results = route_client.get("/api/capture/status?after=0")
    latest_id = (live_results.get_json() or {}).get("data", {}).get("latest_result_id", 0)
    cursor_results = route_client.get(f"/api/capture/status?after={latest_id}")
    # This valid but unfinished flow is finalised only by the stop flush.
    session.submit_packet(packet("198.51.100.250", "203.0.113.250", 54000, 53, time.time()))
    final = session.stop()
    capture_routes.monitoring_session = None

    # A separate small session verifies that active-flow memory remains bounded
    # without prematurely classifying an incomplete flow just to free space.
    bounded = ContinuousMonitoringSession(app, ControlledPredictor(), 30, 300, 2, 5, 5, 0.5)
    bounded.start()
    for port in (7001, 7002, 7003):
        bounded.submit_packet(packet("198.51.100.251", "203.0.113.251", port, 53, time.time(), protocol="UDP"))
    time.sleep(0.2)
    bounded_before_stop = bounded.snapshot(0)
    bounded.stop()

    with app.app_context():
        with database_cursor() as (_connection, cursor):
            placeholders = ", ".join(["%s"] * len(source_ips))
            cursor.execute(f"SELECT threat_id FROM threats WHERE source_ip IN ({placeholders})", source_ips)
            created_ids = [row["threat_id"] for row in cursor.fetchall() if row["threat_id"] not in before_ids]
            if created_ids:
                cleanup = ", ".join(["%s"] * len(created_ids))
                cursor.execute(f"DELETE FROM threats WHERE threat_id IN ({cleanup})", created_ids)
            cursor.execute(f"SELECT threat_id FROM threats WHERE source_ip IN ({placeholders})", source_ips)
            cleaned = {row["threat_id"] for row in cursor.fetchall()} == before_ids

    classes = [item["classification"] for item in final["ai_flows"]]
    print(json.dumps({
        "active_flow_state_observed": active_before_timeout >= 0 and (active_after_submit >= 1 or bounded_before_stop["active_flows"] >= 1),
        "fin_flows_predicted_before_stop": before_stop_ready and before_stop["prediction_count"] >= 7,
        "timeout_flow_finalised_before_stop": before_stop["completed_flows"] >= 7,
        "live_results_available_through_status_api": live_results.status_code == 200 and len((live_results.get_json() or {}).get("data", {}).get("ai_flows", [])) >= 7,
        "status_cursor_avoids_duplicate_rows": cursor_results.status_code == 200 and not (cursor_results.get_json() or {}).get("data", {}).get("ai_flows", []),
        "active_flow_limit_enforced": bounded_before_stop["active_flows"] == 2 and bounded_before_stop["dropped_new_flow_packets"] == 1,
        "benign_not_persisted": final["stored_threat_count"] == 4,
        "controlled_classes_present": all(label in classes for label in ("PortScan", "FTP-Patator", "SSH-Patator", "DDoS")),
        "deduplication_active": final["duplicate_suppressed_count"] == 1,
        "stop_flush_completed": final["completed_flows"] == 8 and final["prediction_count"] == 8,
        "worker_stopped": not final["worker_running"] and not final["running"],
        "created_ids_cleaned": cleaned,
    }, indent=2))


if __name__ == "__main__":
    main()
