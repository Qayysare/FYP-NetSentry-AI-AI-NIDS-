"""Stage 5A service verification using demo packets and temporary controlled results."""
from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from database import database_cursor  # noqa: E402
from services.live_ai_service import analyse_completed_live_capture  # noqa: E402
from services.tshark_service import TSharkService  # noqa: E402


class ControlledPredictor:
    """Safe orchestration test double; it does not represent network traffic."""

    labels = ("PortScan", "FTP-Patator", "SSH-Patator", "DDoS")

    def predict_flows(self, flows):
        predictions = []
        for index, flow in enumerate(flows):
            classification = self.labels[index] if index < len(self.labels) else "BENIGN"
            predictions.append({
                "source_ip": flow["source_ip"],
                "destination_ip": flow["destination_ip"],
                "source_port": flow["source_port"],
                "destination_port": flow["destination_port"],
                "protocol": flow["protocol"],
                "classification": classification,
                "confidence": 0.95,
            })
        return predictions


def threat_count() -> int:
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT COUNT(*) AS total FROM threats")
        return cursor.fetchone()["total"]


def delete_exact_threat_ids(threat_ids: list[int]) -> None:
    if not threat_ids:
        return
    placeholders = ", ".join(["%s"] * len(threat_ids))
    with database_cursor() as (_connection, cursor):
        cursor.execute(f"DELETE FROM threats WHERE threat_id IN ({placeholders})", threat_ids)


def main() -> None:
    app = create_app()
    app.config["TESTING"] = True
    predictor = app.extensions["flow_predictor"]
    service = TSharkService(app.config["TSHARK_PATH"])
    packets = service.analyse_file(str(PROJECT_ROOT / "Wireshark" / "demo.pcapng"), 500)
    created_ids: list[int] = []

    with app.app_context():
        before_benign = threat_count()
        benign = analyse_completed_live_capture(
            packets, predictor, app.config["FLOW_TIMEOUT_SECONDS"], app.config["THREAT_DEDUP_WINDOW_SECONDS"]
        )
        after_benign = threat_count()
        try:
            controlled = analyse_completed_live_capture(
                packets, ControlledPredictor(), app.config["FLOW_TIMEOUT_SECONDS"], app.config["THREAT_DEDUP_WINDOW_SECONDS"]
            )
            created_ids = controlled["threat_ids"]
            repeated = analyse_completed_live_capture(
                packets, ControlledPredictor(), app.config["FLOW_TIMEOUT_SECONDS"], app.config["THREAT_DEDUP_WINDOW_SECONDS"]
            )
            placeholders = ", ".join(["%s"] * len(created_ids))
            with database_cursor() as (_connection, cursor):
                cursor.execute(
                    f"SELECT attack_type, source_ip, destination_ip, severity, confidence_score, status "
                    f"FROM threats WHERE threat_id IN ({placeholders})",
                    created_ids,
                )
                rows = cursor.fetchall()
        finally:
            delete_exact_threat_ids(created_ids)
        final_count = threat_count()

    rows_by_class = {row["attack_type"]: row for row in rows}
    expected_severities = {"PortScan": "Medium", "FTP-Patator": "High", "SSH-Patator": "High", "DDoS": "Critical"}
    verified = {
        label: (
            label in rows_by_class
            and rows_by_class[label]["severity"] == severity
            and abs(float(rows_by_class[label]["confidence_score"]) - 0.95) < 0.01
            and rows_by_class[label]["status"] == "New"
            and bool(rows_by_class[label]["source_ip"])
            and bool(rows_by_class[label]["destination_ip"])
        )
        for label, severity in expected_severities.items()
    }
    print(json.dumps({
        "model_loaded_once": predictor is app.extensions["flow_predictor"],
        "demo_packet_count": len(packets),
        "benign_flow_count": benign["ai_flow_count"],
        "benign_class_summary": benign["class_summary"],
        "benign_stored_threat_count": benign["stored_threat_count"],
        "benign_threat_table_unchanged": before_benign == after_benign,
        "controlled_stored_count": controlled["stored_threat_count"],
        "controlled_duplicate_suppressed": repeated["duplicate_suppressed_count"],
        "controlled_records_verified": verified,
        "controlled_ids_cleaned": final_count == after_benign,
    }, indent=2))


if __name__ == "__main__":
    main()
