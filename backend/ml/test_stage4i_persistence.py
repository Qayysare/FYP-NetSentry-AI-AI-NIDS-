"""Stage 4I database verification with cleanup of only this test's inserted IDs."""
from __future__ import annotations

import io
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from mysql.connector import Error


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from database import database_cursor  # noqa: E402
from services.threat_persistence import (  # noqa: E402
    ThreatPersistenceError,
    persist_malicious_predictions,
)
from services.threat_priority import assess_threat  # noqa: E402


def _authenticated_client(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "stage4i-test"
        session["role"] = "soc_analyst"
    return client


def _controlled_prediction(classification: str, suffix: int) -> dict:
    confidence = 0.95
    return {
        "classification": classification,
        "confidence": confidence,
        "source_ip": f"198.51.100.{suffix}",
        "destination_ip": f"203.0.113.{suffix}",
        **assess_threat(classification, confidence),
    }


def _threat_count() -> int:
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT COUNT(*) AS total FROM threats")
        return cursor.fetchone()["total"]


def _remove_test_records(threat_ids: list[int]) -> None:
    if not threat_ids:
        return
    placeholders = ", ".join(["%s"] * len(threat_ids))
    with database_cursor() as (_connection, cursor):
        cursor.execute(f"DELETE FROM threats WHERE threat_id IN ({placeholders})", threat_ids)


def _controlled_database_records(threat_ids: list[int]) -> list[dict]:
    placeholders = ", ".join(["%s"] * len(threat_ids))
    with database_cursor() as (_connection, cursor):
        cursor.execute(
            f"SELECT threat_id, attack_type, source_ip, destination_ip, severity, confidence_score, status "
            f"FROM threats WHERE threat_id IN ({placeholders})",
            threat_ids,
        )
        return cursor.fetchall()


def main() -> None:
    demo_path = PROJECT_ROOT / "Wireshark" / "demo.pcapng"
    created_ids: list[int] = []
    with tempfile.TemporaryDirectory() as upload_folder:
        app = create_app()
        app.config.update(TESTING=True, PCAP_UPLOAD_FOLDER=upload_folder)
        client = _authenticated_client(app)
        with app.app_context():
            before_demo = _threat_count()
        with demo_path.open("rb") as demo_file:
            demo_response = client.post(
                "/api/ai/analyze-pcap",
                data={"capture_file": (demo_file, "demo.pcapng")},
                content_type="multipart/form-data",
            )
        demo_data = (demo_response.get_json() or {}).get("data", {})
        with app.app_context():
            after_demo = _threat_count()

        controlled = [
            _controlled_prediction("PortScan", 141),
            _controlled_prediction("FTP-Patator", 142),
            _controlled_prediction("SSH-Patator", 143),
            _controlled_prediction("DDoS", 144),
        ]
        try:
            with app.app_context():
                first_insert = persist_malicious_predictions(controlled, 300)
                created_ids = first_insert["threat_ids"]
                second_insert = persist_malicious_predictions(controlled, 300)
                stored_records = _controlled_database_records(created_ids)
            retrieved = client.get(f"/api/threats/{created_ids[0]}")
            retrieved_data = (retrieved.get_json() or {}).get("data", {})

            database_failure_handled = False
            with patch("services.threat_persistence.database_cursor", side_effect=Error("test database unavailable")):
                try:
                    persist_malicious_predictions([controlled[0]], 300)
                except ThreatPersistenceError:
                    database_failure_handled = True
        finally:
            with app.app_context():
                _remove_test_records(created_ids)

        with app.app_context():
            final_count = _threat_count()

        expected = {item["classification"]: item for item in controlled}
        records_by_class = {record["attack_type"]: record for record in stored_records}
        controlled_verification = {
            classification: (
                classification in records_by_class
                and records_by_class[classification]["source_ip"] == prediction["source_ip"]
                and records_by_class[classification]["destination_ip"] == prediction["destination_ip"]
                and records_by_class[classification]["severity"] == prediction["severity"]
                and abs(float(records_by_class[classification]["confidence_score"]) - prediction["confidence"]) < 0.01
                and records_by_class[classification]["status"] == "New"
            )
            for classification, prediction in expected.items()
        }
        result = {
            "demo_status": demo_response.status_code,
            "demo_prediction_count": demo_data.get("prediction_count"),
            "demo_malicious_count": demo_data.get("malicious_flow_count"),
            "demo_stored_threat_count": demo_data.get("stored_threat_count"),
            "demo_duplicate_suppressed_count": demo_data.get("duplicate_suppressed_count"),
            "demo_threat_table_unchanged": before_demo == after_demo,
            "controlled_stored_count": first_insert["stored_threat_count"],
            "controlled_duplicate_suppressed": second_insert["duplicate_suppressed_count"],
            "controlled_classes": sorted(expected),
            "controlled_record_verification": controlled_verification,
            "controlled_ids_cleaned": final_count == after_demo,
            "retrieval_status": retrieved.status_code,
            "retrieved_policy_available": retrieved_data.get("policy_available"),
            "retrieved_attack_type": retrieved_data.get("attack_type"),
            "retrieved_severity": retrieved_data.get("severity"),
            "retrieved_priority": retrieved_data.get("priority"),
            "retrieved_recommended_action": retrieved_data.get("recommended_action"),
            "database_failure_handled": database_failure_handled,
        }
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
