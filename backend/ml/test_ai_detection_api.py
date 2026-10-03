"""Repeatable Stage 4G API verification; it does not write to MySQL or retrain."""
from __future__ import annotations

import io
import json
import sys
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from ml.predictor import FlowPredictor  # noqa: E402
from services.threat_priority import ThreatPriorityError, assess_threat  # noqa: E402


def _authenticated_client(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "stage4g-test"
        session["role"] = "soc_analyst"
    return client


def main() -> None:
    demo_path = PROJECT_ROOT / "Wireshark" / "demo.pcapng"
    with tempfile.TemporaryDirectory() as upload_folder:
        app = create_app()
        app.config.update(TESTING=True, PCAP_UPLOAD_FOLDER=upload_folder)
        client = _authenticated_client(app)

        unauthenticated = app.test_client().post("/api/ai/analyze-pcap")
        missing = client.post("/api/ai/analyze-pcap")
        invalid = client.post(
            "/api/ai/analyze-pcap",
            data={"capture_file": (io.BytesIO(b"not a capture"), "not-a-capture.txt")},
            content_type="multipart/form-data",
        )
        with demo_path.open("rb") as demo_file:
            analysis = client.post(
                "/api/ai/analyze-pcap",
                data={"capture_file": (demo_file, "demo.pcapng")},
                content_type="multipart/form-data",
            )
        with demo_path.open("rb") as demo_file:
            legacy = client.post(
                "/api/pcap/upload",
                data={"capture_file": (demo_file, "demo.pcapng")},
                content_type="multipart/form-data",
            )

        schema_error = None
        try:
            FlowPredictor(schema_path=PROJECT_ROOT / "missing-feature-schema.json")
        except RuntimeError as error:
            schema_error = str(error)

        policy_results = {
            label: assess_threat(label, 0.95)
            for label in ("BENIGN", "PortScan", "FTP-Patator", "SSH-Patator", "DDoS")
        }
        confidence_boundaries = {
            str(value): assess_threat("PortScan", value)["confidence_band"]
            for value in (0.0, 0.5999, 0.60, 0.8499, 0.85, 1.0)
        }
        invalid_class_rejected = False
        try:
            assess_threat("Unknown", 0.9)
        except ThreatPriorityError:
            invalid_class_rejected = True

        original_predictor = app.extensions["flow_predictor"]
        app.extensions["flow_predictor"] = None
        app.extensions["flow_predictor_error"] = "test-only unavailable predictor"
        with demo_path.open("rb") as demo_file:
            unavailable = client.post(
                "/api/ai/analyze-pcap",
                data={"capture_file": (demo_file, "demo.pcapng")},
                content_type="multipart/form-data",
            )
        app.extensions["flow_predictor"] = original_predictor

        payload = analysis.get_json()
        data = payload["data"] if analysis.status_code == 200 else {}
        confidences = [item["confidence"] for item in data.get("predictions", [])]
        result = {
            "endpoint_exists": unauthenticated.status_code == 401,
            "authentication_status": unauthenticated.status_code,
            "missing_file_status": missing.status_code,
            "invalid_extension_status": invalid.status_code,
            "analysis_status": analysis.status_code,
            "packet_count": data.get("packet_count"),
            "flow_count": data.get("flow_count"),
            "prediction_count": data.get("prediction_count"),
            "summary": data.get("summary"),
            "malicious_flow_count": data.get("malicious_flow_count"),
            "severity_summary": data.get("severity_summary"),
            "requires_attention_count": data.get("requires_attention_count"),
            "example_prediction": (data.get("predictions") or [None])[0],
            "confidence_range": [min(confidences), max(confidences)] if confidences else None,
            "prediction_count_matches_flows": data.get("prediction_count") == data.get("flow_count"),
            "all_confidences_valid": all(0.0 <= value <= 1.0 for value in confidences),
            "predictor_unavailable_status": unavailable.status_code,
            "schema_failure_detected": schema_error,
            "stage3_pcap_upload_status": legacy.status_code,
            "stage3_packet_count": (legacy.get_json() or {}).get("data", {}).get("packet_count"),
            "policy_results": policy_results,
            "confidence_boundaries": confidence_boundaries,
            "invalid_class_rejected": invalid_class_rejected,
        }
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
