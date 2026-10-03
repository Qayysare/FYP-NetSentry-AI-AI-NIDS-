"""Safe regression checks for the Stage 5L-D held-out validation UI/API."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from services.feature_schema import RUNTIME_FEATURE_COLUMNS  # noqa: E402


EXPECTED_CLASSES = {"BENIGN", "PortScan", "DDoS", "SSH-Patator", "FTP-Patator"}


def authenticated_client(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "stage5ld-test"
        # Match the application's supported Analyst role so this remains a
        # valid authorised operational-access regression.
        session["role"] = "analyst"
    return client


def main() -> None:
    app = create_app()
    app.config["TESTING"] = True
    client = authenticated_client(app)

    unauthenticated = app.test_client().get("/api/ai/validation-summary")
    with patch("routes.ai_detection.persist_malicious_predictions") as persistence, patch(
        "routes.ai_detection.get_service"
    ) as capture_service:
        response = client.get("/api/ai/validation-summary")

    payload = response.get_json() or {}
    data = payload.get("data") or {}
    classes = data.get("classes") or []
    class_names = {item.get("class_name") for item in classes}
    all_representatives = all(
        item.get("representative_pass")
        and item.get("expected_label") == item.get("class_name")
        and item.get("predicted_label") == item.get("class_name")
        and 0.0 <= float(item.get("confidence", -1)) <= 1.0
        for item in classes
    )
    fixed_samples = all(
        item.get("fixed_sample", {}).get("sample_count") == 5
        and 0 <= item.get("fixed_sample", {}).get("correct_count", -1) <= 5
        for item in classes
    )

    html = (PROJECT_ROOT / "pages" / "ai-detection.html").read_text(encoding="utf-8")
    javascript = (PROJECT_ROOT / "js" / "ai-detection.js").read_text(encoding="utf-8")
    route_source = (PROJECT_ROOT / "backend" / "routes" / "ai_detection.py").read_text(encoding="utf-8")
    result = {
        "authentication_required": unauthenticated.status_code == 401,
        "validation_status": response.status_code,
        "all_five_classes_returned": class_names == EXPECTED_CLASSES,
        "feature_count_is_shared_20": data.get("feature_count") == len(RUNTIME_FEATURE_COLUMNS) == 20,
        "representatives_use_real_predictor_output": all_representatives,
        "fixed_first_five_summary_per_class": fixed_samples,
        "persistence_not_called": not persistence.called,
        "tshark_service_not_called": not capture_service.called,
        "validation_route_has_no_model_training": ".fit(" not in route_source,
        "validation_ui_wording": all(text in html for text in (
            "Controlled Model Validation", "Held-out CIC-IDS2017", "NOT LIVE TRAFFIC",
        )),
        "pcap_upload_preserved": "accept=\".pcap,.pcapng\"" in html,
        "pcap_api_preserved": 'apiRequest("/api/ai/analyze-pcap"' in javascript
        and '@ai_detection_bp.post("/analyze-pcap")' in route_source,
    }
    result["passed"] = all(value for key, value in result.items() if key not in {"validation_status", "passed"}) and response.status_code == 200
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
