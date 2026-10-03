"""Static/frontend-contract checks for Stage 4J; no model or database writes."""
from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402


def main() -> None:
    app = create_app()
    client = app.test_client()
    routes = [
        "/pages/ai-detection.html",
        "/pages/threat-alerts.html",
        "/js/app.js",
        "/js/ai-detection.js",
        "/js/threat-alerts.js",
        "/css/stage4.css",
    ]
    route_statuses = {route: client.get(route).status_code for route in routes}

    ai_html = (PROJECT_ROOT / "pages" / "ai-detection.html").read_text(encoding="utf-8")
    ai_js = (PROJECT_ROOT / "js" / "ai-detection.js").read_text(encoding="utf-8")
    alerts_html = (PROJECT_ROOT / "pages" / "threat-alerts.html").read_text(encoding="utf-8")
    alerts_js = (PROJECT_ROOT / "js" / "threat-alerts.js").read_text(encoding="utf-8")
    app_js = (PROJECT_ROOT / "js" / "app.js").read_text(encoding="utf-8")

    ai_ids = [
        "ai-analysis-form", "capture-file", "analyze-button", "analysis-state",
        "analysis-results", "class-summary", "severity-summary", "predictions-body",
    ]
    alert_ids = ["severity-filter", "alerts-body", "alerts-message", "alert-detail"]
    result = {
        "all_frontend_assets_served": all(status == 200 for status in route_statuses.values()),
        "asset_statuses": route_statuses,
        "ai_page_elements_present": all(f'id="{item}"' in ai_html for item in ai_ids),
        "ai_uses_formdata": "new FormData()" in ai_js and 'formData.append("capture_file", file)' in ai_js,
        "ai_calls_backend_endpoint": 'apiRequest("/api/ai/analyze-pcap"' in ai_js,
        "ai_displays_policy_fields": all(field in ai_js for field in ("severity", "priority", "recommended_action")),
        "ai_formats_probability_as_percent": "probability * 100" in ai_js,
        "alerts_page_elements_present": all(f'id="{item}"' in alerts_html for item in alert_ids),
        "alerts_calls_existing_api": 'apiRequest("/api/threats")' in alerts_js,
        "alerts_displays_policy_fields": all(field in alerts_js for field in ("priority", "recommended_action")),
        "alerts_formats_decimal_confidence": "score <= 1 ? score * 100 : score" in alerts_js,
        "shared_helper_preserves_multipart_boundary": "options.body instanceof FormData" in app_js and "multipart boundary" in app_js,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
