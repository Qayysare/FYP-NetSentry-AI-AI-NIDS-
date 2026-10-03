"""Static Stage 5B frontend contract checks; it makes no capture or DB changes."""
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
    manual_html = (PROJECT_ROOT / "pages" / "manual-capture.html").read_text(encoding="utf-8")
    sensor_html = (PROJECT_ROOT / "pages" / "live-sensor.html").read_text(encoding="utf-8")
    ai_html = (PROJECT_ROOT / "pages" / "ai-detection.html").read_text(encoding="utf-8")
    manual_script = (PROJECT_ROOT / "js" / "manual-capture.js").read_text(encoding="utf-8")
    sensor_script = (PROJECT_ROOT / "js" / "live-sensor.js").read_text(encoding="utf-8")
    shared_script = (PROJECT_ROOT / "js" / "live-ai-results.js").read_text(encoding="utf-8")
    required_ids = ("capture-interface", "start-capture", "stop-capture", "live-capture-summary", "live-ai-results", "live-ai-body", "live-benign-message")
    routes = ("/pages/manual-capture.html", "/pages/live-sensor.html", "/pages/ai-detection.html", "/js/manual-capture.js", "/js/live-sensor.js", "/js/live-ai-results.js", "/css/stage4.css")
    result = {
        "assets_served": all(client.get(route).status_code == 200 for route in routes),
        "manual_capture_and_ai_sections_present": all(f'id="{element}"' in manual_html for element in required_ids),
        "uses_existing_capture_routes": all(route in manual_script for route in ("/api/capture/interfaces", "/api/capture/start", "/api/capture/stop", "/api/capture/status")),
        "offline_pcap_analysis_preserved": "accept=\".pcap,.pcapng\"" in ai_html and "/api/ai/analyze-pcap" in (PROJECT_ROOT / "js" / "ai-detection.js").read_text(encoding="utf-8"),
        "uses_shared_completed_flow_results": "createLiveAiView" in manual_script and "createLiveAiView" in sensor_script and "status.ai_flows" in shared_script,
        "shows_policy_fields": all(field in shared_script for field in ("classification", "confidence", "severity", "priority", "recommended_action")),
        "formats_confidence_as_percentage": "Number(value) * 100" in shared_script,
        "has_benign_only_message": "No supported malicious flow was detected" in manual_html and "No supported malicious flow was detected" in sensor_html,
        "has_threat_alert_link": "view-threat-alerts" in manual_html and "view-threat-alerts" in sensor_html,
        "manual_and_sensor_modes_are_separate": "Autonomous sensor monitoring is currently active" in manual_script and "Autonomous Sensor" in sensor_script,
        "legacy_combined_assets_removed": not (PROJECT_ROOT / "pages" / "live-monitoring.html").exists() and not (PROJECT_ROOT / "js" / "live-monitoring.js").exists(),
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
