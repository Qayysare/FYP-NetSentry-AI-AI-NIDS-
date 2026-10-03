"""Stage 5L static frontend contract checks; no capture or database changes."""
from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402


def main():
    app = create_app()
    client = app.test_client()
    sensor_html = (PROJECT_ROOT / "pages" / "live-sensor.html").read_text(encoding="utf-8")
    manual_html = (PROJECT_ROOT / "pages" / "manual-capture.html").read_text(encoding="utf-8")
    sensor_js = (PROJECT_ROOT / "js" / "live-sensor.js").read_text(encoding="utf-8")
    manual_js = (PROJECT_ROOT / "js" / "manual-capture.js").read_text(encoding="utf-8")
    common_js = (PROJECT_ROOT / "js" / "live-ai-results.js").read_text(encoding="utf-8")
    sidebar_js = (PROJECT_ROOT / "js" / "app.js").read_text(encoding="utf-8")
    assets = ("/pages/live-sensor.html", "/pages/manual-capture.html", "/js/live-sensor.js", "/js/manual-capture.js", "/js/live-ai-results.js")
    ai_fields = ("classification", "confidence", "severity", "priority", "recommended_action")
    print(json.dumps({
        "new_assets_served": all(client.get(asset).status_code == 200 for asset in assets),
        "sidebar_has_separate_workflows": "Live Sensor" in sidebar_js and "Manual AI Capture" in sidebar_js and "live-monitoring.html" not in sidebar_js,
        "live_sensor_has_no_manual_selector": 'id="capture-interface"' not in sensor_html,
        "manual_capture_has_interface_controls": all(identifier in manual_html for identifier in ('id="capture-interface"', 'id="start-capture"', 'id="stop-capture"')),
        "both_pages_show_ai_results": all(identifier in sensor_html and identifier in manual_html for identifier in ('live-ai-body', 'live-benign-message', 'live-capture-summary')),
        "shared_ai_renderer_used": "createLiveAiView" in sensor_js and "createLiveAiView" in manual_js and all(field in common_js for field in ai_fields),
        "uses_existing_capture_api": all(route in manual_js or route in sensor_js for route in ("/api/capture/interfaces", "/api/capture/start", "/api/capture/stop", "/api/capture/status")),
        "manual_conflict_message_present": "Autonomous sensor monitoring is currently active" in manual_js,
        "sensor_uses_cursor_polling": "after=${sensorView.cursor}" in sensor_js,
        "manual_uses_cursor_polling": "after=${manualView.cursor}" in manual_js,
        "offline_pcap_page_preserved": client.get("/pages/ai-detection.html").status_code == 200,
    }, indent=2))


if __name__ == "__main__":
    main()
