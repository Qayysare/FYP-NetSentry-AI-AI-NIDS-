"""Static visual and responsive contracts for the Stage 5O-F UI pass."""
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    css = (PROJECT_ROOT / "css" / "dashboard.css").read_text(encoding="utf-8")
    responsive = (PROJECT_ROOT / "css" / "responsive.css").read_text(encoding="utf-8")
    stage4 = (PROJECT_ROOT / "css" / "stage4.css").read_text(encoding="utf-8")
    reports_css = (PROJECT_ROOT / "css" / "reports.css").read_text(encoding="utf-8")
    pages = {path.name: path.read_text(encoding="utf-8") for path in (PROJECT_ROOT / "pages").glob("*.html")}
    dashboard = (PROJECT_ROOT / "dashboard.html").read_text(encoding="utf-8")
    app_script = (PROJECT_ROOT / "js" / "app.js").read_text(encoding="utf-8")
    result = {
        "production_pages_keep_shared_css": all("dashboard.css" in page and "responsive.css" in page for name, page in pages.items() if name != "change-password.html"),
        "shared_button_and_focus_system": all(token in css for token in (".danger-button", ".secondary-button", ":focus-visible", "min-height:40px")),
        "semantic_status_badges": all(token in css for token in (".status.assigned", ".status.closed", ".status.active", ".status.stopped")),
        "table_consistency": ".table-wrap table{min-width:640px}" in css and "tbody tr:hover" in css,
        "responsive_toolbars_and_cards": all(token in responsive for token in ("toolbar button", "report-review-heading", "chart-wrap{height:240px}", "stat-grid")),
        "sensor_stop_button_styled": ".sensor-state button" in stage4 and 'button[id^="stop-"]' in stage4,
        "examiner_disclosure_preserved": "CONTROLLED DATASET REPLAY - NOT LIVE TRAFFIC" in pages["examiner-demo.html"] and "No packets are transmitted" in pages["examiner-demo.html"],
        "ai_validation_disclosure_preserved": "NOT LIVE TRAFFIC" in pages["ai-detection.html"] and "Held-out CIC-IDS2017" in pages["ai-detection.html"],
        "report_print_sections_preserved": all(token in reports_css for token in ("@media print", ".general-print-signoff", ".stamp-box")),
        "incident_verification_preserved": all(token in pages["incidents.html"] for token in ("VERIFICATION", "verify-incident", "incident-report-preview")),
        "wide_tables_keep_table_wrap": all("table-wrap" in pages[name] for name in ("threat-alerts.html", "incidents.html", "connected-devices.html", "security-logs.html", "reports.html", "examiner-demo.html")) and "table-wrap" in dashboard,
        "stage5ob_navigation_preserved": "navigationGroups" in app_script and "userVisiblePages" in app_script,
        "stage5oc_dashboard_preserved": "Active Observed Devices" in dashboard and "security-posture" in dashboard,
        "stage5od_device_wording_preserved": "Recently Observed Local Devices" in pages["connected-devices.html"] and "authorised monitoring" in pages["connected-devices.html"],
        "stage5oe_session_wording_preserved": "Current Interface" in pages["live-sensor.html"] and "live-session-results-note" in pages["manual-capture.html"],
        "no_sample_data_added": "sample-data.js" not in dashboard and all("sample-data.js" not in page for page in pages.values()),
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
