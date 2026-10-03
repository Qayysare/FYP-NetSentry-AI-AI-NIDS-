"""Static product-branding contract for Stage 5Q-B; no services are started."""
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PAGE_NAMES = (
    "ai-detection.html", "analytics.html", "change-password.html",
    "connected-devices.html", "examiner-demo.html", "incidents.html",
    "live-sensor.html", "manual-capture.html", "password-reset-requests.html",
    "reports.html", "security-logs.html", "settings.html", "threat-alerts.html",
    "user-management.html",
)


def main() -> None:
    login = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")
    dashboard = (PROJECT_ROOT / "dashboard.html").read_text(encoding="utf-8")
    pages = {name: (PROJECT_ROOT / "pages" / name).read_text(encoding="utf-8") for name in PAGE_NAMES}
    app_script = (PROJECT_ROOT / "js" / "app.js").read_text(encoding="utf-8")
    incident_script = (PROJECT_ROOT / "js" / "incidents.js").read_text(encoding="utf-8")
    config = (PROJECT_ROOT / "backend" / "config.py").read_text(encoding="utf-8")
    frontend = "\n".join((login, dashboard, *pages.values(), app_script, incident_script))
    titles = (login, dashboard, *pages.values())
    result = {
        "login_uses_product_brand": "<title>NetSentry AI</title>" in login and "<h1>NetSentry AI</h1>" in login and "AI-Based Network Intrusion Detection System" in login,
        "active_page_titles_use_product_brand": all(" | NetSentry AI</title>" in page for page in titles[1:]),
        "sidebar_uses_product_brand_and_existing_mark": 'title="NetSentry AI"' in app_script and ">NetSentry AI</span>" in app_script and "fa-shield-halved" in app_script,
        "dashboard_product_copy_updated": "NetSentry AI" in dashboard and "Latest persisted NetSentry AI threat detections." in dashboard,
        "general_report_identity_preserved": "<strong>NetSentry AI</strong><h1>AI-BASED NETWORK INTRUSION DETECTION SYSTEM</h1><h2>GENERAL THREAT ANALYSIS REPORT</h2>" in pages["reports.html"],
        "incident_report_identity_preserved": "<strong>NetSentry AI</strong><h1>AI-BASED NETWORK INTRUSION DETECTION SYSTEM</h1><h2>INCIDENT RESOLUTION REPORT</h2>" in pages["incidents.html"],
        "examiner_disclosure_preserved": "CONTROLLED DATASET REPLAY - NOT LIVE TRAFFIC" in pages["examiner-demo.html"] and "No packets are transmitted and no attacks are performed." in pages["examiner-demo.html"],
        "no_company_logo_or_asset_introduced": "HeiTech" not in frontend and "<img" not in frontend,
        "technical_identifiers_unchanged": "AI_NIDS_AUTO_MONITORING" in config and 'DB_NAME = os.getenv("DB_NAME", "ai_nids")' in config,
        "navigation_contract_preserved": "navigationGroups" in app_script and "userVisiblePages" in app_script and "Live Sensor" in app_script,
        "no_sample_data_dependency": "sample-data.js" not in frontend,
        "report_print_controls_preserved": 'id="print-report"' in pages["reports.html"] and 'id="print-incident-report"' in pages["incidents.html"],
        "incident_model_disclosure_updated": "NetSentry AI classification is a model output, not verified ground truth." in incident_script,
        "old_visible_product_brand_removed": "AI-NIDS" not in frontend,
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
