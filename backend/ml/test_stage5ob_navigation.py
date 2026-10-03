"""Static contract checks for Stage 5O-B grouped, role-aware navigation."""
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    app_script = (PROJECT_ROOT / "js" / "app.js").read_text(encoding="utf-8")
    manual_script = (PROJECT_ROOT / "js" / "manual-capture.js").read_text(encoding="utf-8")
    sensor_script = (PROJECT_ROOT / "js" / "live-sensor.js").read_text(encoding="utf-8")
    dashboard_css = (PROJECT_ROOT / "css" / "dashboard.css").read_text(encoding="utf-8")
    result = {
        "grouped_navigation": all(label in app_script for label in (
            'label: "OVERVIEW"', 'label: "MONITORING"', 'label: "SECURITY"',
            'label: "ANALYSIS"', 'label: "ADMIN"',
        )),
        "admin_items_present": all(item in app_script for item in (
            "User Management", "Settings", "Live Sensor", "Manual AI Capture", "Examiner Demo",
        )),
        "analyst_hides_admin_group": 'roles: ["admin"]' in app_script,
        "user_hides_operational_pages": 'userVisiblePages' in app_script and 'roles: ["admin", "analyst"]' in app_script,
        "examiner_demo_hidden_from_users": 'examiner-demo.html' in app_script and 'roles: ["admin", "analyst"]' in app_script,
        "password_reset_not_primary_link": 'password-reset-requests.html", "fa-key"' not in app_script,
        "change_password_in_account_area": 'pages/change-password.html' in app_script,
        "direct_page_guard_present": "isPageAllowed(user)" in app_script,
        "active_page_highlighting_preserved": 'endsWith(page) ? "active" : ""' in app_script,
        "collapse_and_scroll_preserved": all(token in dashboard_css for token in ("overflow-y:auto", ".sidebar.collapsed", ".sidebar-bottom")),
        "analyst_capture_controls_explain_backend_requirement": "Capture controls require an administrator account" in manual_script and "Sensor controls require an administrator account" in sensor_script,
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
