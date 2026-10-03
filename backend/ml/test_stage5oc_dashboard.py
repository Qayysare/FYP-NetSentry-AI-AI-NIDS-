"""Static contract checks for the Stage 5O-C production dashboard."""
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    html = (PROJECT_ROOT / "dashboard.html").read_text(encoding="utf-8")
    script = (PROJECT_ROOT / "js" / "dashboard.js").read_text(encoding="utf-8")
    app_script = (PROJECT_ROOT / "js" / "app.js").read_text(encoding="utf-8")
    result = {
        "real_dashboard_endpoints": all(endpoint in script for endpoint in (
            "/api/capture/status", "/api/dashboard/stats", "/api/dashboard/network-activity",
            "/api/dashboard/threat-overview", "/api/dashboard/recent-threats",
        )),
        "uses_incident_api_only_for_allowed_roles": 'user.role !== "user"' in script and 'apiRequest("/api/incidents")' in script,
        "no_sample_data_dependency": "sample-data.js" not in html and "sample-data.js" not in script,
        "no_controlled_replay_dependency": "/api/replay" not in script and "Controlled Replay" not in html,
        "no_held_out_validation_dependency": "validation-summary" not in script and "Held-out" not in html,
        "no_fake_metric_defaults": all(value not in html for value in ("8.42 GB", "12% from yesterday", ">18<", ">12<", ">2<")),
        "monitoring_status_and_posture_present": all(identifier in html for identifier in ("stat-monitoring", "security-posture", "view-live-sensor")),
        "honest_empty_states": all(text in html or text in script for text in ("No recent threats recorded.", "No network activity", "Unable to load")),
        "real_recent_threat_table": "recent-threats-body" in html and "confidence_score" in script,
        "user_restricted_links_hidden": 'view-live-sensor").hidden = !incidentVisible' in script and 'view-incidents").hidden = !incidentVisible' in script,
        "responsive_charts": "responsive: true" in script and "dashboard-heading" in (PROJECT_ROOT / "css" / "responsive.css").read_text(encoding="utf-8"),
        "stage5ob_navigation_preserved": "navigationGroups" in app_script and "userVisiblePages" in app_script,
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
