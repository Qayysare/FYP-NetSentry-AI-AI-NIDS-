"""Stage 5C SQL/API and frontend-contract verification with exact test-row cleanup."""
from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from database import database_cursor  # noqa: E402


def _authenticated_client(app):
    client = app.test_client()
    login = client.post("/api/login", json={"identity": "admin", "password": "Admin123!"})
    if login.status_code != 200:
        raise RuntimeError("The documented test account could not authenticate.")
    return client


def _as_map(rows):
    return {row["label"]: int(row["value"]) for row in rows}


def _delete_exact(ids):
    if not ids:
        return
    placeholders = ", ".join(["%s"] * len(ids))
    with database_cursor() as (_connection, cursor):
        cursor.execute(f"DELETE FROM threats WHERE threat_id IN ({placeholders})", ids)


def main() -> None:
    app = create_app()
    app.config["TESTING"] = True
    client = _authenticated_client(app)
    endpoints = {
        "types": "/api/analytics/threat-distribution",
        "severity": "/api/analytics/severity-distribution",
        "status": "/api/analytics/status-distribution",
        "trend": "/api/analytics/threat-trend",
    }
    before = {key: _as_map((client.get(url).get_json() or {}).get("data", [])) for key, url in endpoints.items()}
    before_stats = (client.get("/api/dashboard/stats").get_json() or {}).get("data", {})
    test_rows = [
        ("PortScan", "198.51.100.201", "203.0.113.201", "Medium", 0.95, "New"),
        ("FTP-Patator", "198.51.100.202", "203.0.113.202", "High", 0.95, "Investigating"),
        ("SSH-Patator", "198.51.100.203", "203.0.113.203", "High", 0.95, "Resolved"),
        ("DDoS", "198.51.100.204", "203.0.113.204", "Critical", 0.95, "New"),
    ]
    ids = []
    try:
        with app.app_context():
            with database_cursor() as (_connection, cursor):
                for attack_type, source_ip, destination_ip, severity, confidence, status in test_rows:
                    cursor.execute(
                        "INSERT INTO threats (traffic_id, attack_type, source_ip, destination_ip, severity, confidence_score, status, description) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (None, attack_type, source_ip, destination_ip, severity, confidence, status, "Temporary Stage 5C aggregation test record."),
                    )
                    ids.append(cursor.lastrowid)
        after = {key: _as_map((client.get(url).get_json() or {}).get("data", [])) for key, url in endpoints.items()}
        after_stats = (client.get("/api/dashboard/stats").get_json() or {}).get("data", {})
        recent = (client.get("/api/dashboard/recent-threats").get_json() or {}).get("data", [])
    finally:
        with app.app_context():
            _delete_exact(ids)
            if ids:
                placeholders = ", ".join(["%s"] * len(ids))
                with database_cursor() as (_connection, cursor):
                    cursor.execute(f"SELECT COUNT(*) AS total FROM threats WHERE threat_id IN ({placeholders})", ids)
                    cleaned = cursor.fetchone()["total"] == 0
            else:
                cleaned = True

    type_increase = all(after["types"].get(row[0], 0) == before["types"].get(row[0], 0) + 1 for row in test_rows)
    severity_expected = {"Medium": 1, "High": 2, "Critical": 1}
    severity_increase = all(after["severity"].get(label, 0) == before["severity"].get(label, 0) + amount for label, amount in severity_expected.items())
    status_expected = {"New": 2, "Investigating": 1, "Resolved": 1}
    status_increase = all(after["status"].get(label, 0) == before["status"].get(label, 0) + amount for label, amount in status_expected.items())
    html = (PROJECT_ROOT / "pages" / "analytics.html").read_text(encoding="utf-8")
    script = (PROJECT_ROOT / "js" / "analytics.js").read_text(encoding="utf-8")
    dashboard_script = (PROJECT_ROOT / "js" / "dashboard.js").read_text(encoding="utf-8")
    print(json.dumps({
        "all_analytics_routes_success": all(client.get(url).status_code == 200 for url in endpoints.values()),
        "dashboard_stats_increased": after_stats.get("detected_threats") == before_stats.get("detected_threats", 0) + 4,
        "threat_type_distribution_updated": type_increase,
        "severity_distribution_updated": severity_increase,
        "status_distribution_updated": status_increase,
        "trend_increased": sum(after["trend"].values()) == sum(before["trend"].values()) + 4,
        "recent_threats_include_controlled": any(row.get("threat_id") in ids for row in recent),
        "controlled_ids_cleaned": cleaned,
        "analytics_uses_real_endpoints": all(endpoint in script for endpoint in endpoints.values()),
        "analytics_has_empty_state": "No threat data" in script and "emptyRows" in script,
        "dashboard_uses_no_sample_fallback": "sampleThreats" not in dashboard_script,
    }, indent=2))


if __name__ == "__main__":
    main()
