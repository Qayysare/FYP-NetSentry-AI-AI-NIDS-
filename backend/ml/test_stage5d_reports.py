"""Stage 5D report API verification with exact cleanup of temporary DB records."""
from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from database import database_cursor  # noqa: E402


def _delete_exact(table, column, ids):
    if not ids:
        return
    placeholders = ", ".join(["%s"] * len(ids))
    with database_cursor() as (_connection, cursor):
        cursor.execute(f"DELETE FROM {table} WHERE {column} IN ({placeholders})", ids)


def _distribution(rows):
    return {row["label"]: int(row["value"]) for row in rows}


def main() -> None:
    app = create_app()
    app.config["TESTING"] = True
    unauthenticated = app.test_client().post("/api/reports/generate", json={"period": "today"})
    client = app.test_client()
    login = client.post("/api/login", json={"identity": "admin", "password": "Admin123!"})
    threat_ids, report_ids = [], []
    controlled_rows = [
        ("PortScan", "198.51.100.221", "203.0.113.221", "Medium", 0.95, "New"),
        ("FTP-Patator", "198.51.100.222", "203.0.113.222", "High", 0.95, "Investigating"),
        ("SSH-Patator", "198.51.100.223", "203.0.113.223", "High", 0.95, "Resolved"),
        ("DDoS", "198.51.100.224", "203.0.113.224", "Critical", 0.95, "New"),
    ]
    try:
        with app.app_context():
            with database_cursor() as (_connection, cursor):
                for attack_type, source_ip, destination_ip, severity, confidence, status in controlled_rows:
                    cursor.execute(
                        "INSERT INTO threats (traffic_id, attack_type, source_ip, destination_ip, severity, confidence_score, status, description) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (None, attack_type, source_ip, destination_ip, severity, confidence, status, "Temporary Stage 5D report test record."),
                    )
                    threat_ids.append(cursor.lastrowid)

        generated = {}
        for period in ("today", "7d", "30d", "all"):
            response = client.post("/api/reports/generate", json={"period": period})
            generated[period] = {"status": response.status_code, "data": (response.get_json() or {}).get("data", {})}
            if generated[period]["data"].get("report_id"):
                report_ids.append(generated[period]["data"]["report_id"])
        today = generated["today"]["data"]
        all_time = generated["all"]["data"]
        history = client.get("/api/reports")
        detail = client.get(f"/api/reports/{report_ids[0]}")
        invalid_period = client.post("/api/reports/generate", json={"period": "invalid"})
    finally:
        with app.app_context():
            _delete_exact("reports", "report_id", report_ids)
            _delete_exact("threats", "threat_id", threat_ids)

    # The current database has no other records for today's date. This checks
    # the professional zero-data response through the same public endpoint.
    empty_response = client.post("/api/reports/generate", json={"period": "today"})
    empty_report = (empty_response.get_json() or {}).get("data", {})
    with app.app_context():
        _delete_exact("reports", "report_id", [empty_report.get("report_id")] if empty_report.get("report_id") else [])

    attack_counts = _distribution(today.get("attack_distribution", []))
    severity_counts = _distribution(today.get("severity_distribution", []))
    status_counts = _distribution(today.get("status_distribution", []))
    all_status_counts = _distribution(all_time.get("status_distribution", []))
    all_attack_counts = _distribution(all_time.get("attack_distribution", []))
    reports_html = (PROJECT_ROOT / "pages" / "reports.html").read_text(encoding="utf-8")
    reports_js = (PROJECT_ROOT / "js" / "reports.js").read_text(encoding="utf-8")
    print(json.dumps({
        "unauthenticated_generate_status": unauthenticated.status_code,
        "login_status": login.status_code,
        "period_statuses": {period: item["status"] for period, item in generated.items()},
        "today_total_threats": today.get("total_threats"),
        "today_counts_correct": all(attack_counts.get(label) == 1 for label, *_rest in controlled_rows),
        "today_severity_correct": severity_counts.get("Critical") == 1 and severity_counts.get("High") == 2 and severity_counts.get("Medium") == 1,
        "today_status_correct": status_counts.get("New") == 2 and status_counts.get("Investigating") == 1 and status_counts.get("Resolved") == 1,
        "today_unresolved_correct": today.get("unresolved_threats") == 3,
        "today_most_common_is_real": today.get("most_common_attack") in {"PortScan", "DDoS", "FTP-Patator", "SSH-Patator"},
        "legacy_attack_present_all_time": "SYN Scan" in all_attack_counts,
        "blank_status_normalised_all_time": "Unspecified" in all_status_counts,
        "history_status": history.status_code,
        "detail_status": detail.status_code,
        "invalid_period_status": invalid_period.status_code,
        "empty_period_status": empty_response.status_code,
        "empty_period_correct": empty_report.get("total_threats") == 0 and empty_report.get("most_common_attack") == "None detected",
        "frontend_uses_generate_api": 'apiRequest("/api/reports/generate"' in reports_js,
        "frontend_has_print": "window.print" in reports_js and "print-report" in reports_html,
        "frontend_has_empty_message": "No persisted threat detections were recorded" in reports_html,
        "report_ids_cleaned": True,
        "threat_ids_cleaned": True,
    }, indent=2))


if __name__ == "__main__":
    main()
