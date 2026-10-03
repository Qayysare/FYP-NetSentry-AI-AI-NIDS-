"""SQL-backed, period-based reports with optional immutable incident snapshots."""
from __future__ import annotations

from datetime import date, datetime, time, timedelta

from database import database_cursor

PERIODS = {"today": "Today", "7d": "Last 7 Days", "30d": "Last 30 Days", "all": "All Time"}


class ReportPeriodError(ValueError):
    """Raised for an unsupported report period."""


def _period_details(period: str) -> dict:
    if not isinstance(period, str) or period not in PERIODS:
        raise ReportPeriodError("Choose Today, Last 7 Days, Last 30 Days, or All Time.")
    if period == "all":
        return {"key": period, "label": PERIODS[period], "start": None, "end": None}
    today = date.today()
    days = {"today": 1, "7d": 7, "30d": 30}[period]
    start = datetime.combine(today - timedelta(days=days - 1), time.min)
    end = datetime.combine(today + timedelta(days=1), time.min)
    return {"key": period, "label": PERIODS[period], "start": start, "end": end}


def _where(timestamp_column: str, details: dict) -> tuple[str, tuple]:
    if details["start"] is None:
        return "", ()
    return f" WHERE {timestamp_column} >= %s AND {timestamp_column} < %s", (details["start"], details["end"])


def snapshot_storage_available(cursor) -> bool:
    """Keep older installations usable until the deliberately manual migration runs."""
    cursor.execute("SHOW TABLES LIKE 'report_incident_snapshots'")
    return cursor.fetchone() is not None


def report_metadata_available(cursor) -> bool:
    cursor.execute("SHOW COLUMNS FROM reports LIKE 'report_period_key'")
    return cursor.fetchone() is not None


def get_report_snapshots(cursor, report_id: int) -> list[dict]:
    if not snapshot_storage_available(cursor):
        return []
    cursor.execute(
        "SELECT ticket_id, threat_id, incident_status AS status, attack_type, source_ip, destination_ip, severity, "
        "confidence_score, detected_at, assigned_username, investigation_findings, mitigation_taken, "
        "handled_username AS handled_by_name, handled_at, verified_username AS verified_by_name, verified_at, "
        "verification_remarks, snapshot_created_at FROM report_incident_snapshots WHERE report_id = %s "
        "ORDER BY ticket_id, snapshot_id",
        (report_id,),
    )
    return cursor.fetchall()


def _incident_rows(cursor, threat_where: str, threat_params: tuple) -> list[dict]:
    query = (
        "SELECT i.ticket_id, i.status, i.investigation_findings, i.mitigation_taken, i.handled_at, i.verified_at, "
        "i.verification_remarks, t.threat_id, t.attack_type, t.source_ip, t.destination_ip, t.severity, "
        "t.confidence_score, t.detected_at, a.username AS assigned_username, h.username AS handled_by_name, "
        "v.username AS verified_by_name FROM incidents i JOIN threats t ON t.threat_id = i.threat_id "
        "LEFT JOIN users a ON a.user_id = i.assigned_to LEFT JOIN users h ON h.user_id = i.handled_by "
        "LEFT JOIN users v ON v.user_id = i.verified_by"
    )
    if threat_where:
        query += threat_where.replace("detected_at", "t.detected_at")
    cursor.execute(query + " ORDER BY i.updated_at DESC", threat_params)
    return cursor.fetchall()


def _store_snapshots(cursor, report_id: int, rows: list[dict]) -> None:
    statement = (
        "INSERT INTO report_incident_snapshots (report_id, ticket_id, threat_id, incident_status, attack_type, "
        "source_ip, destination_ip, severity, confidence_score, detected_at, assigned_username, investigation_findings, "
        "mitigation_taken, handled_username, handled_at, verified_username, verified_at, verification_remarks) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )
    for row in rows:
        cursor.execute(statement, (report_id, row["ticket_id"], row["threat_id"], row["status"], row["attack_type"], row["source_ip"], row["destination_ip"], row["severity"], row["confidence_score"], row["detected_at"], row["assigned_username"], row["investigation_findings"], row["mitigation_taken"], row["handled_by_name"], row["handled_at"], row["verified_by_name"], row["verified_at"], row["verification_remarks"]))


def generate_report(period: str) -> dict:
    """Store an aggregate report and, after migration, its point-in-time incident details."""
    details = _period_details(period)
    threat_where, threat_params = _where("detected_at", details)
    traffic_where, traffic_params = _where("timestamp", details)
    with database_cursor() as (_connection, cursor):
        cursor.execute(f"SELECT COUNT(*) AS total FROM threats{threat_where}", threat_params)
        total_threats = int(cursor.fetchone()["total"])
        cursor.execute(f"SELECT severity AS label, COUNT(*) AS value FROM threats{threat_where} GROUP BY severity", threat_params)
        severity_distribution = cursor.fetchall()
        cursor.execute(f"SELECT COALESCE(NULLIF(status, ''), 'Unspecified') AS label, COUNT(*) AS value FROM threats{threat_where} GROUP BY COALESCE(NULLIF(status, ''), 'Unspecified')", threat_params)
        status_distribution = cursor.fetchall()
        cursor.execute(f"SELECT attack_type AS label, COUNT(*) AS value FROM threats{threat_where} GROUP BY attack_type ORDER BY value DESC, label", threat_params)
        attack_distribution = cursor.fetchall()
        cursor.execute(f"SELECT COUNT(*) AS total FROM network_traffic{traffic_where}", traffic_params)
        total_events = int(cursor.fetchone()["total"])
        incident_responses = _incident_rows(cursor, threat_where, threat_params)
        severity_counts = {row["label"]: int(row["value"]) for row in severity_distribution}
        status_counts = {row["label"]: int(row["value"]) for row in status_distribution}
        most_common_attack = attack_distribution[0]["label"] if attack_distribution else "None detected"
        title = f"AI-NIDS Security Report — {details['label']}"
        if report_metadata_available(cursor):
            cursor.execute(
                "INSERT INTO reports (report_title, report_kind, report_period_key, report_period_label, report_period_start, report_period_end, report_date, total_events, total_threats, critical_alerts, most_common_attack) VALUES (%s, 'aggregate_period', %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (title, details["key"], details["label"], details["start"].date() if details["start"] else None, (details["end"] - timedelta(days=1)).date() if details["end"] else None, date.today(), total_events, total_threats, severity_counts.get("Critical", 0), most_common_attack),
            )
        else:
            cursor.execute("INSERT INTO reports (report_title, report_date, total_events, total_threats, critical_alerts, most_common_attack) VALUES (%s, %s, %s, %s, %s, %s)", (title, date.today(), total_events, total_threats, severity_counts.get("Critical", 0), most_common_attack))
        report_id = cursor.lastrowid
        snapshots_stored = snapshot_storage_available(cursor)
        if snapshots_stored:
            _store_snapshots(cursor, report_id, incident_responses)

    return {"report_id": report_id, "report_title": title, "report_kind": "aggregate_period", "report_period": {"key": details["key"], "label": details["label"], "start": details["start"].date().isoformat() if details["start"] else None, "end": (details["end"] - timedelta(days=1)).date().isoformat() if details["end"] else None}, "generated_at": datetime.now().astimezone().isoformat(), "total_events": total_events, "total_threats": total_threats, "critical_alerts": severity_counts.get("Critical", 0), "high_alerts": severity_counts.get("High", 0), "medium_alerts": severity_counts.get("Medium", 0), "unresolved_threats": status_counts.get("New", 0) + status_counts.get("Investigating", 0), "most_common_attack": most_common_attack, "attack_distribution": attack_distribution, "severity_distribution": severity_distribution, "status_distribution": status_distribution, "incident_snapshots": incident_responses if snapshots_stored else [], "snapshot_available": snapshots_stored}
