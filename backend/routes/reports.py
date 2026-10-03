from datetime import date
from flask import Blueprint, request
from database import database_cursor
from services.report_service import ReportPeriodError, generate_report, get_report_snapshots, report_metadata_available, snapshot_storage_available
from utils.helpers import analyst_or_admin_required, failure, login_required, required_fields, success

reports_bp = Blueprint("reports", __name__, url_prefix="/api/reports")


@reports_bp.get("")
@login_required
def list_reports():
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT 30")
        rows = cursor.fetchall()
    return success(rows, "Reports retrieved successfully")


@reports_bp.post("")
@analyst_or_admin_required
def create_report():
    data = request.get_json(silent=True) or {}
    missing = required_fields(data, ["report_title", "total_events", "total_threats", "critical_alerts", "most_common_attack"])
    if missing:
        return failure("Missing required fields: " + ", ".join(missing))
    with database_cursor() as (_connection, cursor):
        cursor.execute("INSERT INTO reports (report_title, report_date, total_events, total_threats, critical_alerts, most_common_attack) VALUES (%s, %s, %s, %s, %s, %s)", (data["report_title"], data.get("report_date", date.today()), data["total_events"], data["total_threats"], data["critical_alerts"], data["most_common_attack"]))
        record_id = cursor.lastrowid
    return success({"report_id": record_id}, "Report created successfully", 201)


@reports_bp.post("/generate")
@analyst_or_admin_required
def generate_security_report():
    period = (request.get_json(silent=True) or {}).get("period", "7d")
    try:
        report = generate_report(period)
    except ReportPeriodError as error:
        return failure(str(error))
    return success(report, "Security report generated successfully", 201)


@reports_bp.get("/<int:report_id>")
@login_required
def get_report(report_id):
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT * FROM reports WHERE report_id = %s", (report_id,))
        report = cursor.fetchone()
        if not report:
            return failure("Report not found", 404)
        metadata_available = report_metadata_available(cursor)
        snapshots_available = snapshot_storage_available(cursor)
        report["report_kind"] = report.get("report_kind") or "aggregate_period"
        report["report_period"] = {
            "key": report.get("report_period_key") if metadata_available else None,
            "label": report.get("report_period_label") if metadata_available else None,
            "start": report.get("report_period_start") if metadata_available else None,
            "end": report.get("report_period_end") if metadata_available else None,
        }
        report["snapshot_available"] = snapshots_available
        report["incident_snapshots"] = get_report_snapshots(cursor, report_id) if snapshots_available else []
    return success(report, "Stored report retrieved successfully")
