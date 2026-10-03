from flask import Blueprint, request
from database import database_cursor
from utils.helpers import analyst_or_admin_required, failure, required_fields, success

logs_bp = Blueprint("logs", __name__, url_prefix="/api/logs")


@logs_bp.get("")
@analyst_or_admin_required
def list_logs():
    filters, params = [], []
    for field in ("severity", "status", "event_type"):
        if request.args.get(field):
            filters.append(f"{field} = %s")
            params.append(request.args[field])
    query = "SELECT * FROM security_logs"
    if filters:
        query += " WHERE " + " AND ".join(filters)
    limit = min(max(request.args.get("limit", default=100, type=int) or 100, 1), 200)
    query += " ORDER BY created_at DESC LIMIT %s"
    params.append(limit)
    with database_cursor() as (_connection, cursor):
        cursor.execute(query, params)
        rows = cursor.fetchall()
    return success(rows, "Security logs retrieved successfully")


@logs_bp.post("")
@analyst_or_admin_required
def create_log():
    data = request.get_json(silent=True) or {}
    missing = required_fields(data, ["event_type", "source", "description", "severity", "status"])
    if missing:
        return failure("Missing required fields: " + ", ".join(missing))
    with database_cursor() as (_connection, cursor):
        cursor.execute("INSERT INTO security_logs (event_type, source, description, severity, status) VALUES (%s, %s, %s, %s, %s)", tuple(data[key] for key in ["event_type", "source", "description", "severity", "status"]))
        record_id = cursor.lastrowid
    return success({"log_id": record_id}, "Security log created successfully", 201)
