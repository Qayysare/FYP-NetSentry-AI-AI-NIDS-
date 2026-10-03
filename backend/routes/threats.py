from flask import Blueprint, request
from database import database_cursor
from services.threat_priority import ThreatPriorityError, assess_threat
from utils.helpers import analyst_or_admin_required, failure, login_required, required_fields, success

threats_bp = Blueprint("threats", __name__, url_prefix="/api/threats")
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_STATUSES = {"New", "Investigating", "Resolved"}


def enrich_threat(row):
    """Add derived policy fields without requiring a threats-table migration."""
    if not row:
        return row
    try:
        policy = assess_threat(row["attack_type"], row["confidence_score"])
        return {**row, **policy, "policy_available": True}
    except ThreatPriorityError:
        # Older manually entered threat types remain visible but are not
        # falsely labelled as benign or assigned a made-up policy.
        return {
            **row,
            "priority": None,
            "recommended_action": None,
            "confidence_band": None,
            "reason": "No Stage 4 policy is available for this threat type.",
            "policy_available": False,
        }


@threats_bp.get("")
@login_required
def list_threats():
    severity = request.args.get("severity")
    limit = request.args.get("limit", type=int)
    query, params = "SELECT * FROM threats", []
    if severity:
        query += " WHERE severity = %s"
        params.append(severity)
    query += " ORDER BY detected_at DESC"
    if limit is not None:
        query += " LIMIT %s"
        params.append(max(1, min(limit, 100)))
    with database_cursor() as (_connection, cursor):
        cursor.execute(query, params)
        rows = cursor.fetchall()
    return success([enrich_threat(row) for row in rows], "Threats retrieved successfully")


@threats_bp.get("/<int:threat_id>")
@login_required
def get_threat(threat_id):
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT * FROM threats WHERE threat_id = %s", (threat_id,))
        row = cursor.fetchone()
    return success(enrich_threat(row), "Threat retrieved successfully") if row else failure("Threat not found", 404)


@threats_bp.get("/<int:threat_id>/incidents")
@analyst_or_admin_required
def list_threat_incidents(threat_id):
    """Expose only genuine incident links; analysts remain limited to their tickets."""
    query = (
        "SELECT i.ticket_id, i.threat_id, i.status, i.priority, i.created_at, i.updated_at, "
        "u.username AS assigned_username FROM incidents i "
        "LEFT JOIN users u ON u.user_id = i.assigned_to WHERE i.threat_id = %s"
    )
    params = [threat_id]
    from flask import session
    if session.get("role") != "admin":
        query += " AND i.assigned_to = %s"
        params.append(session["user_id"])
    query += " ORDER BY i.updated_at DESC"
    with database_cursor() as (_connection, cursor):
        cursor.execute(query, params)
        rows = cursor.fetchall()
    return success(rows, "Linked incidents retrieved successfully")


@threats_bp.post("")
@analyst_or_admin_required
def create_threat():
    data = request.get_json(silent=True) or {}
    missing = required_fields(data, ["attack_type", "source_ip", "destination_ip", "severity", "confidence_score", "description"])
    if missing or data.get("severity") not in VALID_SEVERITIES:
        return failure("Provide all required fields and a valid severity")
    status = data.get("status", "New")
    if status not in VALID_STATUSES:
        return failure("Invalid threat status")
    with database_cursor() as (_connection, cursor):
        cursor.execute("INSERT INTO threats (attack_type, source_ip, destination_ip, severity, confidence_score, status, description) VALUES (%s, %s, %s, %s, %s, %s, %s)", (data["attack_type"], data["source_ip"], data["destination_ip"], data["severity"], data["confidence_score"], status, data["description"]))
        record_id = cursor.lastrowid
    return success({"threat_id": record_id}, "Threat created successfully", 201)


@threats_bp.put("/<int:threat_id>")
@analyst_or_admin_required
def update_threat(threat_id):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in VALID_STATUSES:
        return failure("Status must be New, Investigating, or Resolved")
    with database_cursor() as (_connection, cursor):
        cursor.execute("UPDATE threats SET status = %s WHERE threat_id = %s", (status, threat_id))
        if cursor.rowcount == 0:
            return failure("Threat not found", 404)
    return success({"threat_id": threat_id, "status": status}, "Threat status updated successfully")
