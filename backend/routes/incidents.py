from flask import Blueprint, request, session
from database import database_cursor
from utils.helpers import admin_required, analyst_or_admin_required, failure, login_required, required_fields, success

incidents_bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")
VALID_STATUSES = {"New", "Assigned", "Investigating", "Resolved", "Closed"}


@incidents_bp.get("")
@analyst_or_admin_required
def list_incidents():
    query = ("SELECT i.*, t.attack_type, t.source_ip, t.destination_ip, t.severity, t.confidence_score, "
             "t.description AS threat_description, t.detected_at, u.username AS assigned_username, "
             "ab.username AS assigned_by_username, h.username AS handled_username, v.username AS verified_username "
             "FROM incidents i JOIN threats t ON t.threat_id = i.threat_id "
             "LEFT JOIN users u ON u.user_id = i.assigned_to "
             "LEFT JOIN users ab ON ab.user_id = i.assigned_by "
             "LEFT JOIN users h ON h.user_id = i.handled_by "
             "LEFT JOIN users v ON v.user_id = i.verified_by")
    params = []
    if session.get("role") != "admin":
        query += " WHERE i.assigned_to = %s"
        params.append(session["user_id"])
    query += " ORDER BY i.updated_at DESC"
    with database_cursor() as (_connection, cursor):
        cursor.execute(query, params)
        rows = cursor.fetchall()
    return success(rows, "Incidents retrieved successfully")


@incidents_bp.get("/<int:ticket_id>/report")
@analyst_or_admin_required
def incident_resolution_report(ticket_id):
    """Return one authorized, live Incident Resolution Report; no report row is created."""
    query = (
        "SELECT i.*, t.attack_type, t.source_ip, t.destination_ip, t.severity, t.confidence_score, "
        "t.description AS threat_description, t.detected_at, nt.source_port, nt.destination_port, nt.protocol, "
        "u.username AS assigned_username, ab.username AS assigned_by_username, h.username AS handled_username, "
        "v.username AS verified_username FROM incidents i JOIN threats t ON t.threat_id = i.threat_id "
        "LEFT JOIN network_traffic nt ON nt.traffic_id = t.traffic_id "
        "LEFT JOIN users u ON u.user_id = i.assigned_to LEFT JOIN users ab ON ab.user_id = i.assigned_by "
        "LEFT JOIN users h ON h.user_id = i.handled_by LEFT JOIN users v ON v.user_id = i.verified_by "
        "WHERE i.ticket_id = %s"
    )
    params = [ticket_id]
    if session.get("role") != "admin":
        query += " AND i.assigned_to = %s"
        params.append(session["user_id"])
    with database_cursor() as (_connection, cursor):
        cursor.execute(query, params)
        incident = cursor.fetchone()
    if not incident:
        return failure("Incident not found or not assigned to you", 404)
    if incident["status"] not in {"Resolved", "Closed"}:
        return failure("Incident report becomes available after the ticket is resolved.", 409)
    incident["report_type"] = "incident_resolution"
    incident["verification_status"] = "Verified" if incident.get("verified_by") else "Pending administrator verification"
    return success(incident, "Incident Resolution Report retrieved successfully")


@incidents_bp.post("")
@admin_required
def create_incident():
    data = request.get_json(silent=True) or {}
    missing = required_fields(data, ["threat_id", "priority"])
    if missing:
        return failure("Threat and priority are required")
    with database_cursor() as (_connection, cursor):
        # Do not accidentally create parallel active tickets for the same threat.
        cursor.execute("SELECT ticket_id FROM incidents WHERE threat_id = %s AND status <> 'Closed' ORDER BY ticket_id DESC LIMIT 1", (data["threat_id"],))
        existing = cursor.fetchone()
        if existing:
            return success({"ticket_id": existing["ticket_id"], "existing": True}, "An active incident already exists for this threat")
        cursor.execute("INSERT INTO incidents (threat_id, assigned_to, assigned_by, status, priority, notes) VALUES (%s, %s, %s, %s, %s, %s)", (data["threat_id"], data.get("assigned_to"), session["user_id"], "Assigned" if data.get("assigned_to") else "New", data["priority"], data.get("notes")))
        ticket_id = cursor.lastrowid
    return success({"ticket_id": ticket_id}, "Incident created successfully", 201)


@incidents_bp.put("/<int:ticket_id>")
@analyst_or_admin_required
def update_incident(ticket_id):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in VALID_STATUSES:
        return failure("Provide a valid incident status")
    if data.get("verify") and session.get("role") != "admin":
        return failure("Administrator verification is required", 403)
    if status == "Closed" and session.get("role") != "admin":
        return failure("Only an administrator can close an incident", 403)
    if status == "Closed" and not data.get("verify"):
        with database_cursor() as (_connection, cursor):
            cursor.execute("SELECT verified_by FROM incidents WHERE ticket_id = %s", (ticket_id,))
            existing = cursor.fetchone()
        if not existing or not existing.get("verified_by"):
            return failure("Administrator verification is required before closing an incident", 409)
    query = ("UPDATE incidents SET status = %s, notes = COALESCE(%s, notes), "
             "investigation_findings = COALESCE(%s, investigation_findings), "
             "mitigation_taken = COALESCE(%s, mitigation_taken)")
    params = [status, data.get("notes"), data.get("investigation_findings"), data.get("mitigation_taken")]
    if data.get("mitigation_taken") or status in {"Resolved", "Closed"}:
        query += ", handled_by = %s, handled_at = CURRENT_TIMESTAMP"
        params.append(session["user_id"])
    if data.get("verify"):
        query += ", verified_by = %s, verified_at = CURRENT_TIMESTAMP, verification_remarks = COALESCE(%s, verification_remarks)"
        params.extend([session["user_id"], data.get("verification_remarks")])
    if session.get("role") != "admin":
        query += " WHERE ticket_id = %s AND assigned_to = %s"
        params += [ticket_id, session["user_id"]]
    else:
        query += " WHERE ticket_id = %s"
        params.append(ticket_id)
    with database_cursor() as (_connection, cursor):
        cursor.execute(query, params)
        if cursor.rowcount == 0:
            return failure("Incident not found or not assigned to you", 404)
    return success({"ticket_id": ticket_id}, "Incident updated successfully")
