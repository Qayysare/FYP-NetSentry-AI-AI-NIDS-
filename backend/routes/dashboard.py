from flask import Blueprint, current_app
from database import database_cursor
from services.device_identity import valid_unicast_mac_sql
from utils.helpers import login_required, success

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.get("/stats")
@login_required
def stats():
    active_seconds = max(int(current_app.config["DEVICE_ACTIVE_SECONDS"]), 1)
    valid_identity = valid_unicast_mac_sql("mac_address")
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT COALESCE(SUM(bytes_transferred), 0) AS total_network_traffic FROM network_traffic")
        traffic = cursor.fetchone()["total_network_traffic"]
        cursor.execute(
            f"SELECT COUNT(*) AS total FROM devices WHERE {valid_identity} "
            "AND last_activity >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL %s SECOND)",
            (active_seconds,),
        )
        devices = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) AS total FROM threats")
        threats = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) AS total FROM threats WHERE severity = 'Critical' AND status <> 'Resolved'")
        critical = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) AS total FROM threats WHERE severity = 'High' AND status <> 'Resolved'")
        high = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) AS total FROM threats WHERE status IN ('New', 'Investigating')")
        unresolved = cursor.fetchone()["total"]
    return success({"total_network_traffic": traffic, "connected_devices": devices, "detected_threats": threats, "critical_alerts": critical, "high_alerts": high, "new_or_unresolved_threats": unresolved}, "Dashboard statistics retrieved successfully")


@dashboard_bp.get("/network-activity")
@login_required
def network_activity():
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT DATE_FORMAT(timestamp, '%H:%i') AS label, SUM(bytes_transferred) AS value FROM network_traffic GROUP BY DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i') ORDER BY timestamp")
        rows = cursor.fetchall()
    return success(rows, "Network activity retrieved successfully")


@dashboard_bp.get("/threat-overview")
@login_required
def threat_overview():
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT CASE WHEN severity IN ('Critical', 'High') THEN 'Malicious' WHEN severity = 'Medium' THEN 'Suspicious' ELSE 'Normal' END AS label, COUNT(*) AS value FROM threats GROUP BY label")
        rows = cursor.fetchall()
    return success(rows, "Threat overview retrieved successfully")


# --- NEW ENDPOINT ADDED BELOW ---
@dashboard_bp.get("/recent-threats")
@login_required
def recent_threats():
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT threat_id, attack_type, source_ip, destination_ip, severity, confidence_score, COALESCE(NULLIF(status, ''), 'Unspecified') AS status, detected_at FROM threats ORDER BY detected_at DESC LIMIT 5")
        rows = cursor.fetchall()
    return success(rows, "Recent threats retrieved successfully")
