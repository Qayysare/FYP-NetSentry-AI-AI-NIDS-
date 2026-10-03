from flask import Blueprint, current_app, request
from database import database_cursor
from services.device_identity import valid_unicast_mac_sql
from utils.helpers import analyst_or_admin_required, failure, login_required, required_fields, success

devices_bp = Blueprint("devices", __name__, url_prefix="/api/devices")


@devices_bp.get("")
@login_required
def list_devices():
    active_seconds = max(int(current_app.config["DEVICE_ACTIVE_SECONDS"]), 1)
    valid_identity = valid_unicast_mac_sql("mac_address")
    with database_cursor() as (_connection, cursor):
        cursor.execute(
            "SELECT device_id, device_name, ip_address, mac_address, device_type, "
            "CASE WHEN last_activity >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL %s SECOND) "
            "THEN 'Active' ELSE 'Inactive' END AS status, last_activity, created_at "
            f"FROM devices WHERE {valid_identity} ORDER BY last_activity DESC LIMIT 200",
            (active_seconds,),
        )
        rows = cursor.fetchall()
    return success(rows, "Devices retrieved successfully")


@devices_bp.get("/<int:device_id>")
@login_required
def get_device(device_id):
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT * FROM devices WHERE device_id = %s", (device_id,))
        row = cursor.fetchone()
    return success(row, "Device retrieved successfully") if row else failure("Device not found", 404)


@devices_bp.post("")
@analyst_or_admin_required
def create_device():
    data = request.get_json(silent=True) or {}
    missing = required_fields(data, ["device_name", "ip_address", "mac_address", "device_type"])
    if missing:
        return failure("Missing required fields: " + ", ".join(missing))
    with database_cursor() as (_connection, cursor):
        cursor.execute("INSERT INTO devices (device_name, ip_address, mac_address, device_type, status) VALUES (%s, %s, %s, %s, %s)", (data["device_name"], data["ip_address"], data["mac_address"], data["device_type"], data.get("status", "Online")))
        record_id = cursor.lastrowid
    return success({"device_id": record_id}, "Device created successfully", 201)


@devices_bp.put("/<int:device_id>")
@analyst_or_admin_required
def update_device(device_id):
    data = request.get_json(silent=True) or {}
    if not data.get("status"):
        return failure("A device status is required")
    with database_cursor() as (_connection, cursor):
        cursor.execute("UPDATE devices SET status = %s, last_activity = CURRENT_TIMESTAMP WHERE device_id = %s", (data["status"], device_id))
        if cursor.rowcount == 0:
            return failure("Device not found", 404)
    return success({"device_id": device_id}, "Device updated successfully")
