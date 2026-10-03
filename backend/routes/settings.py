from flask import Blueprint, request
from database import database_cursor
from utils.helpers import admin_required, failure, success

settings_bp = Blueprint("settings", __name__, url_prefix="/api/settings")


@settings_bp.get("")
@admin_required
def list_settings():
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT * FROM system_settings ORDER BY setting_name")
        rows = cursor.fetchall()
    return success(rows, "Settings retrieved successfully")


@settings_bp.put("/<int:setting_id>")
@admin_required
def update_setting(setting_id):
    data = request.get_json(silent=True) or {}
    if "setting_value" not in data:
        return failure("setting_value is required")
    with database_cursor() as (_connection, cursor):
        cursor.execute("UPDATE system_settings SET setting_value = %s WHERE setting_id = %s", (str(data["setting_value"]), setting_id))
        if cursor.rowcount == 0:
            return failure("Setting not found", 404)
    return success({"setting_id": setting_id}, "Setting updated successfully")
