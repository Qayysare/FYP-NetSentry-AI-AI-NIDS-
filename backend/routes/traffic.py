from flask import Blueprint, request
from database import database_cursor
from utils.helpers import analyst_or_admin_required, failure, required_fields, success

traffic_bp = Blueprint("traffic", __name__, url_prefix="/api/traffic")


@traffic_bp.get("")
@analyst_or_admin_required
def list_traffic():
    protocol = request.args.get("protocol")
    query = "SELECT traffic_id, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, bytes_transferred, timestamp FROM network_traffic"
    params = []
    if protocol:
        query += " WHERE protocol = %s"
        params.append(protocol)
    query += " ORDER BY timestamp DESC"
    with database_cursor() as (_connection, cursor):
        cursor.execute(query, params)
        rows = cursor.fetchall()
    return success(rows, "Traffic records retrieved successfully")


@traffic_bp.get("/<int:traffic_id>")
@analyst_or_admin_required
def get_traffic(traffic_id):
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT * FROM network_traffic WHERE traffic_id = %s", (traffic_id,))
        row = cursor.fetchone()
    return success(row, "Traffic record retrieved successfully") if row else failure("Traffic record not found", 404)


@traffic_bp.post("")
@analyst_or_admin_required
def create_traffic():
    data = request.get_json(silent=True) or {}
    missing = required_fields(data, ["source_ip", "destination_ip", "source_port", "destination_port", "protocol", "packet_count", "bytes_transferred"])
    if missing:
        return failure("Missing required fields: " + ", ".join(missing))
    with database_cursor() as (_connection, cursor):
        cursor.execute("INSERT INTO network_traffic (source_ip, destination_ip, source_port, destination_port, protocol, packet_count, bytes_transferred) VALUES (%s, %s, %s, %s, %s, %s, %s)", tuple(data[key] for key in ["source_ip", "destination_ip", "source_port", "destination_port", "protocol", "packet_count", "bytes_transferred"]))
        record_id = cursor.lastrowid
    return success({"traffic_id": record_id}, "Traffic record created successfully", 201)
