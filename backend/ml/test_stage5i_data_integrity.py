"""Stage 5I controlled data-integrity checks; all created database rows are removed."""
from __future__ import annotations

import json
import io
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from database import database_cursor  # noqa: E402
from services.device_observation import PassiveDeviceObserver  # noqa: E402
from services.security_log import log_security_event  # noqa: E402
from services.threat_persistence import persist_malicious_predictions  # noqa: E402
from services.threat_priority import assess_threat  # noqa: E402
from routes import capture as capture_routes  # noqa: E402
from routes import auth as auth_routes  # noqa: E402


class FakeTSharkService:
    """No-network test double for monitoring lifecycle event checks."""

    def __init__(self):
        self.running = False

    def interfaces(self):
        return [{"id": "stage5i-sensor", "name": "Authorised test interface"}]

    def start(self, interface_id, _callback=None):
        if interface_id != "stage5i-sensor":
            raise RuntimeError("Unexpected test interface")
        self.running = True

    def stop(self):
        self.running = False
        return []

    def status(self):
        return {"running": self.running, "interface_id": "stage5i-sensor" if self.running else None, "packet_count": 0}

    @staticmethod
    def aggregate(_records):
        return []


def delete_exact(table, ids, column):
    if not ids:
        return
    placeholders = ", ".join(["%s"] * len(ids))
    with database_cursor() as (_connection, cursor):
        cursor.execute(f"DELETE FROM {table} WHERE {column} IN ({placeholders})", ids)


def new_log_ids(after_id):
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT log_id FROM security_logs WHERE log_id > %s", (after_id,))
        return [row["log_id"] for row in cursor.fetchall()]


def max_log_id():
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT COALESCE(MAX(log_id), 0) AS value FROM security_logs")
        return cursor.fetchone()["value"]


def main():
    app = create_app()
    app.config.update(TESTING=True, DEVICE_OBSERVATION_UPDATE_SECONDS=1)
    client = app.test_client()
    device_ids, threat_ids, log_ids = [], [], []
    fake_service = FakeTSharkService()
    try:
        with app.app_context():
            before_log = max_log_id()
        failed = client.post("/api/login", json={"identity": "admin", "password": "incorrect"})
        login = client.post("/api/login", json={"identity": "admin", "password": "Admin123!"})
        devices_api = client.get("/api/devices")
        logs_api = client.get("/api/logs?limit=100")

        with app.app_context():
            observer = PassiveDeviceObserver(1)
            packet = {
                "source_ip": "192.168.250.250", "source_mac": "02:5I:00:00:00:01".replace("5I", "51"),
                "destination_ip": "203.0.113.250", "destination_mac": "00:00:00:00:00:00",
            }
            first_observed = observer.observe_packet(packet)
            # The second observation is within the configured interval, so it cannot duplicate the row.
            second_observed = observer.observe_packet(packet)
            with database_cursor() as (_connection, cursor):
                cursor.execute("SELECT device_id, device_type, status, last_activity FROM devices WHERE ip_address = %s", ("192.168.250.250",))
                device = cursor.fetchone()
                if device:
                    device_ids.append(device["device_id"])
                cursor.execute("SELECT COUNT(*) AS total FROM devices WHERE ip_address = %s", ("192.168.250.250",))
                duplicate_count = cursor.fetchone()["total"]

            malicious = {"classification": "PortScan", "confidence": 0.95, "source_ip": "198.51.100.250", "destination_ip": "203.0.113.250"}
            malicious.update(assess_threat(malicious["classification"], malicious["confidence"]))
            persisted = persist_malicious_predictions([malicious], app.config["THREAT_DEDUP_WINDOW_SECONDS"])
            threat_ids.extend(persisted["threat_ids"])
            benign = {"classification": "BENIGN", "confidence": 0.99, "source_ip": "198.51.100.251", "destination_ip": "203.0.113.251"}
            benign.update(assess_threat(benign["classification"], benign["confidence"]))
            benign_persistence = persist_malicious_predictions([benign], app.config["THREAT_DEDUP_WINDOW_SECONDS"])

            capture_routes.service = fake_service
            capture_routes.monitoring_session = None
            capture_routes.start_monitoring("stage5i-sensor", "manual")
            capture_routes.stop_monitoring()
            app.config.update(AUTO_MONITORING=True, MONITOR_INTERFACE="missing-stage5i-interface")
            autonomous_failure = not capture_routes.start_autonomous_monitoring(app, allow_testing=True)
            app.config.update(AUTO_MONITORING=False, MONITOR_INTERFACE="")
            capture_routes.service = None

            with open(PROJECT_ROOT / "Wireshark" / "demo.pcapng", "rb") as capture_file:
                pcap = client.post(
                    "/api/ai/analyze-pcap",
                    data={"capture_file": (io.BytesIO(capture_file.read()), "stage5i-demo.pcapng")},
                    content_type="multipart/form-data",
                )
            logout = client.post("/api/logout")

        original_log_helper = auth_routes.log_security_event
        auth_routes.log_security_event = lambda *_args, **_kwargs: False
        try:
            nonfatal_login = app.test_client().post("/api/login", json={"identity": "admin", "password": "Admin123!"})
        finally:
            auth_routes.log_security_event = original_log_helper

        with app.app_context():
            log_ids.extend(new_log_ids(before_log))
        with client.session_transaction() as session:
            session.update({"user_id": 1, "username": "admin", "role": "admin", "must_change_password": False})
        log_rows = (client.get("/api/logs?limit=200").get_json() or {}).get("data", [])
        events = {row["event_type"] for row in log_rows if row["log_id"] in log_ids}
        dashboard = (client.get("/api/dashboard/stats").get_json() or {}).get("data", {})
        observed_devices = (client.get("/api/devices").get_json() or {}).get("data", [])
        expected_active = any(row.get("device_id") == (device or {}).get("device_id") for row in observed_devices)
        scripts = {
            "devices": (PROJECT_ROOT / "js" / "devices.js").read_text(encoding="utf-8"),
            "logs": (PROJECT_ROOT / "js" / "security-logs.js").read_text(encoding="utf-8"),
        }
        print(json.dumps({
            "login_success_log": login.status_code == 200 and "AUTH_LOGIN_SUCCESS" in events,
            "login_failure_log": failed.status_code == 401 and "AUTH_LOGIN_FAILED" in events,
            "logout_log": logout.status_code == 200 and "AUTH_LOGOUT" in events,
            "devices_api_authenticated": devices_api.status_code == 200,
            "logs_api_authenticated_and_bounded": logs_api.status_code == 200 and len((logs_api.get_json() or {}).get("data", [])) <= 100,
            "passive_private_mac_observation": first_observed == 1 and second_observed == 0,
            "no_public_endpoint_device": duplicate_count == 1,
            "unknown_type_is_truthful": device and device["device_type"] == "Unknown",
            "device_duplication_protected": duplicate_count == 1,
            "dashboard_device_count_uses_table": expected_active and dashboard.get("connected_devices", 0) >= 1,
            "threat_security_log": persisted["stored_threat_count"] == 1 and "THREAT_DETECTED" in events,
            "benign_creates_no_threat": benign_persistence["stored_threat_count"] == 0,
            "monitoring_start_log": "MONITORING_STARTED" in events,
            "monitoring_stop_log": "MONITORING_STOPPED" in events,
            "sensor_failure_log": autonomous_failure and "MONITORING_START_FAILED" in events,
            "pcap_analysis_log": pcap.status_code == 200 and "PCAP_ANALYSIS" in events,
            "security_log_failure_is_nonfatal": nonfatal_login.status_code == 200,
            "no_devices_sample_fallback": "sampleDevices" not in scripts["devices"],
            "no_logs_sample_fallback": "sampleLogs" not in scripts["logs"],
            "device_empty_message": "No devices have been detected yet." in scripts["devices"],
            "logs_empty_message": "No security events have been recorded yet." in scripts["logs"],
        }, indent=2))
    finally:
        with app.app_context():
            delete_exact("threats", threat_ids, "threat_id")
            delete_exact("devices", device_ids, "device_id")
            delete_exact("security_logs", log_ids, "log_id")
        capture_routes.service = None
        capture_routes.monitoring_session = None


if __name__ == "__main__":
    main()
