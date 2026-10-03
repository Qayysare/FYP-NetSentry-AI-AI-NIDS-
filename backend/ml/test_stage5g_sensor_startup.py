"""Stage 5G lifecycle tests using a fake TShark service; no live capture occurs."""
from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from routes import capture as capture_routes  # noqa: E402
from services.tshark_service import TSharkError  # noqa: E402


class FakeTSharkService:
    """Minimal safe replacement for validating sensor lifecycle orchestration."""

    def __init__(self):
        self.running = False
        self.interface_id = None
        self.callback = None
        self.starts = 0
        self.stops = 0

    def interfaces(self):
        return [{"id": "sensor-1", "name": "Authorised test sensor interface"}]

    def start(self, interface_id, callback=None):
        if self.running:
            raise TSharkError("A capture is already running.")
        if interface_id != "sensor-1":
            raise TSharkError("Selected capture interface is not available.")
        self.running = True
        self.interface_id = interface_id
        self.callback = callback
        self.starts += 1

    def stop(self):
        if not self.running:
            raise TSharkError("No capture is currently running.")
        self.running = False
        self.interface_id = None
        self.callback = None
        self.stops += 1
        return []

    def status(self):
        return {"running": self.running, "interface_id": self.interface_id, "packet_count": 0}

    @staticmethod
    def aggregate(_records):
        return []


def authenticated_client(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "stage5g-test"
        session["role"] = "admin"
    return client


def main():
    app = create_app()
    # A real local .env may intentionally enable the sensor for deployment.
    # Verify the safe source default rather than treating that override as a failure.
    config_source = (PROJECT_ROOT / "backend" / "config.py").read_text(encoding="utf-8")
    default_auto_monitoring = 'AI_NIDS_AUTO_MONITORING", "false"' in config_source
    app.config.update(TESTING=True, AUTO_MONITORING=True, MONITOR_INTERFACE="sensor-1")
    fake = FakeTSharkService()
    capture_routes.service = fake
    capture_routes.monitoring_session = None
    capture_routes.monitoring_last_error = None
    capture_routes.monitoring_stopped_by_operator = False

    testing_protected = not capture_routes.start_autonomous_monitoring(app)
    started = capture_routes.start_autonomous_monitoring(app, allow_testing=True)
    client = authenticated_client(app)
    active = client.get("/api/capture/status?after=0")
    try:
        with app.app_context():
            capture_routes.start_monitoring("sensor-1", "manual")
        duplicate_rejected = False
    except TSharkError:
        duplicate_rejected = True
    with app.app_context():
        stopped = capture_routes.stop_monitoring()
        restarted = capture_routes.start_autonomous_monitoring(app, allow_testing=True)
        capture_routes.stop_monitoring()

    app.config["MONITOR_INTERFACE"] = "missing-interface"
    invalid_started = capture_routes.start_autonomous_monitoring(app, allow_testing=True)
    invalid_status = client.get("/api/capture/status?after=0")
    invalid_data = (invalid_status.get_json() or {}).get("data", {})
    sensor_html = (PROJECT_ROOT / "pages" / "live-sensor.html").read_text(encoding="utf-8")
    sensor_js = (PROJECT_ROOT / "js" / "live-sensor.js").read_text(encoding="utf-8")
    app_source = (PROJECT_ROOT / "backend" / "app.py").read_text(encoding="utf-8")
    factory_source = app_source.split('if __name__ == "__main__":', maxsplit=1)[0]

    result = {
        "default_auto_monitoring_is_false": default_auto_monitoring,
        "testing_does_not_auto_start": testing_protected and fake.starts == 2,
        "autonomous_start_succeeds_when_explicitly_allowed": started,
        "active_status_is_autonomous": active.status_code == 200 and (active.get_json() or {}).get("data", {}).get("mode") == "autonomous" and (active.get_json() or {}).get("data", {}).get("running") is True,
        "single_sensor_session": fake.starts == 2 and duplicate_rejected,
        "manual_stop_preserved": stopped["running"] is False and stopped["worker_running"] is False,
        "restart_starts_one_new_session": restarted and fake.starts == 2 and fake.stops == 2,
        "invalid_configuration_does_not_start": invalid_started is False and fake.running is False,
        "invalid_configuration_keeps_status_available": invalid_status.status_code == 200 and invalid_data.get("mode") == "autonomous" and bool(invalid_data.get("last_error")),
        "no_orphan_fake_capture": not fake.running,
        "frontend_displays_sensor_mode": 'id="monitoring-mode"' in sensor_html and 'id="monitoring-interface"' in sensor_html and "Autonomous Sensor" in sensor_js,
        "factory_import_is_capture_safe": "start_autonomous_monitoring(application)" not in factory_source,
        "reloader_guard_declared": "WERKZEUG_RUN_MAIN" in app_source and "should_start_sensor" in app_source,
    }
    print(json.dumps(result, indent=2))
    capture_routes.service = None
    capture_routes.monitoring_session = None


if __name__ == "__main__":
    main()
