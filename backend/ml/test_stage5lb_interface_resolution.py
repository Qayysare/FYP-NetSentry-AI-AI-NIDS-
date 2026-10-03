"""Stage 5L-B interface-resolution checks using a fake TShark service only."""
from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from routes import capture as capture_routes  # noqa: E402
from services.tshark_service import TSharkError, TSharkService  # noqa: E402


class FakeTSharkService:
    """Current discovery metadata changes ID but retains a friendly adapter name."""

    def __init__(self):
        self.running = False
        self.starts = []

    def interfaces(self):
        return [{
            "id": "14",
            "name": r"\Device\NPF_{CURRENT-SESSION} (Ethernet 3)",
            "friendly_name": "Ethernet 3",
        }]

    def start(self, interface_id, _callback=None):
        if self.running:
            raise TSharkError("A capture is already running.")
        if interface_id != "14":
            raise TSharkError("Selected capture interface is not available.")
        self.running = True
        self.starts.append(interface_id)

    def stop(self):
        if not self.running:
            raise TSharkError("No capture is currently running.")
        self.running = False
        return []

    def status(self):
        return {"running": self.running, "interface_id": "14" if self.running else None, "packet_count": 0}

    @staticmethod
    def aggregate(_records):
        return []


def main():
    app = create_app()
    app.config.update(TESTING=True, AUTO_MONITORING=True, MONITOR_INTERFACE="Ethernet 3")
    fake = FakeTSharkService()
    capture_routes.service = fake
    capture_routes.monitoring_session = None
    capture_routes.monitoring_last_error = None
    capture_routes.monitoring_stopped_by_operator = False
    interfaces = fake.interfaces()
    try:
        numeric = TSharkService.resolve_interface("14", interfaces)
        friendly = TSharkService.resolve_interface("Ethernet 3", interfaces)
        unavailable = TSharkService.resolve_interface("Missing adapter", interfaces)
        autonomous_started = capture_routes.start_autonomous_monitoring(app, allow_testing=True)
        client = app.test_client()
        with client.session_transaction() as session:
            session.update({"user_id": 1, "username": "stage5lb", "role": "admin"})
        active = (client.get("/api/capture/status").get_json() or {}).get("data", {})
        try:
            with app.app_context():
                capture_routes.start_monitoring("14", "manual")
            duplicate_rejected = False
        except TSharkError:
            duplicate_rejected = True
        starts_after_duplicate_attempt = len(fake.starts)
        with app.app_context():
            stopped = capture_routes.stop_monitoring()
            manual = capture_routes.start_monitoring("14", "manual")
            capture_routes.stop_monitoring()
        print(json.dumps({
            "numeric_configuration_resolves": numeric and numeric["id"] == "14",
            "friendly_configuration_resolves": friendly and friendly["id"] == "14",
            "unavailable_friendly_name_is_safe": unavailable is None,
            "autonomous_uses_resolved_current_id": autonomous_started and fake.starts[0] == "14",
            "status_keeps_friendly_configured_name": active.get("interface") == "Ethernet 3" and active.get("interface_name") == "Ethernet 3",
            "duplicate_session_rejected": duplicate_rejected and starts_after_duplicate_attempt == 1,
            "manual_numeric_start_preserved": manual["running"] is True and fake.starts == ["14", "14"],
            "worker_cleanup_preserved": stopped["worker_running"] is False and not fake.running,
        }, indent=2))
    finally:
        capture_routes.service = None
        capture_routes.monitoring_session = None


if __name__ == "__main__":
    main()
