"""Actual Flask route-registration regression test with an in-memory cursor stub."""
from contextlib import contextmanager
from pathlib import Path
import sys
import json

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app import create_app  # noqa: E402
import routes.incidents as incident_routes  # noqa: E402


class Cursor:
    def __init__(self, row): self.row = row
    def execute(self, *_args, **_kwargs): pass
    def fetchone(self): return self.row


def client_for(app, role="admin"):
    client = app.test_client()
    with client.session_transaction() as session:
        session.update(user_id=1, username="route-test", role=role)
    return client


def response_for(app, status, verified_by=None):
    row = {"ticket_id": 1, "threat_id": 110, "status": status, "verified_by": verified_by,
           "verified_username": "administrator" if verified_by else None, "verified_at": None,
           "verification_remarks": None, "attack_type": "DDoS", "severity": "Critical",
           "confidence_score": 95, "source_ip": "192.0.2.1", "destination_ip": "192.0.2.2"}
    @contextmanager
    def cursor_stub(**_kwargs): yield None, Cursor(row)
    original = incident_routes.database_cursor
    incident_routes.database_cursor = cursor_stub
    try: return client_for(app).get("/api/incidents/1/report")
    finally: incident_routes.database_cursor = original


def main():
    app = create_app()
    app.config["TESTING"] = True
    routes = {str(rule): rule.methods for rule in app.url_map.iter_rules()}
    resolved = response_for(app, "Resolved")
    closed = response_for(app, "Closed", verified_by=2)
    assigned = response_for(app, "Assigned")
    anonymous = app.test_client().get("/api/incidents/1/report")
    result = {
        "canonical_route_registered": "/api/incidents/<int:ticket_id>/report" in routes and "GET" in routes["/api/incidents/<int:ticket_id>/report"],
        "resolved_success": resolved.status_code == 200,
        "closed_success": closed.status_code == 200 and (closed.get_json() or {}).get("data", {}).get("verified_username") == "administrator",
        "assigned_unavailable": assigned.status_code == 409,
        "authentication_preserved": anonymous.status_code == 401,
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__": main()
