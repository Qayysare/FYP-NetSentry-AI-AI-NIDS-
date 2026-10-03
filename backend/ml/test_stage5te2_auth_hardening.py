"""Focused Stage 5T-E2 authentication checks without database writes or capture."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from config import INSECURE_DEVELOPMENT_SECRET_KEY, require_production_secret_key  # noqa: E402
import routes.auth as auth_routes  # noqa: E402
import routes.devices as device_routes  # noqa: E402
import routes.reports as report_routes  # noqa: E402
import routes.threats as threat_routes  # noqa: E402


class Cursor:
    def execute(self, *_args, **_kwargs):
        pass

    def fetchall(self):
        return []

    def fetchone(self):
        return {"user_id": 9, "full_name": "Test User", "username": "test-user", "email": "test@example.invalid", "role": "user", "must_change_password": True, "is_active": True}


@contextmanager
def cursor_stub(**_kwargs):
    yield None, Cursor()


def client_for(app, role: str, must_change_password: bool = False):
    client = app.test_client()
    with client.session_transaction() as session:
        session.update(user_id=9, username="test-user", role=role, must_change_password=must_change_password)
    return client


def main() -> None:
    app = create_app()
    app.config["TESTING"] = True
    anonymous = app.test_client()
    user = client_for(app, "user")
    analyst = client_for(app, "analyst")
    admin = client_for(app, "admin")
    must_change = client_for(app, "user", must_change_password=True)

    with patch.object(report_routes, "database_cursor", cursor_stub), \
         patch.object(threat_routes, "database_cursor", cursor_stub), \
         patch.object(device_routes, "database_cursor", cursor_stub), \
         patch.object(auth_routes, "database_cursor", cursor_stub), \
         patch.object(auth_routes, "log_security_event", lambda *_args, **_kwargs: None):
        result = {
            "unauthenticated_protected_apis_rejected": all(response.status_code == 401 for response in (
                anonymous.get("/api/reports"), anonymous.get("/api/capture/status"), anonymous.get("/api/users"),
            )),
            "user_operational_apis_rejected": all(response.status_code == 403 for response in (
                user.get("/api/capture/status"), user.get("/api/analytics/threat-trend"),
                user.get("/api/ai/validation-summary"), user.get("/api/replay/status"),
                user.get("/api/incidents"), user.post("/api/reports/generate", json={"period": "7d"}),
            )),
            "user_read_only_pages_api_contract_preserved": all(response.status_code == 200 for response in (
                user.get("/api/reports"), user.get("/api/threats"), user.get("/api/devices"),
            )),
            "analyst_admin_apis_rejected": all(response.status_code == 403 for response in (
                analyst.get("/api/users"), analyst.get("/api/settings"), analyst.post("/api/capture/start", json={"interface_id": "1"}),
            )),
            "admin_authorization_preserved": admin.get("/api/users").status_code == 200,
            "password_change_gate_blocks_direct_api_bypass": must_change.get("/api/reports").status_code == 403,
            "password_change_gate_allows_session_check": must_change.get("/api/me").status_code == 200,
            "logout_clears_session": False,
            "production_rejects_missing_or_fallback_secret": False,
            "production_accepts_environment_secret": False,
            "login_banner_and_remember_me_corrected": False,
            "demo_password_documentation_removed": False,
        }
        logout = must_change.post("/api/logout")
        result["logout_clears_session"] = logout.status_code == 200 and must_change.get("/api/reports").status_code == 401

    rejected_production_secrets = []
    for unsafe_secret in ("", INSECURE_DEVELOPMENT_SECRET_KEY):
        with patch.dict(os.environ, {"SECRET_KEY": unsafe_secret}, clear=False):
            try:
                require_production_secret_key()
            except RuntimeError:
                rejected_production_secrets.append(unsafe_secret)
    result["production_rejects_missing_or_fallback_secret"] = len(rejected_production_secrets) == 2
    with patch.dict(os.environ, {"SECRET_KEY": "test-only-non-default-secret"}, clear=False):
        try:
            require_production_secret_key()
            result["production_accepts_environment_secret"] = True
        except RuntimeError:
            pass

    login_page = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    seed = (PROJECT_ROOT / "database" / "seed.sql").read_text(encoding="utf-8")
    result["login_banner_and_remember_me_corrected"] = (
        "Authorized access only." in login_page
        and "production authentication will be added" not in login_page
        and "remember-me" not in login_page
    )
    result["demo_password_documentation_removed"] = "Demo account password" not in seed and "Demo account:" not in readme
    result["insecure_default_constant_is_known_only_for_development"] = INSECURE_DEVELOPMENT_SECRET_KEY == "change-this-development-key"
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
