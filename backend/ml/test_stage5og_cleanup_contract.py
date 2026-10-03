"""Static Stage 5O-G dependency checks; no database or capture activity occurs."""
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    pages = {path.name: path.read_text(encoding="utf-8") for path in (PROJECT_ROOT / "pages").glob("*.html")}
    app_script = (PROJECT_ROOT / "js" / "app.js").read_text(encoding="utf-8")
    account_script = (PROJECT_ROOT / "js" / "account.js").read_text(encoding="utf-8")
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    protected_paths = (
        PROJECT_ROOT / "database" / "seed.sql",
        PROJECT_ROOT / "database" / "migrations",
        PROJECT_ROOT / "datasets",
        PROJECT_ROOT / "backend" / "ml" / "models",
        PROJECT_ROOT / "Wireshark" / "demo.pcapng",
        PROJECT_ROOT / "pages" / "examiner-demo.html",
    )
    result = {
        "legacy_combined_monitoring_removed": not (PROJECT_ROOT / "pages" / "live-monitoring.html").exists() and not (PROJECT_ROOT / "js" / "live-monitoring.js").exists(),
        "obsolete_sample_data_removed": not (PROJECT_ROOT / "js" / "sample-data.js").exists(),
        "current_monitoring_workflows_present": all((PROJECT_ROOT / "pages" / name).exists() for name in ("live-sensor.html", "manual-capture.html", "ai-detection.html")),
        "navigation_uses_current_workflows": all(label in app_script for label in ("Live Sensor", "Manual AI Capture", "AI Detection")) and "live-monitoring.html" not in app_script,
        "password_change_script_preserved": "account.js" in pages["change-password.html"] and "change-password-form" in account_script,
        "protected_assets_preserved": all(path.exists() for path in protected_paths),
        "local_secrets_and_venv_ignored": all(entry in gitignore for entry in (".env", "backend/.env", ".venv/", "__pycache__/")),
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
