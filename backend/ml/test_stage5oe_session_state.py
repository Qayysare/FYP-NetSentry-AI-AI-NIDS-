"""Static frontend contracts for Stage 5O-E session-state consistency."""
from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    shared = (PROJECT_ROOT / "js" / "live-ai-results.js").read_text(encoding="utf-8")
    sensor = (PROJECT_ROOT / "js" / "live-sensor.js").read_text(encoding="utf-8")
    manual = (PROJECT_ROOT / "js" / "manual-capture.js").read_text(encoding="utf-8")
    sensor_html = (PROJECT_ROOT / "pages" / "live-sensor.html").read_text(encoding="utf-8")
    manual_html = (PROJECT_ROOT / "pages" / "manual-capture.html").read_text(encoding="utf-8")
    result = {
        "shared_session_identity_uses_started_at": "status?.started_at" in shared,
        "shared_reset_clears_cursor_and_rows": all(token in shared for token in ("resetForNewSession", "cursor = 0", "results.clear()", "renderRows([])")),
        "same_identity_does_not_reset": "identity === activeSessionIdentity" in shared,
        "manual_resets_and_refetches_new_session": "manualView.syncSession(status)" in manual and 'apiRequest("/api/capture/status?after=0")' in manual,
        "sensor_resets_charts_and_refetches_new_session": "sensorView.syncSession(status)" in sensor and "resetSensorCharts()" in sensor and 'apiRequest("/api/capture/status?after=0")' in sensor,
        "old_result_ids_not_used_as_identity": "latest_result_id" not in shared and "result_id !==" not in sensor and "result_id !==" not in manual,
        "stopped_state_clears_current_mode_interface": 'status.running ? status.mode' in manual and 'running ? status.interface_name' in sensor and ' : "—"' in manual and ' : "—"' in sensor,
        "completed_results_labeled_historical": "Results from the last completed monitoring session." in shared and "Last completed monitoring session" in sensor and "Last completed monitoring session" in manual,
        "polling_overlap_guarded": "sensorUpdating" in sensor and "manualUpdating" in manual and "sensorUpdateVersion" in sensor and "manualUpdateVersion" in manual,
        "one_interval_per_page": sensor.count("setInterval(update, 3000)") == 1 and manual.count("setInterval(updateManualStatus, 3000)") == 1,
        "current_session_ui_fields_present": all(token in sensor_html for token in ("Current Interface", "Current Mode", "live-session-results-note")) and all(token in manual_html for token in ("Current Interface", "Current Mode", "live-session-results-note")),
        "stage5ob_role_behavior_preserved": 'role === "admin"' in sensor and 'role === "admin"' in manual,
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
