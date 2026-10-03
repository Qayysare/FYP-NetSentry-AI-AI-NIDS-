"""Static Stage 5M contract checks; no database, capture, or model activity."""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def main():
    sensor_html = (ROOT / "pages" / "live-sensor.html").read_text(encoding="utf-8")
    sensor_js = (ROOT / "js" / "live-sensor.js").read_text(encoding="utf-8")
    incidents_route = (ROOT / "backend" / "routes" / "incidents.py").read_text(encoding="utf-8")
    migration = (ROOT / "database" / "migrations" / "003_stage5m_incident_response.sql").read_text(encoding="utf-8")
    validation_route = (ROOT / "backend" / "routes" / "ai_detection.py").read_text(encoding="utf-8")
    result = {
        "live_charts_use_current_session_data": all(text in sensor_html + sensor_js for text in (
            "live-classification-chart", "live-severity-chart", "status.ai_flows", "started_at", "resetSession",
        )),
        "live_classification_has_five_series": all(label in sensor_js for label in (
            "BENIGN", "PortScan", "DDoS", "SSH-Patator", "FTP-Patator",
        )) and 'type:"line"' in sensor_js,
        "validation_isolated": "validation-summary" in validation_route and "persist_malicious_predictions" not in validation_route.split('def validation_summary')[1].split('@ai_detection_bp.post')[0],
        "incident_response_fields_migrated": all(text in migration for text in ("investigation_findings", "mitigation_taken", "handled_by", "verified_by", "verification_remarks")),
        "handler_verifier_server_controlled": "session[\"user_id\"]" in incidents_route and "Administrator verification is required" in incidents_route,
        "no_tshark_integration_code": "TShark" not in incidents_route,
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    if not result["passed"]: raise SystemExit(1)

if __name__ == "__main__": main()
