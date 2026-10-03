"""Stage 5H evidence test: held-out prediction, policy, propagation and cleanup."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app import create_app  # noqa: E402
from database import database_cursor  # noqa: E402
from ml.predictor import FlowPredictor  # noqa: E402
from services.feature_schema import LABEL_COLUMN, RUNTIME_FEATURE_COLUMNS  # noqa: E402
from services.threat_persistence import persist_malicious_predictions  # noqa: E402
from services.threat_priority import assess_threat  # noqa: E402


CLASSES = ("BENIGN", "PortScan", "FTP-Patator", "SSH-Patator", "DDoS")
POLICY_EXPECTATIONS = {
    "BENIGN": ("Informational", "Monitor"),
    "PortScan": ("Medium", "Review"),
    "FTP-Patator": ("High", "Investigate"),
    "SSH-Patator": ("High", "Investigate"),
    "DDoS": ("Critical", "Immediate Attention"),
}


def authenticated_client(app):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "stage5h-validation"
        session["role"] = "admin"
    return client


def distribution(rows):
    return {row["label"]: int(row["value"]) for row in rows}


def delete_exact(table, column, identifiers):
    identifiers = [identifier for identifier in identifiers if identifier]
    if not identifiers:
        return
    placeholders = ", ".join(["%s"] * len(identifiers))
    with database_cursor() as (_connection, cursor):
        cursor.execute(f"DELETE FROM {table} WHERE {column} IN ({placeholders})", identifiers)


def main():
    app = create_app()
    app.config["TESTING"] = True
    client = authenticated_client(app)
    predictor = FlowPredictor()
    test_data = pd.read_csv(PROJECT_ROOT / "datasets" / "processed" / "test.csv")
    samples = test_data.groupby(LABEL_COLUMN, group_keys=False).head(3)
    predictions = predictor.predict_flows(samples[RUNTIME_FEATURE_COLUMNS].to_dict("records"))

    validation_rows = []
    selected = {}
    for expected, prediction in zip(samples[LABEL_COLUMN], predictions):
        row = {
            "expected": expected,
            "predicted": prediction["classification"],
            "confidence": round(float(prediction["confidence"]), 6),
            "correct": prediction["classification"] == expected,
        }
        validation_rows.append(row)
        if expected not in selected and row["correct"]:
            selected[expected] = prediction
    if set(selected) != set(CLASSES):
        raise RuntimeError("The held-out validation sample did not provide one correct representative per class.")

    matrix = {}
    for expected in CLASSES:
        prediction = selected[expected]
        policy = assess_threat(prediction["classification"], prediction["confidence"])
        matrix[expected] = {
            "expected": expected,
            "predicted": prediction["classification"],
            "confidence": round(float(prediction["confidence"]), 6),
            "correct": prediction["classification"] == expected,
            "severity": policy["severity"],
            "priority": policy["priority"],
            "recommended_action": policy["recommended_action"],
        }

    endpoints = {
        "types": "/api/analytics/threat-distribution",
        "severity": "/api/analytics/severity-distribution",
        "status": "/api/analytics/status-distribution",
        "trend": "/api/analytics/threat-trend",
    }
    before_stats = (client.get("/api/dashboard/stats").get_json() or {}).get("data", {})
    before_analytics = {name: distribution((client.get(url).get_json() or {}).get("data", [])) for name, url in endpoints.items()}
    before_report = client.post("/api/reports/generate", json={"period": "today"})
    report_ids = [(before_report.get_json() or {}).get("data", {}).get("report_id")]
    threat_ids = []
    cleanup_verified = False
    try:
        controlled = []
        benign_prediction = None
        for offset, expected in enumerate(CLASSES):
            prediction = selected[expected]
            enriched = {
                "classification": prediction["classification"],
                "confidence": prediction["confidence"],
                "source_ip": f"198.51.100.{230 + offset}",
                "destination_ip": f"203.0.113.{230 + offset}",
                **assess_threat(prediction["classification"], prediction["confidence"]),
            }
            if expected == "BENIGN":
                benign_prediction = enriched
            else:
                controlled.append(enriched)
        with app.app_context():
            benign = persist_malicious_predictions([benign_prediction], 300)
            inserted = persist_malicious_predictions(controlled, 300)
            threat_ids = inserted["threat_ids"]
            repeated = persist_malicious_predictions(controlled, 300)

        threat_responses = [
            (client.get(f"/api/threats/{threat_id}").get_json() or {}).get("data", {})
            for threat_id in threat_ids
        ]
        after_stats = (client.get("/api/dashboard/stats").get_json() or {}).get("data", {})
        recent = (client.get("/api/dashboard/recent-threats").get_json() or {}).get("data", [])
        after_analytics = {name: distribution((client.get(url).get_json() or {}).get("data", [])) for name, url in endpoints.items()}
        after_report = client.post("/api/reports/generate", json={"period": "today"})
        after_report_data = (after_report.get_json() or {}).get("data", {})
        report_ids.append(after_report_data.get("report_id"))
    finally:
        with app.app_context():
            delete_exact("reports", "report_id", report_ids)
            delete_exact("threats", "threat_id", threat_ids)
            with database_cursor() as (_connection, cursor):
                threat_total = 0
                report_total = 0
                if threat_ids:
                    placeholders = ", ".join(["%s"] * len(threat_ids))
                    cursor.execute(f"SELECT COUNT(*) AS total FROM threats WHERE threat_id IN ({placeholders})", threat_ids)
                    threat_total = cursor.fetchone()["total"]
                remaining_reports = [report_id for report_id in report_ids if report_id]
                if remaining_reports:
                    placeholders = ", ".join(["%s"] * len(remaining_reports))
                    cursor.execute(f"SELECT COUNT(*) AS total FROM reports WHERE report_id IN ({placeholders})", remaining_reports)
                    report_total = cursor.fetchone()["total"]
                cleanup_verified = threat_total == 0 and report_total == 0

    class_counts = {label: sum(row["expected"] == label for row in validation_rows) for label in CLASSES}
    class_correct = {label: sum(row["expected"] == label and row["correct"] for row in validation_rows) for label in CLASSES}
    expected_severities = {label: values[0] for label, values in POLICY_EXPECTATIONS.items() if label != "BENIGN"}
    propagation_fields = all(
        row.get("attack_type") in expected_severities
        and row.get("severity") == expected_severities[row.get("attack_type")]
        and row.get("priority") == POLICY_EXPECTATIONS[row.get("attack_type")][1]
        and row.get("recommended_action")
        and row.get("status") == "New"
        for row in threat_responses
    )
    analytics_correct = (
        all(after_analytics["types"].get(label, 0) == before_analytics["types"].get(label, 0) + 1 for label in expected_severities)
        and after_analytics["severity"].get("Critical", 0) == before_analytics["severity"].get("Critical", 0) + 1
        and after_analytics["severity"].get("High", 0) == before_analytics["severity"].get("High", 0) + 2
        and after_analytics["severity"].get("Medium", 0) == before_analytics["severity"].get("Medium", 0) + 1
        and after_analytics["status"].get("New", 0) == before_analytics["status"].get("New", 0) + 4
        and sum(after_analytics["trend"].values()) == sum(before_analytics["trend"].values()) + 4
    )
    result = {
        "model_loaded": len(predictor.feature_order) == 20 and set(str(item) for item in predictor.model.classes_) == set(CLASSES),
        "held_out_samples": {"per_class": 3, "total": len(validation_rows), "correct": sum(row["correct"] for row in validation_rows), "by_class": {label: {"correct": class_correct[label], "total": class_counts[label]} for label in CLASSES}},
        "class_matrix": matrix,
        "policy_matches_expected": all((item["severity"], item["priority"]) == POLICY_EXPECTATIONS[label] for label, item in matrix.items()),
        "benign_not_persisted": benign["stored_threat_count"] == 0,
        "malicious_persistence": inserted["stored_threat_count"] == 4 and len(threat_ids) == 4,
        "deduplication": repeated["duplicate_suppressed_count"] == 4,
        "threat_alert_propagation": propagation_fields,
        "dashboard_propagation": after_stats.get("detected_threats") == before_stats.get("detected_threats", 0) + 4 and after_stats.get("critical_alerts") == before_stats.get("critical_alerts", 0) + 1 and after_stats.get("high_alerts") == before_stats.get("high_alerts", 0) + 2 and after_stats.get("new_or_unresolved_threats") == before_stats.get("new_or_unresolved_threats", 0) + 4 and all(row.get("threat_id") in threat_ids for row in recent[:4]),
        "analytics_propagation": analytics_correct,
        "report_propagation": after_report.status_code == 201 and after_report_data.get("total_threats") == (before_report.get_json() or {}).get("data", {}).get("total_threats", 0) + 4 and after_report_data.get("critical_alerts") == (before_report.get_json() or {}).get("data", {}).get("critical_alerts", 0) + 1,
        "exact_cleanup": cleanup_verified,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
