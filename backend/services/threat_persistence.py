"""Persist policy-validated malicious AI detections using the existing schema."""
from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Any

from mysql.connector import Error

from database import database_cursor
from services.threat_priority import THREAT_POLICY, ThreatPriorityError, assess_threat
from services.security_log import log_security_event


class ThreatPersistenceError(RuntimeError):
    """Raised when validated AI threats cannot be safely persisted."""


def _validated_record(prediction: dict[str, Any]) -> tuple:
    """Validate one enriched model result before starting a database transaction."""
    if not isinstance(prediction, dict):
        raise ThreatPersistenceError("A malicious prediction must be a dictionary.")
    classification = prediction.get("classification")
    if classification == "BENIGN":
        raise ThreatPersistenceError("BENIGN predictions must not be persisted as threats.")
    if classification not in THREAT_POLICY:
        raise ThreatPersistenceError("The prediction classification is not supported for persistence.")
    source_ip = prediction.get("source_ip")
    destination_ip = prediction.get("destination_ip")
    if not isinstance(source_ip, str) or not source_ip or not isinstance(destination_ip, str) or not destination_ip:
        raise ThreatPersistenceError("A malicious prediction requires source and destination IP addresses.")

    try:
        confidence = float(prediction.get("confidence"))
        policy = assess_threat(classification, confidence)
    except (TypeError, ValueError, ThreatPriorityError) as error:
        raise ThreatPersistenceError("The malicious prediction has invalid policy or confidence data.") from error

    # Severity comes from the shared policy; do not trust or duplicate a route value.
    if prediction.get("severity") != policy["severity"]:
        raise ThreatPersistenceError("The malicious prediction does not match the shared severity policy.")
    description = (
        f"AI-NIDS classified traffic as {classification} "
        f"with {confidence:.2%} confidence. {policy['recommended_action']}."
    )
    return classification, source_ip, destination_ip, policy["severity"], round(confidence, 2), description


def persist_malicious_predictions(predictions: list[dict[str, Any]], dedup_window_seconds: int) -> dict[str, Any]:
    """Store non-BENIGN predictions once per recent matching alert window.

    A duplicate is the same attack class, source IP, and destination IP seen in
    the previous configured window. The whole batch uses one transaction: a
    real insert failure rolls back the batch rather than returning partial data.
    """
    if not isinstance(dedup_window_seconds, int) or dedup_window_seconds <= 0:
        raise ThreatPersistenceError("Threat deduplication window must be a positive number of seconds.")
    malicious = [prediction for prediction in predictions if prediction.get("classification") != "BENIGN"]
    records = [_validated_record(prediction) for prediction in malicious]
    if not records:
        return {"stored_threat_count": 0, "duplicate_suppressed_count": 0, "threat_ids": []}

    cutoff = datetime.now() - timedelta(seconds=dedup_window_seconds)
    stored_ids: list[int] = []
    stored_events: list[tuple[str, str]] = []
    duplicate_suppressed_count = 0
    try:
        with database_cursor() as (_connection, cursor):
            for attack_type, source_ip, destination_ip, severity, confidence, description in records:
                cursor.execute(
                    "SELECT threat_id FROM threats "
                    "WHERE attack_type = %s AND source_ip = %s AND destination_ip = %s "
                    "AND detected_at >= %s ORDER BY detected_at DESC LIMIT 1",
                    (attack_type, source_ip, destination_ip, cutoff),
                )
                if cursor.fetchone():
                    duplicate_suppressed_count += 1
                    continue
                cursor.execute(
                    "INSERT INTO threats "
                    "(traffic_id, attack_type, source_ip, destination_ip, severity, confidence_score, status, description) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (None, attack_type, source_ip, destination_ip, severity, confidence, "New", description),
                )
                stored_ids.append(cursor.lastrowid)
                stored_events.append((attack_type, severity))
    except Error as error:
        raise ThreatPersistenceError("AI threats could not be stored in the database.") from error

    for threat_id, (attack_type, severity) in zip(stored_ids, stored_events):
        # A record exists only when the deduplication check allowed it.
        log_security_event("THREAT_DETECTED", "AI Detection", f"AI-NIDS persisted {attack_type} threat alert #{threat_id}.", severity)

    return {
        "stored_threat_count": len(stored_ids),
        "duplicate_suppressed_count": duplicate_suppressed_count,
        "threat_ids": stored_ids,
    }
