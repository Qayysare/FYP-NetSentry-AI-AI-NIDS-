"""Transparent policy rules for operational treatment of AI threat classes.

The model predicts only a traffic classification and a confidence probability.
This module separately assigns severity and priority, so the policy can later be
reused by PCAP, live-capture, database, and dashboard components.
"""
from __future__ import annotations

import math
from typing import Any


class ThreatPriorityError(ValueError):
    """Raised when a model result cannot be evaluated by the policy."""


# One central policy definition for this undergraduate project.
THREAT_POLICY = {
    "BENIGN": {
        "severity": "Informational",
        "priority": "Monitor",
        "recommended_action": "No immediate action",
    },
    "PortScan": {
        "severity": "Medium",
        "priority": "Review",
        "recommended_action": "Review the related source and destination activity",
    },
    "FTP-Patator": {
        "severity": "High",
        "priority": "Investigate",
        "recommended_action": "Investigate possible FTP authentication abuse",
    },
    "SSH-Patator": {
        "severity": "High",
        "priority": "Investigate",
        "recommended_action": "Investigate possible SSH authentication abuse",
    },
    "DDoS": {
        "severity": "Critical",
        "priority": "Immediate Attention",
        "recommended_action": "Investigate immediately and verify service impact",
    },
}

# Confidence is a model probability and not a severity prediction.
HIGH_CONFIDENCE_THRESHOLD = 0.85
MEDIUM_CONFIDENCE_THRESHOLD = 0.60


def confidence_band(confidence: float) -> str:
    """Return a documented confidence band for a validated probability."""
    if confidence >= HIGH_CONFIDENCE_THRESHOLD:
        return "High"
    if confidence >= MEDIUM_CONFIDENCE_THRESHOLD:
        return "Medium"
    return "Low"


def assess_threat(classification: str, confidence: Any, flow: dict | None = None) -> dict[str, str]:
    """Apply the rule policy to one model result without modifying the flow.

    ``flow`` is accepted for future bounded context rules, but no unsupported
    traffic-impact assumption is made in this first version.
    """
    if classification not in THREAT_POLICY:
        raise ThreatPriorityError("The AI classification is not supported by the threat policy.")
    if isinstance(confidence, bool):
        raise ThreatPriorityError("Model confidence must be a probability from 0.0 to 1.0.")
    try:
        probability = float(confidence)
    except (TypeError, ValueError) as error:
        raise ThreatPriorityError("Model confidence must be a probability from 0.0 to 1.0.") from error
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ThreatPriorityError("Model confidence must be a probability from 0.0 to 1.0.")

    policy = THREAT_POLICY[classification]
    band = confidence_band(probability)
    if classification == "BENIGN":
        reason = f"Traffic classified as benign with {band.lower()} model confidence."
    elif band == "High":
        reason = f"{classification} classification with high model confidence."
    else:
        reason = (
            f"{classification} classification with {band.lower()} model confidence; "
            "confirm it using supporting network evidence."
        )

    # Base severity and priority come from the policy mapping, not probability.
    # Confidence only qualifies the investigation guidance in this version.
    return {
        "severity": policy["severity"],
        "priority": policy["priority"],
        "recommended_action": policy["recommended_action"],
        "reason": reason,
        "confidence_band": band,
    }
