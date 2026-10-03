"""Read-only Stage 5R-D feature compatibility diagnostic.

This utility never starts capture, writes to the database, persists threats, or
changes the model.  It profiles the processed training data and can compare a
manually exported completed-flow JSON object against that profile.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
import sys

sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from ml.predictor import FlowPredictor  # noqa: E402
from services.feature_schema import LABEL_COLUMN, RUNTIME_FEATURE_COLUMNS  # noqa: E402


def training_profile(path: Path) -> dict:
    """Return descriptive statistics for the immutable processed train CSV."""
    frame = pd.read_csv(path, usecols=RUNTIME_FEATURE_COLUMNS)
    profile = {}
    for feature in RUNTIME_FEATURE_COLUMNS:
        values = frame[feature]
        profile[feature] = {
            "dtype": str(values.dtype),
            "count": int(values.count()),
            "negative_count": int((values < 0).sum()),
            "zero_count": int((values == 0).sum()),
            "min": float(values.min()),
            "median": float(values.median()),
            "mean": float(values.mean()),
            "std": float(values.std()),
            "p95": float(values.quantile(0.95)),
            "p99": float(values.quantile(0.99)),
            "max": float(values.max()),
        }
    return profile


def _finite_number(value, feature: str) -> float:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{feature} must be a finite numeric value.")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{feature} must be numeric.") from error
    if not np.isfinite(number):
        raise ValueError(f"{feature} must be finite.")
    return number


def _normalise_vectors(raw_vectors) -> list[tuple[dict, dict]]:
    """Accept raw feature maps or the documented diagnostic snapshot wrapper."""
    vectors = raw_vectors if isinstance(raw_vectors, list) else [raw_vectors]
    normalised = []
    for index, item in enumerate(vectors):
        if not isinstance(item, dict):
            raise ValueError("The live snapshot JSON must be one object or a list of objects.")
        if "features" in item:
            features = item["features"]
            if not isinstance(features, dict):
                raise ValueError(f"Live vector {index} has an invalid features object.")
            declared_schema = item.get("feature_schema")
            if declared_schema is not None and declared_schema != RUNTIME_FEATURE_COLUMNS:
                raise ValueError(f"Live vector {index} does not declare the required 20-feature schema.")
            context = {key: value for key, value in item.items() if key not in {"features", "feature_schema"}}
        else:
            features, context = item, {}
        normalised.append((features, context))
    return normalised


def _distribution_flag(value: float, stats: dict) -> str:
    if value > stats["max"]:
        return "ABOVE TRAINING RANGE"
    if value < stats["min"]:
        return "BELOW TRAINING RANGE"
    if value > stats["p99"]:
        return "ABOVE P99"
    if value > stats["p95"]:
        return "HIGH BUT WITHIN TRAINING RANGE"
    if value < stats["median"]:
        return "LOW BUT WITHIN TRAINING RANGE"
    return "WITHIN TYPICAL RANGE"


def compare_live_vectors(raw_vectors, profile: dict) -> list[dict]:
    """Compare caller-supplied completed-flow vectors without capture access."""
    comparisons = []
    for index, (vector, context) in enumerate(_normalise_vectors(raw_vectors)):
        missing = [feature for feature in RUNTIME_FEATURE_COLUMNS if feature not in vector]
        if missing:
            raise ValueError(f"Live vector {index} is missing: {', '.join(missing)}")
        feature_rows = []
        for feature in RUNTIME_FEATURE_COLUMNS:
            value = _finite_number(vector[feature], feature)
            stats = profile[feature]
            feature_rows.append({"feature": feature, "live_value": value, **stats, "diagnostic_flag": _distribution_flag(value, stats)})
        comparisons.append({
            "vector_index": index,
            "context": context,
            "extra_fields": sorted(set(vector) - set(RUNTIME_FEATURE_COLUMNS)),
            "features": feature_rows,
        })
    return comparisons


def deterministic_sanity_check(path: Path) -> list[dict]:
    """Predict the first stored test row for each class; no rows are selected by outcome."""
    frame = pd.read_csv(path, usecols=[*RUNTIME_FEATURE_COLUMNS, LABEL_COLUMN])
    predictor = FlowPredictor()
    results = []
    for label in ("BENIGN", "PortScan", "DDoS", "SSH-Patator", "FTP-Patator"):
        rows = frame[frame[LABEL_COLUMN] == label]
        if rows.empty:
            raise ValueError(f"The held-out test set has no {label} row.")
        row = rows.iloc[0]
        prediction = predictor.predict_flow(row[RUNTIME_FEATURE_COLUMNS].to_dict())
        results.append({
            "ground_truth": label,
            "prediction": prediction["classification"],
            "confidence": prediction.get("confidence"),
            "correct": prediction["classification"] == label,
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only NetSentry AI feature diagnostic")
    parser.add_argument("--live-json", type=Path, help="Optional manually exported completed-flow JSON snapshot")
    parser.add_argument("--skip-sanity-check", action="store_true", help="Skip held-out model-contract predictions")
    arguments = parser.parse_args()

    train_path = PROJECT_ROOT / "datasets" / "processed" / "train.csv"
    test_path = PROJECT_ROOT / "datasets" / "processed" / "test.csv"
    profile = training_profile(train_path)
    result = {"training_profile": profile, "live_comparison": None, "held_out_sanity": None}
    if arguments.live_json:
        result["live_comparison"] = compare_live_vectors(json.loads(arguments.live_json.read_text(encoding="utf-8")), profile)
    if not arguments.skip_sanity_check:
        result["held_out_sanity"] = deterministic_sanity_check(test_path)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
