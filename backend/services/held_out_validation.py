"""Read-only held-out CIC-IDS2017 validation helpers for FYP evidence."""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from services.feature_schema import LABEL_COLUMN, RUNTIME_FEATURE_COLUMNS
from services.threat_priority import assess_threat


CLASS_ORDER = ("BENIGN", "PortScan", "DDoS", "SSH-Patator", "FTP-Patator")
FIXED_SAMPLE_COUNT = 5
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TEST_DATA_PATH = PROJECT_ROOT / "datasets" / "processed" / "test.csv"


class HeldOutValidationError(RuntimeError):
    """Raised when the saved held-out split cannot meet the shared contract."""


def load_held_out_test_data(path: Path = DEFAULT_TEST_DATA_PATH) -> pd.DataFrame:
    """Read and validate the existing held-out split without changing it."""
    if not path.is_file():
        raise HeldOutValidationError(f"Held-out test set was not found: {path}")
    data = pd.read_csv(path)
    required_columns = [*RUNTIME_FEATURE_COLUMNS, LABEL_COLUMN]
    missing = [column for column in required_columns if column not in data.columns]
    if missing:
        raise HeldOutValidationError(f"Held-out test set is missing required columns: {missing}")
    missing_labels = [label for label in CLASS_ORDER if label not in set(data[LABEL_COLUMN])]
    if missing_labels:
        raise HeldOutValidationError(f"Held-out test set is missing supported labels: {missing_labels}")
    return data


def _first_correct_representative(class_rows: pd.DataFrame, expected_label: str, predictor) -> tuple[dict | None, int]:
    """Select the first correctly predicted row in the saved test-file order."""
    for examined, (_, row) in enumerate(class_rows.iterrows(), start=1):
        prediction = predictor.predict_flow(row[RUNTIME_FEATURE_COLUMNS].to_dict())
        if prediction["classification"] == expected_label:
            return prediction, examined
    return None, len(class_rows)


def build_validation_summary(predictor, data: pd.DataFrame | None = None) -> dict:
    """Build a read-only representative and fixed-sample validation summary."""
    data = load_held_out_test_data() if data is None else data
    if list(predictor.feature_order) != RUNTIME_FEATURE_COLUMNS or len(predictor.feature_order) != 20:
        raise HeldOutValidationError("The predictor does not match the shared 20-feature contract.")

    results = []
    for expected_label in CLASS_ORDER:
        class_rows = data.loc[data[LABEL_COLUMN] == expected_label]
        representative, rows_examined = _first_correct_representative(class_rows, expected_label, predictor)
        fixed_rows = class_rows.head(FIXED_SAMPLE_COUNT)
        fixed_predictions = predictor.predict_flows(fixed_rows[RUNTIME_FEATURE_COLUMNS].to_dict("records"))
        fixed_correct = sum(
            prediction["classification"] == expected_label for prediction in fixed_predictions
        )

        result = {
            "class_name": expected_label,
            "representative_pass": representative is not None,
            "rows_examined": rows_examined,
            "fixed_sample": {
                "correct_count": fixed_correct,
                "sample_count": len(fixed_predictions),
            },
        }
        if representative is not None:
            policy = assess_threat(
                representative["classification"], representative["confidence"]
            )
            result.update({
                "expected_label": expected_label,
                "predicted_label": representative["classification"],
                "confidence": float(representative["confidence"]),
                "severity": policy["severity"],
                "priority": policy["priority"],
                "recommended_action": policy["recommended_action"],
            })
        results.append(result)

    return {
        "source": "Held-out CIC-IDS2017 test set",
        "feature_count": len(RUNTIME_FEATURE_COLUMNS),
        "classes": results,
    }
