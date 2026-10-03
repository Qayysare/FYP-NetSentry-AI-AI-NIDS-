"""Read-only Stage 5L-C validation of held-out AI-NIDS threat classes.

This FYP evidence utility deliberately uses only the saved held-out test split.
It does not import Flask routes, start TShark, generate traffic, or persist
predictions.  It demonstrates existing model output; it does not alter labels
or force classifications.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from ml.predictor import FlowPredictor  # noqa: E402
from services.feature_schema import LABEL_COLUMN, RUNTIME_FEATURE_COLUMNS  # noqa: E402
from services.threat_priority import assess_threat  # noqa: E402


TEST_DATA_PATH = PROJECT_ROOT / "datasets" / "processed" / "test.csv"
MODEL_PATH = PROJECT_ROOT / "backend" / "ml" / "models" / "intrusion_model.joblib"
CLASS_ORDER = ("BENIGN", "PortScan", "DDoS", "SSH-Patator", "FTP-Patator")
FIXED_SAMPLE_COUNT = 5
DIVIDER = "=" * 60
SUBDIVIDER = "-" * 60


def confidence_percent(prediction: dict) -> str:
    """Format the existing predictor confidence without changing its value."""
    return f"{float(prediction['confidence']) * 100:.2f}%"


def feature_records(rows: pd.DataFrame) -> list[dict]:
    """Convert held-out rows using the shared runtime feature order."""
    return rows[RUNTIME_FEATURE_COLUMNS].to_dict("records")


def first_correct_representative(
    class_rows: pd.DataFrame, expected_label: str, predictor: FlowPredictor
) -> tuple[dict | None, int]:
    """Return the first correctly predicted held-out row in its stored order."""
    for examined, (_, row) in enumerate(class_rows.iterrows(), start=1):
        prediction = predictor.predict_flow(
            row[RUNTIME_FEATURE_COLUMNS].to_dict()
        )
        if prediction["classification"] == expected_label:
            return prediction, examined
    return None, len(class_rows)


def print_representative(expected_label: str, prediction: dict | None, examined: int) -> bool:
    """Print one transparent, correctly predicted presentation example."""
    print(f"CLASS: {expected_label}")
    print()
    print(f"Rows examined before representative: {examined}")
    if prediction is None:
        print("RESULT: FAIL — no correctly predicted held-out representative was found.")
        print(SUBDIVIDER)
        return False

    policy = assess_threat(prediction["classification"], prediction["confidence"])
    print(f"Expected: {expected_label}")
    print(f"Predicted: {prediction['classification']}")
    print(f"Confidence: {confidence_percent(prediction)}")
    print(f"Severity: {policy['severity']}")
    print(f"Priority: {policy['priority']}")
    print(f"Recommended Action: {policy['recommended_action']}")
    print("RESULT: PASS")
    print(SUBDIVIDER)
    return True


def print_fixed_samples(expected_label: str, class_rows: pd.DataFrame, predictor: FlowPredictor) -> tuple[int, int]:
    """Show the first five rows without selecting them by prediction outcome."""
    samples = class_rows.head(FIXED_SAMPLE_COUNT)
    predictions = predictor.predict_flows(feature_records(samples))
    print(f"CLASS: {expected_label}")
    print("Sample | Expected | Predicted | Confidence | Correct")
    correct = 0
    for index, prediction in enumerate(predictions, start=1):
        is_correct = prediction["classification"] == expected_label
        correct += int(is_correct)
        result = "YES" if is_correct else "NO"
        print(
            f"{index:<6} | {expected_label:<12} | {prediction['classification']:<12} | "
            f"{confidence_percent(prediction):>9} | {result}"
        )
    print(f"Fixed five-sample demonstration result: {correct} / {len(samples)}")
    print(SUBDIVIDER)
    return correct, len(samples)


def load_held_out_data() -> pd.DataFrame:
    """Load and validate only the saved held-out split needed for this check."""
    if not TEST_DATA_PATH.is_file():
        raise FileNotFoundError(f"Held-out test set was not found: {TEST_DATA_PATH}")
    data = pd.read_csv(TEST_DATA_PATH)
    required_columns = [*RUNTIME_FEATURE_COLUMNS, LABEL_COLUMN]
    missing = [column for column in required_columns if column not in data.columns]
    if missing:
        raise ValueError(f"Held-out test set is missing required columns: {missing}")
    missing_labels = [label for label in CLASS_ORDER if label not in set(data[LABEL_COLUMN])]
    if missing_labels:
        raise ValueError(f"Held-out test set is missing supported labels: {missing_labels}")
    return data


def main() -> None:
    data = load_held_out_data()
    predictor = FlowPredictor(model_path=MODEL_PATH)
    if predictor.feature_order != RUNTIME_FEATURE_COLUMNS or len(predictor.feature_order) != 20:
        raise RuntimeError("The saved predictor does not match the shared 20-feature contract.")

    print(DIVIDER)
    print("STAGE 5L-C - CONTROLLED AI THREAT CLASSIFICATION VALIDATION")
    print(DIVIDER)
    print("Dataset: datasets/processed/test.csv")
    print("Dataset type: HELD-OUT TEST SET")
    print("Model: backend/ml/models/intrusion_model.joblib")
    print("Prediction pipeline: FlowPredictor")
    print(f"Feature count: {len(predictor.feature_order)}")
    print(SUBDIVIDER)
    print("REPRESENTATIVE CLASSIFICATION RESULTS")
    print(SUBDIVIDER)

    representative_results: dict[str, bool] = {}
    class_rows_by_label: dict[str, pd.DataFrame] = {}
    for label in CLASS_ORDER:
        class_rows = data.loc[data[LABEL_COLUMN] == label]
        class_rows_by_label[label] = class_rows
        prediction, examined = first_correct_representative(class_rows, label, predictor)
        representative_results[label] = print_representative(label, prediction, examined)

    print(DIVIDER)
    print("FIXED FIRST-5 HELD-OUT SAMPLE CHECK")
    print(DIVIDER)
    fixed_results: dict[str, tuple[int, int]] = {}
    for label in CLASS_ORDER:
        fixed_results[label] = print_fixed_samples(label, class_rows_by_label[label], predictor)

    demonstrated = sum(representative_results.values())
    print(DIVIDER)
    print("SUMMARY")
    print(DIVIDER)
    print(f"Representative classes demonstrated: {demonstrated} / {len(CLASS_ORDER)}")
    for label in CLASS_ORDER:
        print(f"{label}: {'PASS' if representative_results[label] else 'FAIL'}")
    print("Model: Existing Random Forest")
    print("Model retrained: NO")
    print("Dataset modified: NO")
    print("Database modified: NO")
    print("Network traffic generated: NO")
    print("TShark started: NO")
    print("Threat persistence called: NO")
    print(f"FINAL STATUS: {'PASS' if demonstrated == len(CLASS_ORDER) else 'NEEDS REVIEW'}")
    print(SUBDIVIDER)
    print("LIMITATION NOTE")
    print(
        "These results validate the trained model on held-out CIC-IDS2017 feature rows. "
        "They do not represent real-world detection accuracy and do not replace live-network validation."
    )
    print("SSH-Patator is the weakest supported class in the saved held-out evaluation artifacts.")


if __name__ == "__main__":
    main()
