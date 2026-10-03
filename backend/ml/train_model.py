"""Stage 4E: train, compare, select, and persist one AI-NIDS classifier."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from sklearn import __version__ as sklearn_version  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    ConfusionMatrixDisplay, accuracy_score, classification_report, confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedGroupKFold  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.tree import DecisionTreeClassifier  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from services.feature_schema import CLASS_MAPPING, LABEL_COLUMN, RUNTIME_FEATURE_COLUMNS  # noqa: E402

DATA_DIRECTORY = PROJECT_ROOT / "datasets" / "processed"
MODEL_DIRECTORY = PROJECT_ROOT / "backend" / "ml" / "models"
RESULTS_DIRECTORY = PROJECT_ROOT / "backend" / "ml" / "results"
RANDOM_STATE = 42
VALIDATION_SPLITS = 5
LABEL_ORDER = ["BENIGN", "DDoS", "FTP-Patator", "PortScan", "SSH-Patator"]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_inputs() -> tuple[pd.DataFrame, pd.DataFrame, dict, dict, dict]:
    """Load the prepared split and reject any feature-contract mismatch."""
    train = pd.read_csv(DATA_DIRECTORY / "train.csv")
    test = pd.read_csv(DATA_DIRECTORY / "test.csv")
    schema = read_json(DATA_DIRECTORY / "feature_schema.json")
    class_mapping = read_json(DATA_DIRECTORY / "class_mapping.json")
    preprocessing_metadata = read_json(DATA_DIRECTORY / "preprocessing_metadata.json")

    if schema["runtime_feature_order"] != RUNTIME_FEATURE_COLUMNS:
        raise ValueError("Feature schema does not match the shared runtime contract.")
    for frame_name, frame in {"train": train, "test": test}.items():
        if list(frame.columns) != RUNTIME_FEATURE_COLUMNS + [LABEL_COLUMN]:
            raise ValueError(f"{frame_name}.csv does not have the required feature order.")
        if frame[RUNTIME_FEATURE_COLUMNS].isna().any().any():
            raise ValueError(f"{frame_name}.csv contains NaN feature values.")
        if not np.isfinite(frame[RUNTIME_FEATURE_COLUMNS].to_numpy()).all():
            raise ValueError(f"{frame_name}.csv contains infinite feature values.")
        if set(frame[LABEL_COLUMN].unique()) != set(LABEL_ORDER):
            raise ValueError(f"{frame_name}.csv does not contain the expected five classes.")
    if class_mapping != CLASS_MAPPING:
        raise ValueError("Class mapping does not match the shared runtime contract.")
    return train, test, schema, class_mapping, preprocessing_metadata


def metrics_for(y_true: pd.Series, y_pred: np.ndarray) -> tuple[dict, dict]:
    """Return the required overall and per-class metrics with a fixed label order."""
    macro = precision_recall_fscore_support(y_true, y_pred, labels=LABEL_ORDER, average="macro", zero_division=0)
    weighted = precision_recall_fscore_support(y_true, y_pred, labels=LABEL_ORDER, average="weighted", zero_division=0)
    report = classification_report(y_true, y_pred, labels=LABEL_ORDER, output_dict=True, zero_division=0)
    summary = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(macro[0]),
        "macro_recall": float(macro[1]),
        "macro_f1": float(macro[2]),
        "weighted_precision": float(weighted[0]),
        "weighted_recall": float(weighted[1]),
        "weighted_f1": float(weighted[2]),
    }
    return summary, report


def build_candidates() -> dict:
    """Small, explainable models appropriate for the undergraduate project."""
    return {
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced", random_state=RANDOM_STATE,
            max_depth=20, min_samples_leaf=5,
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=80, max_depth=24, min_samples_leaf=2,
            max_features="sqrt", class_weight="balanced", random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(
                class_weight="balanced", random_state=RANDOM_STATE,
                max_iter=300, solver="lbfgs",
            )),
        ]),
    }


def serializable_parameters(model) -> dict:
    """Keep model settings readable without serialising estimator objects."""
    parameters = {}
    for key, value in model.get_params(deep=True).items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            parameters[key] = value
        else:
            parameters[key] = repr(value)
    return parameters


def grouped_validation_split(features: pd.DataFrame, labels: pd.Series) -> tuple[np.ndarray, np.ndarray]:
    """Keep exact duplicate feature/label rows in one validation partition."""
    identities = pd.util.hash_pandas_object(pd.concat([features, labels], axis=1), index=False)
    splitter = StratifiedGroupKFold(n_splits=VALIDATION_SPLITS, shuffle=True, random_state=RANDOM_STATE)
    train_index, validation_index = next(splitter.split(features, labels, groups=identities))
    if set(identities.iloc[train_index]) & set(identities.iloc[validation_index]):
        raise ValueError("Exact rows overlap between training and validation data.")
    return train_index, validation_index


def save_confusion_matrix(y_true: pd.Series, y_pred: np.ndarray) -> None:
    matrix = confusion_matrix(y_true, y_pred, labels=LABEL_ORDER)
    pd.DataFrame(matrix, index=LABEL_ORDER, columns=LABEL_ORDER).to_csv(RESULTS_DIRECTORY / "confusion_matrix.csv")
    figure, axis = plt.subplots(figsize=(8, 6))
    ConfusionMatrixDisplay(matrix, display_labels=LABEL_ORDER).plot(ax=axis, colorbar=False, xticks_rotation=35)
    axis.set_title("AI-NIDS Final Test Confusion Matrix")
    figure.tight_layout()
    figure.savefig(RESULTS_DIRECTORY / "confusion_matrix.png", dpi=160)
    plt.close(figure)


def save_feature_importance(model) -> list[dict]:
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    else:
        classifier = model.named_steps["classifier"]
        importances = np.mean(np.abs(classifier.coef_), axis=0)
    rows = sorted(
        ({"feature": feature, "importance": float(importance)} for feature, importance in zip(RUNTIME_FEATURE_COLUMNS, importances)),
        key=lambda item: item["importance"], reverse=True,
    )
    pd.DataFrame(rows).to_csv(RESULTS_DIRECTORY / "feature_importance.csv", index=False)
    top = rows[:10]
    figure, axis = plt.subplots(figsize=(8, 5))
    axis.barh([row["feature"] for row in reversed(top)], [row["importance"] for row in reversed(top)], color="#2f81f7")
    axis.set_title("Top Feature Importance")
    axis.set_xlabel("Importance")
    figure.tight_layout()
    figure.savefig(RESULTS_DIRECTORY / "feature_importance.png", dpi=160)
    plt.close(figure)
    return rows


def main() -> None:
    MODEL_DIRECTORY.mkdir(parents=True, exist_ok=True)
    RESULTS_DIRECTORY.mkdir(parents=True, exist_ok=True)
    train, test, schema, class_mapping, preprocessing_metadata = validate_inputs()
    features, labels = train[RUNTIME_FEATURE_COLUMNS], train[LABEL_COLUMN]
    train_index, validation_index = grouped_validation_split(features, labels)
    x_fit, y_fit = features.iloc[train_index], labels.iloc[train_index]
    x_validation, y_validation = features.iloc[validation_index], labels.iloc[validation_index]

    comparison = []
    candidate_models = build_candidates()
    for name, model in candidate_models.items():
        start = time.perf_counter()
        model.fit(x_fit, y_fit)
        training_seconds = time.perf_counter() - start
        start = time.perf_counter()
        validation_predictions = model.predict(x_validation)
        prediction_seconds = time.perf_counter() - start
        summary, report = metrics_for(y_validation, validation_predictions)
        comparison.append({
            "model": name,
            **summary,
            "training_seconds": training_seconds,
            "validation_prediction_seconds": prediction_seconds,
            "validation_report": report,
            "parameters": serializable_parameters(model),
        })

    # Macro F1 is primary; weighted F1 breaks a tie without using test data.
    selected = max(comparison, key=lambda result: (result["macro_f1"], result["weighted_f1"]))
    selected_name = selected["model"]
    selected_model = candidate_models[selected_name]

    # This is the first and only final-test evaluation used for model selection.
    final_test_predictions = selected_model.predict(test[RUNTIME_FEATURE_COLUMNS])
    test_summary, test_report = metrics_for(test[LABEL_COLUMN], final_test_predictions)
    save_confusion_matrix(test[LABEL_COLUMN], final_test_predictions)
    importance_rows = save_feature_importance(selected_model)

    model_path = MODEL_DIRECTORY / "intrusion_model.joblib"
    joblib.dump(selected_model, model_path)
    reloaded_model = joblib.load(model_path)
    reload_predictions = reloaded_model.predict(x_validation.iloc[:10])
    reload_test_passed = bool(np.array_equal(reload_predictions, selected_model.predict(x_validation.iloc[:10])))

    comparison_csv = [{key: value for key, value in result.items() if key not in {"validation_report", "parameters"}} for result in comparison]
    pd.DataFrame(comparison_csv).to_csv(RESULTS_DIRECTORY / "model_comparison.csv", index=False)
    (RESULTS_DIRECTORY / "validation_reports.json").write_text(
        json.dumps({result["model"]: result["validation_report"] for result in comparison}, indent=2), encoding="utf-8"
    )
    (RESULTS_DIRECTORY / "classification_report.json").write_text(json.dumps(test_report, indent=2), encoding="utf-8")
    metadata = {
        "training_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "selected_model": selected_name,
        "selection_rule": "Highest validation macro F1; weighted F1 used only as a tie-breaker.",
        "selected_model_parameters": serializable_parameters(selected_model),
        "feature_order": RUNTIME_FEATURE_COLUMNS,
        "class_labels": LABEL_ORDER,
        "class_mapping": class_mapping,
        "sklearn_version": sklearn_version,
        "validation_metrics": {result["model"]: {key: value for key, value in result.items() if key not in {"validation_report", "parameters"}} for result in comparison},
        "final_test_metrics": test_summary,
        "preprocessing_metadata": preprocessing_metadata,
        "reload_test_passed": reload_test_passed,
        "model_trained_on_test_data": False,
    }
    (RESULTS_DIRECTORY / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps({
        "fit_rows": len(x_fit), "validation_rows": len(x_validation), "test_rows": len(test),
        "selected_model": selected_name, "validation_comparison": comparison_csv,
        "final_test_metrics": test_summary, "reload_test_passed": reload_test_passed,
        "top_feature_importance": importance_rows[:10],
    }, indent=2))


if __name__ == "__main__":
    main()
