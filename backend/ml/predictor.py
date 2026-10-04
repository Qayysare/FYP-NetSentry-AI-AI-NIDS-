"""Runtime inference for completed Stage 4B flows.

This module deliberately has no Flask, database, or frontend dependency.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from services.feature_schema import CLASS_MAPPING, RUNTIME_FEATURE_COLUMNS


class PredictionInputError(ValueError):
    """Raised when a completed flow cannot safely be passed to the model."""


class FlowPredictor:
    """Load one validated model instance and predict completed flow records."""

    def __init__(self, model_path: Path | None = None, schema_path: Path | None = None, metadata_path: Path | None = None):
        project_root = Path(__file__).resolve().parents[2]
        self.model_path = model_path or project_root / "backend" / "ml" / "models" / "intrusion_model.joblib"
        self.schema_path = schema_path or Path(__file__).resolve().parent / "artifacts" / "feature_schema.json"
        self.metadata_path = metadata_path or project_root / "backend" / "ml" / "results" / "model_metadata.json"
        self.feature_order = self._load_and_validate_schema()
        self.model = self._load_and_validate_model()

    def _load_and_validate_schema(self) -> list[str]:
        if not self.schema_path.is_file():
            raise RuntimeError(f"Feature schema was not found: {self.schema_path}")
        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        feature_order = schema.get("runtime_feature_order")
        if feature_order != RUNTIME_FEATURE_COLUMNS or len(feature_order) != 20:
            raise RuntimeError("Feature schema does not match the shared 20-feature runtime contract.")
        if self.metadata_path.is_file():
            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            if metadata.get("feature_order") != feature_order:
                raise RuntimeError("Training metadata feature order does not match the feature schema.")
            if set(metadata.get("class_labels", [])) != set(CLASS_MAPPING):
                raise RuntimeError("Training metadata classes do not match the supported classes.")
        return feature_order

    def _load_and_validate_model(self):
        if not self.model_path.is_file():
            raise RuntimeError(f"Trained model was not found: {self.model_path}")
        model = joblib.load(self.model_path)
        model_features = list(getattr(model, "feature_names_in_", []))
        if model_features and model_features != self.feature_order:
            raise RuntimeError("Saved model feature order does not match the shared feature schema.")
        model_classes = set(str(item) for item in getattr(model, "classes_", []))
        if model_classes != set(CLASS_MAPPING):
            raise RuntimeError("Saved model classes do not match the supported classes.")
        if not hasattr(model, "predict"):
            raise RuntimeError("Saved model does not support prediction.")
        return model

    def _feature_frame(self, flow: dict[str, Any]) -> pd.DataFrame:
        if not isinstance(flow, dict):
            raise PredictionInputError("A completed flow must be provided as a dictionary.")
        values = []
        for feature in self.feature_order:
            if feature not in flow:
                raise PredictionInputError(f"Completed flow is missing required feature: {feature}")
            value = flow[feature]
            if isinstance(value, bool) or value is None:
                raise PredictionInputError(f"Feature {feature} must be a finite numeric value.")
            try:
                numeric_value = float(value)
            except (TypeError, ValueError) as error:
                raise PredictionInputError(f"Feature {feature} must be numeric.") from error
            if not np.isfinite(numeric_value):
                raise PredictionInputError(f"Feature {feature} must not be NaN or infinity.")
            values.append(numeric_value)
        return pd.DataFrame([values], columns=self.feature_order)

    @staticmethod
    def _metadata(flow: dict[str, Any]) -> dict[str, Any]:
        keys = ("source_ip", "destination_ip", "source_port", "destination_port", "protocol")
        return {key: flow.get(key) for key in keys}

    def _result(self, flow: dict[str, Any], frame: pd.DataFrame, prediction: str | None = None, probability_row=None) -> dict[str, Any]:
        classification = str(prediction if prediction is not None else self.model.predict(frame)[0])
        result = {**self._metadata(flow), "classification": classification}
        if hasattr(self.model, "predict_proba"):
            probabilities = probability_row if probability_row is not None else self.model.predict_proba(frame)[0]
            class_index = list(self.model.classes_).index(classification)
            result["confidence"] = float(probabilities[class_index])
        return result

    def predict_flow(self, flow: dict[str, Any]) -> dict[str, Any]:
        """Classify one completed flow and return its metadata, class, and confidence."""
        frame = self._feature_frame(flow)
        return self._result(flow, frame)

    def predict_flows(self, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Classify a batch without reloading the model."""
        if not isinstance(flows, list):
            raise PredictionInputError("Flows must be provided as a list.")
        if not flows:
            return []
        frames = []
        for index, flow in enumerate(flows):
            try:
                frames.append(self._feature_frame(flow))
            except PredictionInputError as error:
                raise PredictionInputError(f"Invalid flow at batch index {index}: {error}") from error
        combined = pd.concat(frames, ignore_index=True)
        predictions = self.model.predict(combined)
        probabilities = self.model.predict_proba(combined) if hasattr(self.model, "predict_proba") else [None] * len(flows)
        return [
            self._result(flow, combined.iloc[[index]], prediction, probabilities[index])
            for index, (flow, prediction) in enumerate(zip(flows, predictions))
        ]
