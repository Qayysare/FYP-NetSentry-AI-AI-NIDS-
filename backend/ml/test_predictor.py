"""Repeatable Stage 4F local verification; it does not retrain or persist predictions."""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from ml.predictor import FlowPredictor, PredictionInputError  # noqa: E402
from services.feature_schema import FLOW_TIMEOUT_SECONDS, LABEL_COLUMN, RUNTIME_FEATURE_COLUMNS  # noqa: E402
from services.tshark_service import TSharkService  # noqa: E402


def main() -> None:
    predictor = FlowPredictor()
    test_data = pd.read_csv(PROJECT_ROOT / "datasets" / "processed" / "test.csv")
    labelled_sample = test_data.groupby(LABEL_COLUMN, group_keys=False).head(2)
    labelled_flows = labelled_sample[RUNTIME_FEATURE_COLUMNS].to_dict("records")
    labelled_predictions = predictor.predict_flows(labelled_flows)
    expected = labelled_sample[LABEL_COLUMN].tolist()
    matches = [prediction["classification"] == label for prediction, label in zip(labelled_predictions, expected)]

    valid_flow = labelled_flows[0]
    invalid_tests = {}
    for name, invalid_flow in {
        "missing_feature": {key: value for key, value in valid_flow.items() if key != RUNTIME_FEATURE_COLUMNS[0]},
        "nan": {**valid_flow, RUNTIME_FEATURE_COLUMNS[0]: float("nan")},
        "positive_infinity": {**valid_flow, RUNTIME_FEATURE_COLUMNS[0]: float("inf")},
        "negative_infinity": {**valid_flow, RUNTIME_FEATURE_COLUMNS[0]: float("-inf")},
        "wrong_type": {**valid_flow, RUNTIME_FEATURE_COLUMNS[0]: "not-a-number"},
    }.items():
        try:
            predictor.predict_flow(invalid_flow)
        except PredictionInputError as error:
            invalid_tests[name] = str(error)
        else:
            raise AssertionError(f"{name} was not rejected")

    demo_path = PROJECT_ROOT / "Wireshark" / "demo.pcapng"
    service = TSharkService(str(PROJECT_ROOT / "Wireshark" / "tshark.exe"))
    demo_packets = service.analyse_file(str(demo_path), 500)
    demo_flows = service.aggregate_bidirectional(demo_packets, FLOW_TIMEOUT_SECONDS)
    single_start = time.perf_counter()
    single_prediction = predictor.predict_flow(demo_flows[0])
    single_latency_ms = (time.perf_counter() - single_start) * 1000
    batch_start = time.perf_counter()
    demo_predictions = predictor.predict_flows(demo_flows)
    batch_latency_ms = (time.perf_counter() - batch_start) * 1000

    result = {
        "model_schema_compatible": True,
        "feature_count": len(predictor.feature_order),
        "supported_classes": sorted(str(item) for item in predictor.model.classes_),
        "held_out_sample_size": len(expected),
        "held_out_correct_predictions": sum(matches),
        "held_out_expected_labels": expected,
        "held_out_predicted_labels": [item["classification"] for item in labelled_predictions],
        "invalid_input_errors": invalid_tests,
        "demo_packet_count": len(demo_packets),
        "demo_flow_count": len(demo_flows),
        "demo_class_distribution": dict(Counter(item["classification"] for item in demo_predictions)),
        "demo_example_prediction": single_prediction,
        "single_flow_latency_ms": single_latency_ms,
        "batch_latency_ms": batch_latency_ms,
        "batch_flow_count": len(demo_flows),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
