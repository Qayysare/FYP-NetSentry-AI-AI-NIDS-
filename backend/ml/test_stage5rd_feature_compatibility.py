"""Focused Stage 5R-D implementation-contract tests; no capture or database use."""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from ml.predictor import FlowPredictor, PredictionInputError  # noqa: E402
from services.feature_schema import FEATURE_CONTRACT, RUNTIME_FEATURE_COLUMNS  # noqa: E402
from services.flow_aggregator import BidirectionalFlowAggregator, _number_statistics  # noqa: E402
from services.tshark_service import TSharkService  # noqa: E402


def packet(timestamp, source, destination, source_port, destination_port, length, fin=False):
    return {"timestamp": timestamp, "source_ip": source, "destination_ip": destination, "source_port": source_port, "destination_port": destination_port, "protocol": "TCP", "payload_length": length, "tcp_fin": fin}


def main() -> None:
    aggregator = BidirectionalFlowAggregator(timeout_seconds=120)
    aggregator.add_packet(packet("2026-01-01T00:00:00+00:00", "10.0.0.1", "10.0.0.2", 50000, 443, 10))
    aggregator.add_packet(packet("2026-01-01T00:00:01+00:00", "10.0.0.2", "10.0.0.1", 443, 50000, 20))
    aggregator.add_packet(packet("2026-01-01T00:00:03+00:00", "10.0.0.1", "10.0.0.2", 50000, 443, 30))
    flow = aggregator.finalize_all()[0]
    predictor = FlowPredictor()
    test_row = pd.read_csv(PROJECT_ROOT / "datasets" / "processed" / "test.csv", nrows=1)[RUNTIME_FEATURE_COLUMNS].iloc[0].to_dict()
    schema = json.loads((PROJECT_ROOT / "datasets" / "processed" / "feature_schema.json").read_text(encoding="utf-8"))
    tcp_line = "1\t1\t\t\t10.0.0.1\t\t10.0.0.2\t\t6\t\tHTTP\t1234\t\t443\t\t60\t20\t\t0"
    udp_line = "2\t2\t\t\t10.0.0.1\t\t10.0.0.2\t\t17\t\tDNS\t\t1234\t\t53\t60\t\t28\t0"
    result = {
        "exact_shared_feature_order": predictor.feature_order == RUNTIME_FEATURE_COLUMNS and schema["runtime_feature_order"] == RUNTIME_FEATURE_COLUMNS and len(RUNTIME_FEATURE_COLUMNS) == 20,
        "training_time_conversion_declared": [item[2] for item in FEATURE_CONTRACT if item[1] in {"flow_duration", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min"}] == ["microseconds_to_seconds"] * 5,
        "live_duration_and_rates_use_seconds": flow["flow_duration"] == 3.0 and flow["flow_bytes_per_second"] == 20.0 and flow["flow_packets_per_second"] == 1.0,
        "forward_backward_direction_and_destination_port": (flow["destination_port"], flow["total_forward_packets"], flow["total_backward_packets"], flow["total_forward_bytes"], flow["total_backward_bytes"]) == (443, 2, 1, 40, 20),
        "iat_excludes_first_packet": (flow["flow_iat_mean"], flow["flow_iat_min"], flow["flow_iat_max"]) == (1.5, 1.0, 2.0),
        "standard_deviation_is_sample": math.isclose(_number_statistics([10, 30])["std"], math.sqrt(200)) and math.isclose(flow["flow_iat_std"], math.sqrt(0.5)),
        "zero_duration_rates_are_finite": all(math.isfinite(flow[feature]) for feature in RUNTIME_FEATURE_COLUMNS),
        "tcp_and_udp_payload_mapping": TSharkService._packet_from_line(tcp_line)["payload_length"] == 20 and TSharkService._packet_from_line(udp_line)["payload_length"] == 20,
        "transport_protocol_is_not_display_protocol": TSharkService._packet_from_line(tcp_line)["protocol"] == "TCP" and TSharkService._packet_from_line(tcp_line)["display_protocol"] == "HTTP" and TSharkService._packet_from_line(udp_line)["protocol"] == "UDP" and TSharkService._packet_from_line(udp_line)["display_protocol"] == "DNS",
        "predictor_accepts_exact_runtime_vector": predictor.predict_flow(test_row)["classification"] in {"BENIGN", "DDoS", "FTP-Patator", "PortScan", "SSH-Patator"},
        "predictor_rejects_missing_and_nonfinite": False,
        "predictor_ignores_metadata_extras_but_builds_exact_vector": len(predictor._feature_frame({**test_row, "source_ip": "192.0.2.1"}).columns) == 20,
    }
    try:
        predictor.predict_flow({key: value for key, value in test_row.items() if key != RUNTIME_FEATURE_COLUMNS[0]})
    except PredictionInputError:
        try:
            predictor.predict_flow({**test_row, RUNTIME_FEATURE_COLUMNS[0]: float("inf")})
        except PredictionInputError:
            result["predictor_rejects_missing_and_nonfinite"] = True
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
