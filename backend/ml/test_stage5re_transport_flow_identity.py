"""Stage 5R-E transport-flow identity regression; no capture or database use."""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from services.feature_schema import RUNTIME_FEATURE_COLUMNS  # noqa: E402
from services.flow_aggregator import BidirectionalFlowAggregator  # noqa: E402
from services.tshark_service import TSharkService  # noqa: E402


def packet(timestamp, source, destination, source_port, destination_port, transport, display, *, fin=False):
    return {
        "timestamp": timestamp,
        "source_ip": source,
        "destination_ip": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        # Production packets have this stable value from ip.proto/ipv6.nxt.
        "transport_protocol": transport,
        # Deliberately different: this must not affect aggregation identity.
        "protocol": display,
        "payload_length": 20,
        "tcp_fin": fin,
    }


def aggregate(records):
    aggregator = BidirectionalFlowAggregator(timeout_seconds=30)
    completed = []
    for record in records:
        completed.extend(aggregator.add_packet(record))
    completed.extend(aggregator.finalize_all())
    return completed


def main() -> None:
    forward = ("192.0.2.10", "198.51.100.20", 50000, 8000)
    reverse = (forward[1], forward[0], forward[3], forward[2])
    http_flow = aggregate([
        packet(1, *forward, "TCP", "TCP"),
        packet(2, *forward, "TCP", "HTTP"),
        packet(3, *reverse, "TCP", "TCP"),
    ])
    tls_flow = aggregate([
        packet(1, *forward, "TCP", "TCP"),
        packet(2, *forward, "TCP", "TLS"),
        packet(3, *reverse, "TCP", "TCP"),
    ])
    dns_flow = aggregate([
        packet(1, *forward, "UDP", "UDP"),
        packet(2, *forward, "UDP", "DNS"),
        packet(3, *reverse, "UDP", "UDP"),
    ])
    separate_transport = aggregate([
        packet(1, *forward, "TCP", "HTTP"),
        packet(2, *forward, "UDP", "DNS"),
    ])
    separate_ports = aggregate([
        packet(1, *forward, "TCP", "HTTP"),
        packet(2, forward[0], forward[1], 50001, 8000, "TCP", "HTTP"),
    ])
    fin_aggregator = BidirectionalFlowAggregator(timeout_seconds=30)
    fin_first = fin_aggregator.add_packet(packet(1, *forward, "TCP", "TLS", fin=True))
    fin_second = fin_aggregator.add_packet(packet(2, *reverse, "TCP", "TCP", fin=True))
    eof_aggregator = BidirectionalFlowAggregator(timeout_seconds=30)
    eof_aggregator.add_packet(packet(1, *forward, "UDP", "DNS"))
    eof_flows = eof_aggregator.finalize_all()
    parser_line = "1\t1\t\t\t192.0.2.10\t\t198.51.100.20\t\t6\t\tHTTP\t50000\t\t8000\t\t60\t20\t\t0"
    parsed = TSharkService._packet_from_line(parser_line)
    flow = http_flow[0]
    result = {
        "parser_separates_transport_from_display": parsed is not None and parsed["protocol"] == "TCP" and parsed["display_protocol"] == "HTTP",
        "tcp_display_tcp_http_is_one_flow": len(http_flow) == 1 and http_flow[0]["protocol"] == "TCP",
        "tcp_display_tcp_tls_is_one_flow": len(tls_flow) == 1 and tls_flow[0]["protocol"] == "TCP",
        "udp_display_udp_dns_is_one_flow": len(dns_flow) == 1 and dns_flow[0]["protocol"] == "UDP",
        "reverse_direction_matches_same_flow": len(http_flow) == 1 and flow["total_forward_packets"] == 2 and flow["total_backward_packets"] == 1,
        "different_transport_protocols_are_separate": len(separate_transport) == 2,
        "different_port_tuples_are_separate": len(separate_ports) == 2,
        "first_destination_port_is_preserved": flow["destination_port"] == 8000,
        "exact_20_feature_contract_is_present": list(RUNTIME_FEATURE_COLUMNS) == [key for key in RUNTIME_FEATURE_COLUMNS] and all(name in flow for name in RUNTIME_FEATURE_COLUMNS),
        "feature_values_are_finite": all(isinstance(flow[name], (int, float)) and math.isfinite(flow[name]) for name in RUNTIME_FEATURE_COLUMNS),
        "tcp_fin_finalises_after_both_directions": not fin_first and len(fin_second) == 1 and fin_aggregator.active_flow_count == 0,
        "eof_finalisation_is_preserved": len(eof_flows) == 1 and eof_aggregator.active_flow_count == 0,
    }
    result["passed"] = all(result.values())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
