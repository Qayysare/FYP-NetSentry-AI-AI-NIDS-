"""Bidirectional, time-bounded flow aggregation for the Stage 4 AI pipeline.

This module consumes the packet dictionaries already returned by
``TSharkService``.  Endpoint addresses are kept as metadata for later display;
they are deliberately not part of the machine-learning feature set.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from statistics import mean, stdev
from typing import Any


def _timestamp_seconds(value: Any) -> float | None:
    """Convert an ISO-8601 packet timestamp to Unix seconds, if available."""
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _number_statistics(values: list[float | int]) -> dict[str, float]:
    """Return sample statistics, matching CICFlowMeter's SummaryStatistics."""
    if not values:
        return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0}
    return {
        "mean": float(mean(values)),
        "std": float(stdev(values)) if len(values) > 1 else 0.0,
        "max": float(max(values)),
        "min": float(min(values)),
    }


class BidirectionalFlowAggregator:
    """Build flows where the first observed packet defines the forward side.

    Durations and IAT values are stored in **seconds**.  A flow is finalised
    once it has been inactive for ``timeout_seconds`` or when ``finalize_all``
    is called after a PCAP has been read.
    """

    def __init__(self, timeout_seconds: int, max_active_flows: int | None = None):
        if timeout_seconds <= 0:
            raise ValueError("Flow timeout must be greater than zero seconds.")
        if max_active_flows is not None and max_active_flows <= 0:
            raise ValueError("The active-flow limit must be greater than zero.")
        self.timeout_seconds = timeout_seconds
        self.max_active_flows = max_active_flows
        self._active_flows: dict[tuple, dict] = {}
        self.dropped_new_flow_packets = 0

    @property
    def active_flow_count(self) -> int:
        """Expose the bounded number of flows currently awaiting completion."""
        return len(self._active_flows)

    @staticmethod
    def _endpoint(packet: dict, prefix: str) -> tuple[str, int | None]:
        port = packet.get(f"{prefix}_port")
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            port = None
        return str(packet.get(f"{prefix}_ip")), port

    @classmethod
    def _transport_protocol(cls, packet: dict) -> str:
        """Return the stable transport identity carried by a parsed packet.

        TSharkService supplies ``protocol`` as TCP, UDP, or an IP protocol
        identifier. ``transport_protocol`` keeps direct/test packet input
        explicit when a separate display label is also present.
        """
        return str(packet.get("transport_protocol") or packet.get("protocol") or "IP-UNKNOWN").upper()

    @classmethod
    def _flow_key(cls, packet: dict) -> tuple | None:
        if not packet.get("source_ip") or not packet.get("destination_ip"):
            return None
        endpoint_a = cls._endpoint(packet, "source")
        endpoint_b = cls._endpoint(packet, "destination")
        # ``None`` ports are valid: ICMP and other packets do not use ports.
        ordered_endpoints = tuple(sorted((endpoint_a, endpoint_b), key=lambda item: (item[0], item[1] is None, item[1] or 0)))
        return (cls._transport_protocol(packet), *ordered_endpoints)

    @staticmethod
    def _new_flow(packet: dict, timestamp: float | None) -> dict:
        source_endpoint = BidirectionalFlowAggregator._endpoint(packet, "source")
        destination_endpoint = BidirectionalFlowAggregator._endpoint(packet, "destination")
        return {
            "source_ip": source_endpoint[0],
            "destination_ip": destination_endpoint[0],
            "source_port": source_endpoint[1],
            "destination_port": destination_endpoint[1],
            "source_mac": packet.get("source_mac"),
            "destination_mac": packet.get("destination_mac"),
            "protocol": BidirectionalFlowAggregator._transport_protocol(packet),
            "flow_start": timestamp,
            "flow_end": timestamp,
            "last_seen": timestamp,
            "timestamps": [],
            "forward_lengths": [],
            "backward_lengths": [],
            "forward_fin": False,
            "backward_fin": False,
        }

    def _finalize_inactive(self, current_timestamp: float | None) -> list[dict]:
        if current_timestamp is None:
            return []
        expired_keys = [
            key for key, flow in self._active_flows.items()
            if flow["last_seen"] is not None
            and current_timestamp >= flow["last_seen"]
            and current_timestamp - flow["last_seen"] >= self.timeout_seconds
        ]
        return [self._finalize(self._active_flows.pop(key)) for key in expired_keys]

    def finalize_expired(self, current_timestamp: float | None = None) -> list[dict]:
        """Finalise stale flows during an active capture without a new packet.

        PCAP processing normally advances time using incoming packet timestamps.
        Continuous monitoring also calls this method periodically using wall time
        so idle flows can become eligible for inference before capture stop.
        """
        timestamp = time.time() if current_timestamp is None else current_timestamp
        return self._finalize_inactive(timestamp)

    def add_packet(self, packet: dict) -> list[dict]:
        """Add one parsed packet and return flows closed by inactivity."""
        timestamp = _timestamp_seconds(packet.get("timestamp"))
        completed = self._finalize_inactive(timestamp)
        key = self._flow_key(packet)
        if key is None:
            return completed

        flow = self._active_flows.get(key)
        if flow is None:
            # Keep long-running sessions bounded. A new flow is ignored when
            # the configured active-flow limit is reached; existing flows are
            # never forced into premature AI inference merely to free space.
            if self.max_active_flows is not None and len(self._active_flows) >= self.max_active_flows:
                self.dropped_new_flow_packets += 1
                return completed
            flow = self._new_flow(packet, timestamp)
            self._active_flows[key] = flow

        is_forward = (
            packet.get("source_ip") == flow["source_ip"]
            and packet.get("destination_ip") == flow["destination_ip"]
            and packet.get("source_port") == flow["source_port"]
            and packet.get("destination_port") == flow["destination_port"]
        )
        try:
            # Stage 3 retains frame length for display. Stage 4 uses transport
            # payload length to match the CICFlowMeter byte feature definition.
            packet_length = max(0, int(packet.get("payload_length", packet.get("packet_length")) or 0))
        except (TypeError, ValueError):
            packet_length = 0
        (flow["forward_lengths"] if is_forward else flow["backward_lengths"]).append(packet_length)

        if timestamp is not None:
            flow["timestamps"].append(timestamp)
            flow["flow_start"] = timestamp if flow["flow_start"] is None else min(flow["flow_start"], timestamp)
            flow["flow_end"] = timestamp if flow["flow_end"] is None else max(flow["flow_end"], timestamp)
            flow["last_seen"] = timestamp if flow["last_seen"] is None else max(flow["last_seen"], timestamp)
        if flow["protocol"] == "TCP" and packet.get("tcp_fin"):
            if is_forward:
                flow["forward_fin"] = True
            else:
                flow["backward_fin"] = True
            # A normal TCP teardown has a FIN from both directions. Closing at
            # that point avoids treating a one-sided FIN as the full teardown.
            if flow["forward_fin"] and flow["backward_fin"]:
                completed.append(self._finalize(self._active_flows.pop(key)))
        return completed

    def finalize_all(self) -> list[dict]:
        """Finalise all remaining flows, used at the end of PCAP analysis."""
        completed = [self._finalize(flow) for flow in self._active_flows.values()]
        self._active_flows.clear()
        return completed

    @staticmethod
    def _finalize(flow: dict) -> dict:
        all_lengths = flow["forward_lengths"] + flow["backward_lengths"]
        timestamps = sorted(flow["timestamps"])
        iats = [later - earlier for earlier, later in zip(timestamps, timestamps[1:])]
        duration = max(0.0, (flow["flow_end"] or 0.0) - (flow["flow_start"] or 0.0)) if timestamps else 0.0
        length_stats = _number_statistics(all_lengths)
        forward_stats = _number_statistics(flow["forward_lengths"])
        backward_stats = _number_statistics(flow["backward_lengths"])
        iat_stats = _number_statistics(iats)
        total_bytes = sum(all_lengths)
        total_packets = len(all_lengths)

        return {
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],
            "source_port": flow["source_port"],
            "destination_port": flow["destination_port"],
            "source_mac": flow["source_mac"],
            "destination_mac": flow["destination_mac"],
            "protocol": flow["protocol"],
            "flow_start": datetime.fromtimestamp(flow["flow_start"], timezone.utc).isoformat() if flow["flow_start"] is not None else None,
            "flow_end": datetime.fromtimestamp(flow["flow_end"], timezone.utc).isoformat() if flow["flow_end"] is not None else None,
            "flow_duration": duration,
            "total_forward_packets": len(flow["forward_lengths"]),
            "total_backward_packets": len(flow["backward_lengths"]),
            "total_forward_bytes": sum(flow["forward_lengths"]),
            "total_backward_bytes": sum(flow["backward_lengths"]),
            "packet_length_mean": length_stats["mean"],
            "packet_length_std": length_stats["std"],
            "packet_length_max": length_stats["max"],
            "packet_length_min": length_stats["min"],
            "flow_bytes_per_second": total_bytes / duration if duration > 0 else 0.0,
            "flow_packets_per_second": total_packets / duration if duration > 0 else 0.0,
            "flow_iat_mean": iat_stats["mean"],
            "flow_iat_std": iat_stats["std"],
            "flow_iat_max": iat_stats["max"],
            "flow_iat_min": iat_stats["min"],
            "forward_packet_length_mean": forward_stats["mean"],
            "forward_packet_length_std": forward_stats["std"],
            "forward_packet_length_max": forward_stats["max"],
            "forward_packet_length_min": forward_stats["min"],
            "backward_packet_length_mean": backward_stats["mean"],
            "backward_packet_length_std": backward_stats["std"],
            "backward_packet_length_max": backward_stats["max"],
            "backward_packet_length_min": backward_stats["min"],
        }


def aggregate_bidirectional_flows(records: list[dict], timeout_seconds: int) -> list[dict]:
    """Aggregate parsed packets into completed bidirectional flow dictionaries."""
    aggregator = BidirectionalFlowAggregator(timeout_seconds)
    completed: list[dict] = []
    for record in records:
        completed.extend(aggregator.add_packet(record))
    completed.extend(aggregator.finalize_all())
    return completed
