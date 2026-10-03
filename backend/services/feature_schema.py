"""Single Stage 4 feature contract shared by preprocessing and inference."""
from __future__ import annotations

FEATURE_SCHEMA_VERSION = "1.0"
CANONICAL_TIME_UNIT = "seconds"
FLOW_TIMEOUT_SECONDS = 120
LABEL_COLUMN = "Label"
CLASS_MAPPING = {
    "BENIGN": 0,
    "DDoS": 1,
    "FTP-Patator": 2,
    "PortScan": 3,
    "SSH-Patator": 4,
}

# (CIC-IDS2017 column, AI-NIDS runtime field, conversion applied to training data)
FEATURE_CONTRACT = (
    ("Destination Port", "destination_port", None),
    ("Flow Duration", "flow_duration", "microseconds_to_seconds"),
    ("Total Fwd Packets", "total_forward_packets", None),
    ("Total Backward Packets", "total_backward_packets", None),
    ("Total Length of Fwd Packets", "total_forward_bytes", None),
    ("Total Length of Bwd Packets", "total_backward_bytes", None),
    ("Fwd Packet Length Mean", "forward_packet_length_mean", None),
    ("Fwd Packet Length Std", "forward_packet_length_std", None),
    ("Fwd Packet Length Max", "forward_packet_length_max", None),
    ("Fwd Packet Length Min", "forward_packet_length_min", None),
    ("Bwd Packet Length Mean", "backward_packet_length_mean", None),
    ("Bwd Packet Length Std", "backward_packet_length_std", None),
    ("Bwd Packet Length Max", "backward_packet_length_max", None),
    ("Bwd Packet Length Min", "backward_packet_length_min", None),
    ("Flow Bytes/s", "flow_bytes_per_second", None),
    ("Flow Packets/s", "flow_packets_per_second", None),
    ("Flow IAT Mean", "flow_iat_mean", "microseconds_to_seconds"),
    ("Flow IAT Std", "flow_iat_std", "microseconds_to_seconds"),
    ("Flow IAT Max", "flow_iat_max", "microseconds_to_seconds"),
    ("Flow IAT Min", "flow_iat_min", "microseconds_to_seconds"),
)

CIC_FEATURE_COLUMNS = [item[0] for item in FEATURE_CONTRACT]
RUNTIME_FEATURE_COLUMNS = [item[1] for item in FEATURE_CONTRACT]
TIMING_COLUMNS = [item[0] for item in FEATURE_CONTRACT if item[2] == "microseconds_to_seconds"]
