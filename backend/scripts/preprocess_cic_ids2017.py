"""Create reproducible Stage 4D training and test CSVs without training a model."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from services.feature_schema import (  # noqa: E402
    CANONICAL_TIME_UNIT, CLASS_MAPPING, CIC_FEATURE_COLUMNS, FEATURE_CONTRACT,
    FEATURE_SCHEMA_VERSION, FLOW_TIMEOUT_SECONDS, LABEL_COLUMN,
    RUNTIME_FEATURE_COLUMNS, TIMING_COLUMNS,
)

SOURCE_FILES = (
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
)
RANDOM_STATE = 42
TEST_FRACTION = 0.20


def normalized_name(value: str) -> str:
    return value.strip().lstrip("\ufeff")


def read_selected_columns(path: Path) -> pd.DataFrame:
    """Read only the fixed contract columns while preserving source CSVs."""
    raw_headers = pd.read_csv(path, nrows=0).columns.tolist()
    raw_to_normalized = {raw: normalized_name(raw) for raw in raw_headers}
    needed = set(CIC_FEATURE_COLUMNS + [LABEL_COLUMN])
    missing = needed - set(raw_to_normalized.values())
    if missing:
        raise ValueError(f"{path.name} is missing required columns: {sorted(missing)}")
    selected_raw = [raw for raw, normalized in raw_to_normalized.items() if normalized in needed]
    frame = pd.read_csv(path, usecols=selected_raw, low_memory=False)
    frame = frame.rename(columns=raw_to_normalized)
    return frame[CIC_FEATURE_COLUMNS + [LABEL_COLUMN]]


def row_identity(frame: pd.DataFrame) -> pd.Series:
    """Stable identity groups exact rows so duplicates cannot cross the split."""
    return pd.util.hash_pandas_object(frame[RUNTIME_FEATURE_COLUMNS + [LABEL_COLUMN]], index=False)


def stratified_group_split(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split by label while keeping exact duplicate records in one partition."""
    test_groups = set()
    for label, group in frame.groupby(LABEL_COLUMN, sort=True):
        identities = group["_row_identity"].drop_duplicates()
        if len(identities) < 2:
            raise ValueError(f"{label} has too few unique rows for a stratified split.")
        selected = identities.sample(frac=TEST_FRACTION, random_state=RANDOM_STATE)
        test_groups.update(selected.tolist())
    test = frame[frame["_row_identity"].isin(test_groups)].copy()
    train = frame[~frame["_row_identity"].isin(test_groups)].copy()
    return train, test


def distribution(frame: pd.DataFrame) -> dict[str, int]:
    return {label: int(count) for label, count in frame[LABEL_COLUMN].value_counts().sort_index().items()}


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    source_directory = PROJECT_ROOT / "datasets" / "CIC-IDS2017"
    output_directory = PROJECT_ROOT / "datasets" / "processed"
    output_directory.mkdir(parents=True, exist_ok=True)

    source_paths = [source_directory / filename for filename in SOURCE_FILES]
    source_hashes_before = {path.name: file_hash(path) for path in source_paths}
    frames = [read_selected_columns(path) for path in source_paths]
    combined = pd.concat(frames, ignore_index=True)
    original_rows = len(combined)
    combined[LABEL_COLUMN] = combined[LABEL_COLUMN].astype(str).str.strip()
    found_labels = set(combined[LABEL_COLUMN].unique())
    expected_labels = set(CLASS_MAPPING)
    if found_labels != expected_labels:
        raise ValueError(f"Expected labels {sorted(expected_labels)}, found {sorted(found_labels)}")

    for column in CIC_FEATURE_COLUMNS:
        combined[column] = pd.to_numeric(combined[column], errors="coerce")
    for column in TIMING_COLUMNS:
        combined[column] = combined[column] / 1_000_000
    combined = combined.replace([np.inf, -np.inf], np.nan)
    invalid_rows = int(combined[CIC_FEATURE_COLUMNS].isna().any(axis=1).sum())
    cleaned = combined.dropna(subset=CIC_FEATURE_COLUMNS).copy()

    runtime_rename = {cic_name: runtime_name for cic_name, runtime_name, _ in FEATURE_CONTRACT}
    cleaned = cleaned.rename(columns=runtime_rename)
    cleaned["_row_identity"] = row_identity(cleaned)
    train, test = stratified_group_split(cleaned)
    overlap = set(train["_row_identity"]) & set(test["_row_identity"])
    if overlap:
        raise ValueError("Exact rows overlap between training and test data.")
    train = train[RUNTIME_FEATURE_COLUMNS + [LABEL_COLUMN]]
    test = test[RUNTIME_FEATURE_COLUMNS + [LABEL_COLUMN]]

    if train[RUNTIME_FEATURE_COLUMNS].isna().any().any() or test[RUNTIME_FEATURE_COLUMNS].isna().any().any():
        raise ValueError("NaN values remain after cleaning.")
    if not np.isfinite(train[RUNTIME_FEATURE_COLUMNS].to_numpy()).all() or not np.isfinite(test[RUNTIME_FEATURE_COLUMNS].to_numpy()).all():
        raise ValueError("Infinity values remain after cleaning.")
    if not all(pd.api.types.is_numeric_dtype(train[column]) for column in RUNTIME_FEATURE_COLUMNS):
        raise ValueError("A predictive feature is not numeric.")
    if not set(train[LABEL_COLUMN].unique()) == expected_labels or not set(test[LABEL_COLUMN].unique()) == expected_labels:
        raise ValueError("A split is missing one or more target classes.")

    train.to_csv(output_directory / "train.csv", index=False)
    test.to_csv(output_directory / "test.csv", index=False)
    source_hashes_after = {path.name: file_hash(path) for path in source_paths}
    if source_hashes_before != source_hashes_after:
        raise RuntimeError("A source CSV changed during preprocessing.")
    (output_directory / "feature_schema.json").write_text(json.dumps({
        "version": FEATURE_SCHEMA_VERSION,
        "runtime_feature_order": RUNTIME_FEATURE_COLUMNS,
        "mapping": [dict(cic_column=cic, runtime_field=runtime, conversion=conversion) for cic, runtime, conversion in FEATURE_CONTRACT],
        "time_unit": CANONICAL_TIME_UNIT,
        "packet_length_semantics": "TCP/UDP transport payload bytes",
        "standard_deviation": "sample",
        "flow_timeout_seconds": FLOW_TIMEOUT_SECONDS,
    }, indent=2), encoding="utf-8")
    (output_directory / "class_mapping.json").write_text(json.dumps(CLASS_MAPPING, indent=2), encoding="utf-8")
    metadata = {
        "source_files": SOURCE_FILES,
        "source_hashes": source_hashes_after,
        "source_files_unchanged": True,
        "original_rows": original_rows,
        "invalid_rows_removed": invalid_rows,
        "final_rows": len(cleaned),
        "random_state": RANDOM_STATE,
        "test_fraction": TEST_FRACTION,
        "duplicate_policy": "Retained; exact duplicate identities are kept in one split only.",
        "split_strategy": "Stratified by Label and grouped by exact cleaned-row identity.",
        "class_counts_after_cleaning": distribution(cleaned),
        "train_rows": len(train),
        "test_rows": len(test),
        "train_class_distribution": distribution(train),
        "test_class_distribution": distribution(test),
        "exact_row_overlap": 0,
        "model_trained": False,
    }
    (output_directory / "preprocessing_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
