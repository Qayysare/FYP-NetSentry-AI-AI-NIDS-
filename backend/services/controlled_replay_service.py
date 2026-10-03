"""Volatile, held-out dataset replay for examiner demonstrations only."""
from __future__ import annotations

from collections import deque
from pathlib import Path
import random
import uuid

import pandas as pd

from services.feature_schema import LABEL_COLUMN, RUNTIME_FEATURE_COLUMNS
from services.threat_priority import assess_threat

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_DATA_PATH = PROJECT_ROOT / "datasets" / "processed" / "test.csv"
SCENARIOS = {"NORMAL": "BENIGN", "PORTSCAN": "PortScan", "SSH": "SSH-Patator", "FTP": "FTP-Patator", "DDOS": "DDoS"}
SPEEDS = {"slow", "normal", "fast"}
CLASS_ORDER = ("BENIGN", "PortScan", "SSH-Patator", "FTP-Patator", "DDoS")
# Fixed local seed makes an irregular examiner sequence repeatable without
# changing Python's process-wide random state.
MIXED_SOC_SEED = 20250514
MIXED_COMPOSITION = {"BENIGN": 40, "PortScan": 15, "SSH-Patator": 15, "FTP-Patator": 15, "DDoS": 15}


class ControlledReplayError(ValueError): pass


def load_test_data(path: Path = TEST_DATA_PATH) -> pd.DataFrame:
    if not path.is_file(): raise ControlledReplayError("Held-out replay data is unavailable.")
    data = pd.read_csv(path)
    missing = [column for column in [*RUNTIME_FEATURE_COLUMNS, LABEL_COLUMN] if column not in data.columns]
    if missing: raise ControlledReplayError("Held-out replay data does not match the model feature contract.")
    return data


def scenario_rows(data: pd.DataFrame, scenario: str) -> list[dict]:
    if scenario == "MIXED":
        selected = []
        for label, count in MIXED_COMPOSITION.items():
            class_rows = data.loc[data[LABEL_COLUMN] == label].head(count)
            if len(class_rows) != count:
                raise ControlledReplayError("Held-out replay data cannot supply the Mixed SOC composition.")
            selected.extend({**row, "_replay_row_id": int(index)} for index, row in class_rows.iterrows())
        random.Random(MIXED_SOC_SEED).shuffle(selected)
        return selected
    label = SCENARIOS.get(scenario)
    if not label: raise ControlledReplayError("Choose a supported replay scenario.")
    return [{**row, "_replay_row_id": int(index)} for index, row in data.loc[data[LABEL_COLUMN] == label].head(20).iterrows()]


class ControlledReplayManager:
    """Bounded in-memory states, keyed by a random Flask-session identifier."""
    def __init__(self): self.sessions = {}

    def start(self, session_id: str | None, scenario: str, speed: str) -> tuple[str, dict]:
        if scenario not in {*SCENARIOS, "MIXED"}: raise ControlledReplayError("Unsupported replay scenario.")
        if speed not in SPEEDS: raise ControlledReplayError("Unsupported replay speed.")
        rows = scenario_rows(load_test_data(), scenario)
        if not rows: raise ControlledReplayError("No held-out rows are available for this scenario.")
        session_id = session_id or uuid.uuid4().hex
        self.sessions[session_id] = {"scenario": scenario, "speed": speed, "rows": rows, "position": 0, "running": True, "recent": deque(maxlen=50), "counts": {label: 0 for label in CLASS_ORDER}, "severity": {label: 0 for label in ("Informational", "Medium", "High", "Critical")}, "agreements": 0}
        return session_id, self.status(session_id)

    def status(self, session_id: str) -> dict:
        state = self.sessions.get(session_id)
        if not state: raise ControlledReplayError("Start a controlled replay first.")
        return {"scenario": state["scenario"], "speed": state["speed"], "running": state["running"], "complete": state["position"] >= len(state["rows"]), "total_available": len(state["rows"]), "total_replayed": state["position"], "prediction_counts": state["counts"], "severity_counts": state["severity"], "agreement_count": state["agreements"], "recent_predictions": list(state["recent"])}

    def next(self, session_id: str, predictor) -> dict:
        state = self.sessions.get(session_id)
        if not state: raise ControlledReplayError("Start a controlled replay first.")
        if not state["running"]: return {"event": None, **self.status(session_id)}
        if state["position"] >= len(state["rows"]):
            state["running"] = False; return {"event": None, **self.status(session_id)}
        row = state["rows"][state["position"]]
        prediction = predictor.predict_flow({key: row[key] for key in RUNTIME_FEATURE_COLUMNS})
        policy = assess_threat(prediction["classification"], prediction["confidence"])
        event = {"sequence": state["position"] + 1, "ground_truth": row[LABEL_COLUMN], "prediction": prediction["classification"], "confidence": float(prediction["confidence"]), "correct": prediction["classification"] == row[LABEL_COLUMN], "destination_port": row.get("destination_port"), "scenario": state["scenario"], "source": "CIC-IDS2017 held-out test partition", **policy}
        state["position"] += 1; state["counts"][event["prediction"]] += 1; state["severity"][event["severity"]] += 1; state["agreements"] += int(event["correct"]); state["recent"].appendleft(event)
        if state["position"] >= len(state["rows"]): state["running"] = False
        return {"event": event, **self.status(session_id)}

    def pause(self, session_id: str) -> dict:
        self.sessions[session_id]["running"] = False
        return self.status(session_id)

    def reset(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)
