"""Authenticated API for session-only CIC-IDS2017 controlled replay."""
from flask import Blueprint, current_app, request, session
from services.controlled_replay_service import ControlledReplayError, ControlledReplayManager, SCENARIOS, SPEEDS
from utils.helpers import analyst_or_admin_required, failure, success

replay_bp = Blueprint("controlled_replay", __name__, url_prefix="/api/replay")

def manager():
    return current_app.extensions.setdefault("controlled_replay_manager", ControlledReplayManager())

def replay_id(): return session.get("controlled_replay_id")

@replay_bp.get("/scenarios")
@analyst_or_admin_required
def scenarios():
    return success({"scenarios": [{"key": key, "label": label} for key, label in {**{"NORMAL":"Normal Activity","PORTSCAN":"PortScan Activity","SSH":"SSH Authentication Activity","FTP":"FTP Authentication Activity","DDOS":"DDoS Activity","MIXED":"Mixed SOC Scenario"}}.items()], "speeds": sorted(SPEEDS)}, "Controlled replay scenarios retrieved")

@replay_bp.post("/start")
@analyst_or_admin_required
def start():
    data=request.get_json(silent=True) or {}
    try:
        identifier, state=manager().start(replay_id(), str(data.get("scenario","MIXED")).upper(), str(data.get("speed","normal")).lower())
        session["controlled_replay_id"]=identifier
        return success(state, "Controlled replay started")
    except ControlledReplayError as error: return failure(str(error), 400)

@replay_bp.post("/next")
@analyst_or_admin_required
def next_flow():
    predictor=current_app.extensions.get("flow_predictor")
    if predictor is None: return failure("AI prediction service is unavailable", 503)
    try: return success(manager().next(replay_id(), predictor), "Controlled replay advanced")
    except ControlledReplayError as error: return failure(str(error), 409)

@replay_bp.post("/pause")
@analyst_or_admin_required
def pause():
    try: return success(manager().pause(replay_id()), "Controlled replay paused")
    except (ControlledReplayError, KeyError): return failure("Start a controlled replay first.", 409)

@replay_bp.post("/reset")
@analyst_or_admin_required
def reset():
    manager().reset(replay_id()); session.pop("controlled_replay_id", None)
    return success({"reset": True}, "Controlled replay reset")

@replay_bp.get("/status")
@analyst_or_admin_required
def status():
    try: return success(manager().status(replay_id()), "Controlled replay status retrieved")
    except ControlledReplayError: return success({"running":False,"total_replayed":0,"recent_predictions":[]}, "No controlled replay is active")
