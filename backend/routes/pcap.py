from pathlib import Path
from flask import Blueprint, current_app, request
from werkzeug.utils import secure_filename
from routes.capture import get_service
from services.tshark_service import TSharkError
from utils.helpers import analyst_or_admin_required, failure, success

pcap_bp = Blueprint("pcap", __name__, url_prefix="/api/pcap")
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


@pcap_bp.post("/upload")
@analyst_or_admin_required
def upload():
    uploaded = request.files.get("capture_file")
    if not uploaded or not uploaded.filename:
        return failure("Choose a .pcap or .pcapng file")
    filename = secure_filename(uploaded.filename)
    if not filename or Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        return failure("Only .pcap and .pcapng files are supported")
    folder = Path(current_app.config["PCAP_UPLOAD_FOLDER"])
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / filename
    uploaded.save(path)
    try:
        packets = get_service().analyse_file(str(path), current_app.config["MAX_PCAP_PACKETS"])
    except TSharkError as error:
        path.unlink(missing_ok=True)
        return failure(str(error), 400)
    return success({"filename": filename, "packet_count": len(packets), "packets": packets}, "PCAP analysed successfully", 201)
