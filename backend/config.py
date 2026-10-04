import os
from dotenv import load_dotenv

load_dotenv()

INSECURE_DEVELOPMENT_SECRET_KEY = "change-this-development-key"


def require_production_secret_key() -> None:
    """Reject a missing or development signing key before Waitress starts."""
    configured_key = os.getenv("SECRET_KEY", "").strip()
    if not configured_key or configured_key == INSECURE_DEVELOPMENT_SECRET_KEY:
        raise RuntimeError("Waitress deployment requires a valid SECRET_KEY environment variable.")


class Config:
    """Configuration values are read from environment variables."""
    SECRET_KEY = os.getenv("SECRET_KEY", INSECURE_DEVELOPMENT_SECRET_KEY)
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_NAME = os.getenv("DB_NAME", "ai_nids")
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_SSL_CA = os.getenv("DB_SSL_CA", "") 
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    TSHARK_PATH = os.getenv("TSHARK_PATH", r"D:\Degree\FYP\Wireshark\tshark.exe")
    PCAP_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), "pcap", "uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_PCAP_UPLOAD_BYTES", str(20 * 1024 * 1024)))
    MAX_PCAP_PACKETS = int(os.getenv("MAX_PCAP_PACKETS", "500"))
    FLOW_TIMEOUT_SECONDS = int(os.getenv("FLOW_TIMEOUT_SECONDS", "120"))
    THREAT_DEDUP_WINDOW_SECONDS = int(os.getenv("THREAT_DEDUP_WINDOW_SECONDS", "300"))
    MONITOR_POLL_SECONDS = float(os.getenv("MONITOR_POLL_SECONDS", "2"))
    MAX_MONITOR_ACTIVE_FLOWS = int(os.getenv("MAX_MONITOR_ACTIVE_FLOWS", "500"))
    MAX_MONITOR_RESULTS = int(os.getenv("MAX_MONITOR_RESULTS", "200"))
    MAX_MONITOR_QUEUE = int(os.getenv("MAX_MONITOR_QUEUE", "500"))
    DEVICE_ACTIVE_SECONDS = int(os.getenv("DEVICE_ACTIVE_SECONDS", "300"))
    DEVICE_OBSERVATION_UPDATE_SECONDS = int(os.getenv("DEVICE_OBSERVATION_UPDATE_SECONDS", "60"))
    # Sensor mode is deliberately opt-in. The interface value is a TShark
    # interface ID from /api/capture/interfaces, not a machine-specific default.
    AUTO_MONITORING = os.getenv("AI_NIDS_AUTO_MONITORING", "false").lower() == "true"
    MONITOR_INTERFACE = os.getenv("AI_NIDS_MONITOR_INTERFACE", "").strip()
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    JSON_SORT_KEYS = False
