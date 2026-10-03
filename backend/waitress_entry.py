"""Standalone Waitress entry point for the NetSentry AI Windows deployment."""
from waitress import serve

from app import create_app
from config import require_production_secret_key
from routes.capture import shutdown_monitoring, start_autonomous_monitoring


def main() -> None:
    """Create one application and run its optional autonomous sensor once."""
    require_production_secret_key()
    app = create_app()
    start_autonomous_monitoring(app)
    try:
        serve(app, host="0.0.0.0", port=8080)
    finally:
        shutdown_monitoring(app)


if __name__ == "__main__":
    main()
