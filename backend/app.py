import os
from pathlib import Path
from flask import Flask, request, send_from_directory
from flask_cors import CORS
from config import Config
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.traffic import traffic_bp
from routes.threats import threats_bp
from routes.devices import devices_bp
from routes.logs import logs_bp
from routes.reports import reports_bp
from routes.settings import settings_bp
from routes.capture import capture_bp, shutdown_monitoring, start_autonomous_monitoring
from routes.pcap import pcap_bp
from routes.incidents import incidents_bp
from routes.ai_detection import ai_detection_bp
from routes.analytics import analytics_bp
from routes.controlled_replay import replay_bp
from ml.predictor import FlowPredictor

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def create_app():
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    CORS(app, supports_credentials=True)

    # Load once during application creation. Routes reuse this validated object
    # and report a clear 503 response if the model artefacts are unavailable.
    try:
        app.extensions["flow_predictor"] = FlowPredictor()
        app.extensions["flow_predictor_error"] = None
    except Exception as error:
        app.extensions["flow_predictor"] = None
        app.extensions["flow_predictor_error"] = str(error)
        app.logger.exception("AI flow predictor could not be loaded")

    for blueprint in (auth_bp, dashboard_bp, traffic_bp, threats_bp, devices_bp, logs_bp, reports_bp, settings_bp, capture_bp, pcap_bp, ai_detection_bp, analytics_bp, incidents_bp, replay_bp):
        app.register_blueprint(blueprint)

    @app.route("/")
    def login_page():
        return send_from_directory(PROJECT_ROOT, "index.html")

    @app.route("/<path:filename>")
    def frontend_file(filename):
        return send_from_directory(PROJECT_ROOT, filename)

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith('/api/'):
            return {"success": False, "message": "API endpoint not found"}, 404
        return _error

    @app.errorhandler(500)
    def server_error(_error):
        return {"success": False, "message": "An internal server error occurred"}, 500

    @app.errorhandler(405)
    def method_not_allowed(_error):
        if request.path.startswith('/api/'):
            return {"success": False, "message": "HTTP method not allowed for this API endpoint"}, 405
        return _error

    @app.errorhandler(413)
    def upload_too_large(_error):
        if request.path.startswith('/api/'):
            return {"success": False, "message": "Uploaded PCAP file exceeds the configured size limit"}, 413
        return _error

    return app

# Flask application instance for WSGI/serverless deployment (e.g. Vercel)
app = create_app()

# MUST BE DOUBLE UNDERSCORES: __name__ and "__main__"
if __name__ == "__main__":


    print("Starting AI-NIDS on http://127.0.0.1:5000", flush=True)
    application = create_app()
    # The factory remains safe for imports and tests. In debug mode Werkzeug
    # starts a parent and child process; only the child may start the sensor.
    is_reloader_child = os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    should_start_sensor = not application.config["DEBUG"] or is_reloader_child
    if should_start_sensor:
        start_autonomous_monitoring(application)
    try:
        application.run(debug=application.config["DEBUG"], host="127.0.0.1", port=5000)
    finally:
        if should_start_sensor:
            shutdown_monitoring(application)
