"""Small, non-fatal helper for recording real AI-NIDS security events."""
from __future__ import annotations

from flask import current_app, has_app_context
from mysql.connector import Error

from database import database_cursor


def log_security_event(event_type, source, description, severity="Low", status="Recorded"):
    """Store one operational event without interrupting the caller on failure."""
    try:
        with database_cursor() as (_connection, cursor):
            cursor.execute(
                "INSERT INTO security_logs (event_type, source, description, severity, status) "
                "VALUES (%s, %s, %s, %s, %s)",
                (event_type, source, description, severity, status),
            )
        return True
    except Error:
        if has_app_context():
            current_app.logger.warning("Security event could not be recorded: %s", event_type)
        return False
