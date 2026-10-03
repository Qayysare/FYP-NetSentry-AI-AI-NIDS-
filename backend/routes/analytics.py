"""Authenticated SQL aggregations used by the Stage 5 dashboard and analytics UI."""
from flask import Blueprint

from database import database_cursor
from utils.helpers import analyst_or_admin_required, success


analytics_bp = Blueprint("analytics", __name__, url_prefix="/api/analytics")


def _distribution(column: str) -> list[dict]:
    """Return a simple count grouped by a fixed, internal table column."""
    with database_cursor() as (_connection, cursor):
        cursor.execute(f"SELECT {column} AS label, COUNT(*) AS value FROM threats GROUP BY {column} ORDER BY value DESC, label")
        return cursor.fetchall()


@analytics_bp.get("/threat-distribution")
@analyst_or_admin_required
def threat_distribution():
    return success(_distribution("attack_type"), "Threat type distribution retrieved successfully")


@analytics_bp.get("/severity-distribution")
@analyst_or_admin_required
def severity_distribution():
    return success(_distribution("severity"), "Severity distribution retrieved successfully")


@analytics_bp.get("/status-distribution")
@analyst_or_admin_required
def status_distribution():
    with database_cursor() as (_connection, cursor):
        cursor.execute(
            "SELECT COALESCE(NULLIF(status, ''), 'Unspecified') AS label, COUNT(*) AS value "
            "FROM threats GROUP BY COALESCE(NULLIF(status, ''), 'Unspecified') ORDER BY value DESC, label"
        )
        rows = cursor.fetchall()
    return success(rows, "Threat status distribution retrieved successfully")


@analytics_bp.get("/threat-trend")
@analyst_or_admin_required
def threat_trend():
    """Return up to the most recent 30 threat-detection days in chronological order."""
    with database_cursor() as (_connection, cursor):
        cursor.execute(
            "SELECT label, value FROM ("
            "SELECT DATE_FORMAT(detected_at, '%Y-%m-%d') AS label, COUNT(*) AS value "
            "FROM threats GROUP BY DATE_FORMAT(detected_at, '%Y-%m-%d') "
            "ORDER BY label DESC LIMIT 30"
            ") AS recent_days ORDER BY label"
        )
        rows = cursor.fetchall()
    return success(rows, "Threat trend retrieved successfully")
