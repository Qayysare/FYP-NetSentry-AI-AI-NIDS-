from functools import wraps
from flask import jsonify, request, session


PASSWORD_CHANGE_ENDPOINTS = {"auth.current_user", "auth.change_password", "auth.logout"}


def success(data=None, message="Request completed successfully", status=200):
    return jsonify({"success": True, "message": message, "data": data}), status


def failure(message, status=400):
    return jsonify({"success": False, "message": message}), status


def required_fields(payload, fields):
    missing = [field for field in fields if not payload.get(field)]
    return missing


def _authentication_failure():
    if not session.get("user_id"):
        return failure("Authentication is required", 401)
    if session.get("must_change_password") and request.endpoint not in PASSWORD_CHANGE_ENDPOINTS:
        return failure("Password change is required before accessing this feature", 403)
    return None


def roles_required(*allowed_roles):
    """Require authentication and one of the existing application roles."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            blocked = _authentication_failure()
            if blocked:
                return blocked
            if session.get("role") not in allowed_roles:
                return failure("You do not have permission to access this feature", 403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        blocked = _authentication_failure()
        if blocked:
            return blocked
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    """Keep the existing administrator error wording for management routes."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        blocked = _authentication_failure()
        if blocked:
            return blocked
        if session.get("role") != "admin":
            return failure("Administrator access is required", 403)
        return view(*args, **kwargs)
    return wrapped


def analyst_or_admin_required(view):
    return roles_required("admin", "analyst")(view)
