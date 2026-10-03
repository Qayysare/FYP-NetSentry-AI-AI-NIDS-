from flask import Blueprint, request, session
from werkzeug.security import check_password_hash, generate_password_hash
from database import database_cursor
from utils.helpers import admin_required, failure, login_required, required_fields, success
from services.security_log import log_security_event

auth_bp = Blueprint("auth", __name__, url_prefix="/api")
VALID_ROLES = {"admin", "analyst", "user"}


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    identity, password = data.get("identity", "").strip(), data.get("password", "")
    if not identity or not password:
        return failure("Email/username and password are required")
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT user_id, full_name, username, email, password_hash, role, must_change_password, is_active FROM users WHERE username = %s OR email = %s", (identity, identity))
        user = cursor.fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        log_security_event("AUTH_LOGIN_FAILED", "Authentication", "A login attempt failed.", "Low")
        return failure("Invalid email/username or password", 401)
    if not user["is_active"]:
        return failure("This account is inactive. Contact an administrator.", 403)
    session.clear()
    session.update({"user_id": user["user_id"], "username": user["username"], "role": user["role"], "must_change_password": bool(user["must_change_password"])})
    user.pop("password_hash")
    log_security_event("AUTH_LOGIN_SUCCESS", user["username"], "User signed in successfully.", "Low")
    return success(user, "Password change required" if user["must_change_password"] else "Login successful")


@auth_bp.post("/logout")
@login_required
def logout():
    log_security_event("AUTH_LOGOUT", session.get("username", "Authenticated user"), "User signed out successfully.", "Low")
    session.clear()
    return success(message="Logged out successfully")


@auth_bp.get("/me")
@login_required
def current_user():
    """Return the authenticated account without exposing its password hash."""
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT user_id, full_name, username, email, role, must_change_password, is_active FROM users WHERE user_id = %s", (session["user_id"],))
        user = cursor.fetchone()
    if not user or not user["is_active"]:
        session.clear()
        return failure("Your account is unavailable. Please sign in again.", 401)
    return success(user, "Current user retrieved successfully")


@auth_bp.get("/users")
@admin_required
def list_users():
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT user_id, full_name, username, email, role, must_change_password, is_active, created_at FROM users ORDER BY created_at DESC")
        rows = cursor.fetchall()
    return success(rows, "Users retrieved successfully")


@auth_bp.post("/users")
@admin_required
def create_user():
    data = request.get_json(silent=True) or {}
    missing = required_fields(data, ["full_name", "username", "email", "temporary_password", "role"])
    if missing or data.get("role") not in VALID_ROLES:
        return failure("Provide valid user details, a temporary password, and a role")
    if len(data["temporary_password"]) < 8:
        return failure("Temporary password must contain at least 8 characters")
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (data["username"].strip(), data["email"].strip()))
        if cursor.fetchone():
            return failure("Username or email already exists", 409)
        cursor.execute("INSERT INTO users (full_name, username, email, password_hash, role, must_change_password) VALUES (%s, %s, %s, %s, %s, TRUE)", (data["full_name"].strip(), data["username"].strip(), data["email"].strip(), generate_password_hash(data["temporary_password"]), data["role"]))
        user_id = cursor.lastrowid
        cursor.execute("INSERT INTO security_logs (event_type, source, description, severity, status) VALUES ('Admin created user', %s, %s, 'Low', 'Recorded')", (session["username"], f"Created {data['role']} account: {data['username']}"))
    return success({"user_id": user_id, "must_change_password": True}, "User created with a temporary password", 201)


@auth_bp.put("/users/<int:user_id>")
@admin_required
def update_user(user_id):
    data = request.get_json(silent=True) or {}
    if "role" in data and data["role"] not in VALID_ROLES:
        return failure("Invalid role")
    if "is_active" not in data and "role" not in data:
        return failure("Provide a role or account status")
    fields, values = [], []
    for key in ("role", "is_active"):
        if key in data:
            fields.append(f"{key} = %s")
            values.append(data[key])
    values.append(user_id)
    with database_cursor() as (_connection, cursor):
        cursor.execute(f"UPDATE users SET {', '.join(fields)} WHERE user_id = %s", values)
        if cursor.rowcount == 0:
            return failure("User not found", 404)
    return success({"user_id": user_id}, "User updated successfully")


@auth_bp.post("/change-password")
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    missing = required_fields(data, ["current_password", "new_password", "confirm_password"])
    if missing or data["new_password"] != data["confirm_password"] or len(data["new_password"]) < 8:
        return failure("Provide matching new passwords with at least 8 characters")
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT password_hash FROM users WHERE user_id = %s", (session["user_id"],))
        user = cursor.fetchone()
        if not user or not check_password_hash(user["password_hash"], data["current_password"]):
            return failure("Current password is incorrect", 401)
        cursor.execute("UPDATE users SET password_hash = %s, must_change_password = FALSE WHERE user_id = %s", (generate_password_hash(data["new_password"]), session["user_id"]))
        cursor.execute("INSERT INTO security_logs (event_type, source, description, severity, status) VALUES ('Password changed', %s, 'User changed their password.', 'Low', 'Recorded')", (session["username"],))
    session["must_change_password"] = False
    return success(message="Password changed successfully")


@auth_bp.post("/password-reset-requests")
def request_password_reset():
    identity = (request.get_json(silent=True) or {}).get("identity", "").strip()
    if identity:
        with database_cursor() as (_connection, cursor):
            cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (identity, identity))
            user = cursor.fetchone()
            if user:
                cursor.execute("INSERT INTO password_reset_requests (user_id) VALUES (%s)", (user["user_id"],))
    return success(message="If the account exists, a reset request has been sent to an administrator.")


@auth_bp.get("/password-reset-requests")
@admin_required
def list_password_reset_requests():
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT r.request_id, u.username, u.email, r.requested_at, r.status FROM password_reset_requests r JOIN users u ON u.user_id = r.user_id ORDER BY r.requested_at DESC")
        rows = cursor.fetchall()
    return success(rows, "Password reset requests retrieved successfully")


@auth_bp.put("/password-reset-requests/<int:request_id>")
@admin_required
def review_password_reset_request(request_id):
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action not in {"Approved", "Rejected"}:
        return failure("Action must be Approved or Rejected")
    with database_cursor() as (_connection, cursor):
        cursor.execute("SELECT user_id FROM password_reset_requests WHERE request_id = %s AND status = 'Pending'", (request_id,))
        reset = cursor.fetchone()
        if not reset:
            return failure("Pending reset request not found", 404)
        if action == "Approved":
            temporary_password = data.get("temporary_password", "")
            if len(temporary_password) < 8:
                return failure("Approved requests need a temporary password of at least 8 characters")
            cursor.execute("UPDATE users SET password_hash = %s, must_change_password = TRUE WHERE user_id = %s", (generate_password_hash(temporary_password), reset["user_id"]))
        cursor.execute("UPDATE password_reset_requests SET status = %s, approved_by = %s, approved_at = CURRENT_TIMESTAMP WHERE request_id = %s", (action, session["user_id"], request_id))
    return success(message=f"Password reset request {action.lower()}")
