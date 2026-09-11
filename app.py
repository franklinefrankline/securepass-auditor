"""Password Strength Auditor - Flask Web Application.

A cybersecurity web application for analyzing password strength, detecting weaknesses,
checking common passwords, and logging SHA-256 audit records to PostgreSQL with
full multi-tenant user isolation and authentication.
Version 2.0 with cybersecurity split-screen authentication.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import string
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from db import (
    check_db_connection,
    create_user,
    get_audit_history,
    get_user_by_email,
    get_user_by_id,
    init_db,
    log_audit,
    truncate_hash,
)
from scorer import get_scorer

# Load environment configuration with override=True
load_dotenv(override=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

# Enterprise session security configuration
secret = os.getenv("SECRET_KEY", "")
if not secret or not secret.strip():
    secret = "securepass-enterprise-secret-key-2026-auth-prod-32bytes"

app.secret_key = secret
app.config["SECRET_KEY"] = secret
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["JSON_SORT_KEYS"] = False

# Maximum allowable password length to prevent DoS via regex/hashing exhaustion
MAX_PASSWORD_LENGTH = 1024

# Initialize database table on application start
try:
    init_db()
except Exception:
    # Non-blocking if database is offline on startup
    pass


# ---------------------------------------------------------------------------
# Context Processors & Auth Helpers
# ---------------------------------------------------------------------------
@app.context_processor
def inject_user() -> Dict[str, Any]:
    """Injects current authenticated user info into all rendered templates."""
    user = None
    user_id = session.get("user_id")
    if user_id:
        user = get_user_by_id(user_id)
    return {"current_user": user}


def login_required(f):
    """Decorator requiring an active user session.

    Redirects web requests to /login and returns JSON 401 for API requests.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if (
                request.is_json
                or request.path.startswith("/api/")
                or request.headers.get("Accept") == "application/json"
            ):
                return jsonify({"error": "Authentication required", "redirect": "/login"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------
@app.after_request
def apply_security_headers(response: Response) -> Response:
    """Injects essential cybersecurity HTTP headers into every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    csp_policy = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    response.headers["Content-Security-Policy"] = csp_policy
    return response


# ---------------------------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
@app.route("/api/login", methods=["GET", "POST"])
@app.route("/api/index/login", methods=["GET", "POST"])
def login():
    """Authenticates users via email and password."""
    # Redirect if already logged in
    if "user_id" in session and request.method == "GET":
        return redirect("/")

    if request.method == "POST":
        is_json = request.is_json
        data = (request.get_json(silent=True) if is_json else request.form) or {}

        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        if not email or not password:
            msg = "Email and password are required."
            if is_json:
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "error")
            return render_template("login.html"), 400

        user = get_user_by_email(email)
        if not user or not check_password_hash(user["password_hash"], password):
            msg = "Invalid email or password."
            if is_json:
                return jsonify({"success": False, "error": msg}), 401
            flash(msg, "error")
            return render_template("login.html"), 401

        # Establish secure session
        session.clear()
        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        session["user_name"] = user["full_name"]

        target_next = request.args.get("next") or "/"
        if not target_next.startswith("/"):
            target_next = "/"

        if is_json:
            return jsonify({
                "success": True,
                "message": "Authentication successful",
                "redirect": target_next,
                "user": {"id": user["id"], "name": user["full_name"], "email": user["email"]},
            }), 200

        return redirect(target_next)

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@app.route("/api/register", methods=["GET", "POST"])
@app.route("/api/index/register", methods=["GET", "POST"])
def register():
    """Registers a new user account with secure password hashing."""
    if "user_id" in session and request.method == "GET":
        return redirect("/")

    if request.method == "POST":
        try:
            is_json = request.is_json
            data = (request.get_json(silent=True) if is_json else request.form) or {}

            full_name = (data.get("full_name") or data.get("name") or "").strip()
            email = (data.get("email") or "").strip().lower()
            password = data.get("password") or ""
            confirm_password = data.get("confirm_password") or ""

            # Validation
            if not full_name:
                msg = "Full name is required."
                if is_json:
                    return jsonify({"success": False, "error": msg}), 400
                flash(msg, "error")
                return render_template("register.html"), 400

            if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                msg = "A valid email address is required."
                if is_json:
                    return jsonify({"success": False, "error": msg}), 400
                flash(msg, "error")
                return render_template("register.html"), 400

            if len(password) < 8:
                msg = "Password must be at least 8 characters long."
                if is_json:
                    return jsonify({"success": False, "error": msg}), 400
                flash(msg, "error")
                return render_template("register.html"), 400

            if password != confirm_password:
                msg = "Passwords do not match."
                if is_json:
                    return jsonify({"success": False, "error": msg}), 400
                flash(msg, "error")
                return render_template("register.html"), 400

            # Check existing user
            existing_user = get_user_by_email(email)
            if existing_user:
                msg = "An account with this email address already exists."
                if is_json:
                    return jsonify({"success": False, "error": msg}), 400
                flash(msg, "error")
                return render_template("register.html"), 400

            # Secure password hashing (Werkzeug default)
            password_hash = generate_password_hash(password)
            user_id, err = create_user(full_name, email, password_hash)

            if err or not user_id:
                msg = err or "Registration failed. Please try again."
                if is_json:
                    return jsonify({"success": False, "error": msg}), 400
                flash(msg, "error")
                return render_template("register.html"), 400

            # Require explicit user login: do not auto-login into home page
            session.clear()

            if is_json:
                return jsonify({
                    "success": True,
                    "message": "Account created successfully! Please log in.",
                    "redirect": "/login?registered=1",
                    "user": {"id": user_id, "name": full_name, "email": email},
                }), 201

            flash("Account created successfully! Please log in.", "success")
            return redirect("/login?registered=1")
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            print("ERROR in register:", e, tb)
            if request.is_json:
                return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500
            flash(f"Server error: {str(e)}", "error")
            return render_template("register.html"), 500

    return render_template("register.html")


@app.route("/logout", methods=["GET"])
@app.route("/api/logout", methods=["GET"])
@app.route("/api/index/logout", methods=["GET"])
def logout():
    """Terminates user session and redirects to login."""
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect("/login")


@app.route("/settings", methods=["GET"])
@app.route("/api/settings", methods=["GET"])
@app.route("/api/index/settings", methods=["GET"])
@login_required
def settings():
    """Opens auditor interface with settings dialog active."""
    return render_template("index.html", open_settings=True)


# ---------------------------------------------------------------------------
# Core Application Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
@app.route("/api/index", methods=["GET", "POST"])
@app.route("/api/index/", methods=["GET", "POST"])
def index():
    """Renders the main Password Strength Auditor interface or delegates to requested route."""
    # Check if this was a forwarded request for a sub-route on Vercel
    target_route = (
        request.args.get("__route__")
        or request.args.get("path")
        or request.args.get("view")
        or ""
    ).strip("/")
    matched = request.headers.get("x-matched-path", "")

    if (
        target_route == "login"
        or request.path == "/login"
        or request.path.endswith("/login")
        or matched == "/login"
    ):
        return login()
    elif (
        target_route == "register"
        or request.path == "/register"
        or request.path.endswith("/register")
        or matched == "/register"
    ):
        return register()
    elif (
        target_route == "logout"
        or request.path == "/logout"
        or request.path.endswith("/logout")
        or matched == "/logout"
    ):
        return logout()
    elif (
        target_route == "settings"
        or request.path == "/settings"
        or request.path.endswith("/settings")
        or matched == "/settings"
    ):
        return settings()
    elif (
        target_route == "history"
        or request.path == "/history"
        or request.path.endswith("/history")
        or matched == "/history"
    ):
        return history()
    elif (
        target_route == "check"
        or request.path == "/check"
        or request.path.endswith("/check")
        or matched == "/check"
    ):
        return check_password()
    elif (
        target_route == "health"
        or request.path == "/health"
        or request.path.endswith("/health")
        or matched == "/health"
    ):
        return health()
    elif (
        target_route == "generate"
        or request.path == "/generate"
        or request.path.endswith("/generate")
        or matched == "/generate"
    ):
        return generate_password()

    # Protected main page: redirect to login if unauthenticated
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        return check_password()

    return render_template("index.html")


@app.route("/static/<path:filename>")
def serve_static_asset(filename: str):
    """Serves static files directly with proper MIME types."""
    static_folder = os.path.join(BASE_DIR, "static")
    return send_from_directory(static_folder, filename)


@app.route("/history", methods=["GET"])
@app.route("/api/history", methods=["GET"])
@app.route("/api/index/history", methods=["GET"])
@login_required
def history():
    """Returns audit history for the authenticated user only (full tenant isolation)."""
    user_id = session.get("user_id")
    records = get_audit_history(user_id=user_id, limit=20)

    wants_json = (
        request.headers.get("Accept") == "application/json"
        or request.args.get("format") == "json"
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    if wants_json:
        return jsonify({"history": records})

    return render_template("history.html", history=records)


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
@app.route("/api/health", methods=["GET"])
@app.route("/api/index/health", methods=["GET"])
def health():
    """Public health check endpoint for uptime monitoring."""
    db_ok, db_msg = check_db_connection()
    return jsonify({
        "status": "ok",
        "database": "connected" if db_ok else "disconnected",
        "message": db_msg,
    }), 200


@app.route("/check", methods=["POST"])
@app.route("/api/check", methods=["POST"])
@app.route("/api/index/check", methods=["POST"])
@login_required
def check_password():
    """Evaluates password strength, hashes the password, and logs audit record for active user."""
    # 1. Validate JSON presence
    if not request.is_json:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    data = request.get_json(silent=True)
    if data is None or not isinstance(data, dict):
        return jsonify({"error": "Invalid or malformed JSON payload"}), 400

    # 2. Validate password field presence and type
    if "password" not in data:
        return jsonify({"error": "Password is required"}), 400

    raw_password = data["password"]
    if not isinstance(raw_password, str):
        return jsonify({"error": "Password must be a string"}), 400

    # 3. Guard against excessive length (DoS prevention)
    if len(raw_password) > MAX_PASSWORD_LENGTH:
        return jsonify({
            "error": f"Password exceeds maximum allowed length of {MAX_PASSWORD_LENGTH} characters"
        }), 400

    # 4. Determine if this audit should be logged
    should_log = data.get("log_audit", True)

    # 5. Handle empty password gracefully
    if raw_password == "":
        return jsonify({
            "score": 0,
            "level": "WEAK",
            "issues": ["Password cannot be empty"],
            "suggestions": ["Enter a secure password of at least 12 characters"],
            "length": 0,
            "has_upper": False,
            "has_lower": False,
            "has_digit": False,
            "has_symbol": False,
            "is_common": False,
            "truncated_hash": "",
            "logged": False,
        }), 200

    # 6. Evaluate password strength using scorer engine
    scorer = get_scorer()
    analysis = scorer.evaluate(raw_password)

    # 7. Compute SHA-256 hash (never log or store raw password!)
    password_hash = hashlib.sha256(raw_password.encode("utf-8")).hexdigest()
    truncated = truncate_hash(password_hash)

    # 8. Save audit record associated with active user
    logged = False
    if should_log:
        user_id = session.get("user_id", 1)
        audit_id = log_audit(
            password_hash=password_hash,
            score=analysis["score"],
            length=analysis["length"],
            has_upper=analysis["has_upper"],
            has_lower=analysis["has_lower"],
            has_digit=analysis["has_digit"],
            has_symbol=analysis["has_symbol"],
            is_common=analysis["is_common"],
            user_id=user_id,
        )
        logged = audit_id is not None

    save_status = (
        "Audit saved successfully."
        if logged
        else ("Password analyzed, but the audit could not be saved." if should_log else "")
    )

    # 9. Return JSON response
    return jsonify({
        "success": True,
        "score": analysis["score"],
        "strength": analysis["level"].capitalize(),
        "level": analysis["level"],
        "issues": analysis["issues"],
        "suggestions": analysis["suggestions"],
        "length": analysis["length"],
        "has_upper": analysis["has_upper"],
        "has_lower": analysis["has_lower"],
        "has_digit": analysis["has_digit"],
        "has_symbol": analysis["has_symbol"],
        "is_common": analysis["is_common"],
        "truncated_hash": truncated,
        "logged": logged,
        "save_status": save_status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }), 200


@app.route("/generate", methods=["POST"])
@app.route("/api/generate", methods=["POST"])
@app.route("/api/index/generate", methods=["POST"])
def generate_password():
    """Generates a cryptographically secure random strong password."""
    length = 16
    specials = "!@#$%^&*()-_=+"
    alphabet = string.ascii_letters + string.digits + specials

    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.isupper() for c in candidate)
            and any(c.islower() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and any(c in specials for c in candidate)
        ):
            return jsonify({"generated_password": candidate})


# ---------------------------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------------------------
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(401)
def unauthorized(e):
    if request.is_json or request.path.startswith("/api"):
        return jsonify({"error": "Authentication required", "redirect": "/login"}), 401
    return redirect("/login")


@app.errorhandler(404)
def not_found(e):
    if (
        request.path == "/history"
        or "history" in request.path
        or request.args.get("view") == "history"
        or request.args.get("__route__") == "history"
    ):
        return history()
    if (
        request.path == "/login"
        or request.args.get("__route__") == "login"
    ):
        return login()
    if (
        request.path == "/register"
        or request.args.get("__route__") == "register"
    ):
        return register()
    if request.path.startswith("/api") or request.is_json:
        return jsonify({"error": "Resource not found"}), 404
    return redirect("/")


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def server_error(e):
    import traceback
    err_str = str(getattr(e, "original_exception", e))
    tb = traceback.format_exc()
    return jsonify({"error": f"Internal server error: {err_str}", "traceback": tb}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    print(f"[*] Starting Password Strength Auditor on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug, threaded=True)
