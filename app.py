"""Password Strength Auditor - Flask Web Application.

A cybersecurity web application for analyzing password strength, detecting weaknesses,
checking common passwords, and logging SHA-256 audit records to PostgreSQL.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import string
from typing import Any, Dict

from flask import Flask, Response, jsonify, render_template, request, send_from_directory
from dotenv import load_dotenv

from db import (
    check_db_connection,
    get_audit_history,
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
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key-replace-in-production")
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
# Security Headers Middleware
# ---------------------------------------------------------------------------
@app.after_request
def apply_security_headers(response: Response) -> Response:
    """Injects essential cybersecurity HTTP headers into every response."""
    # Prevent MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking / frame embedding
    response.headers["X-Frame-Options"] = "DENY"

    # Legacy XSS protection for older browsers
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Control Referrer Information
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Restrict permissions for camera, microphone, geolocation
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # Content Security Policy (allows Google Fonts, local assets, and UI state scripts)
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
# Page Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
@app.route("/api/index", methods=["GET", "POST"])
@app.route("/api/index/", methods=["GET", "POST"])
def index():
    """Renders the main Password Strength Auditor interface or delegates to requested route."""
    # Check if this was a forwarded request for a sub-route on Vercel
    target_route = request.args.get("__route__") or request.args.get("path") or ""
    target_route = target_route.strip("/")
    if target_route == "history":
        return history()
    elif target_route == "check":
        return check_password()
    elif target_route == "health":
        return health()
    elif target_route == "generate":
        return generate_password()

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
def history():
    """Returns audit history either as HTML page or JSON based on request headers."""
    records = get_audit_history(limit=20)

    # Return JSON if requested by API client or query param format=json
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
    """Health check endpoint for smoke testing and service monitoring."""
    db_ok, db_msg = check_db_connection()
    status_code = 200 if db_ok else 200  # Returns 200 with status info
    return jsonify({
        "status": "ok",
        "database": "connected" if db_ok else "disconnected",
        "message": db_msg,
    }), status_code


@app.route("/check", methods=["POST"])
@app.route("/api/check", methods=["POST"])
@app.route("/api/index/check", methods=["POST"])
def check_password():
    """Evaluates password strength, hashes the password, and optionally logs the audit.

    Expected JSON body:
    {
        "password": "ExamplePassword123!",
        "log_audit": true  (optional, defaults to true)
    }
    """
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
    # Allows debounced live analysis preview vs completed audit save
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

    # 7. Compute SHA-256 hash (never log or store the raw password!)
    password_hash = hashlib.sha256(raw_password.encode("utf-8")).hexdigest()
    truncated = truncate_hash(password_hash)

    # 8. Save audit record to PostgreSQL if logging is enabled
    logged = False
    if should_log:
        audit_id = log_audit(
            password_hash=password_hash,
            score=analysis["score"],
            length=analysis["length"],
            has_upper=analysis["has_upper"],
            has_lower=analysis["has_lower"],
            has_digit=analysis["has_digit"],
            has_symbol=analysis["has_symbol"],
            is_common=analysis["is_common"],
        )
        logged = audit_id is not None

    save_status = (
        "Audit saved successfully."
        if logged
        else ("Password analyzed, but the audit could not be saved." if should_log else "")
    )

    # 9. Return JSON response (Raw password is strictly omitted!)
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
    }), 200


@app.route("/generate", methods=["POST"])
@app.route("/api/generate", methods=["POST"])
@app.route("/api/index/generate", methods=["POST"])
def generate_password():
    """Bonus feature: Generates a cryptographically secure random strong password."""
    # Ensure minimum 16 characters with at least 1 upper, 1 lower, 1 digit, 1 symbol
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


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api") or request.is_json:
        return jsonify({"error": "Resource not found"}), 404
    return render_template("index.html"), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    print(f"[*] Starting Password Strength Auditor on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug, threaded=True)
