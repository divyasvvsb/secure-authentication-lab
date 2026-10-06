"""Secure Authentication Lab - a small local authentication service.

Defensive controls implemented:
  1. Password hashing (scrypt, salted) and server-side input validation
  2. Secure session cookies (HttpOnly, Secure, SameSite), logout, session expiry
  3. Rate limiting on login and generic authentication errors
"""
import os
import re
import secrets
import time

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
GENERIC_AUTH_ERROR = "Invalid username or password."

# Hash used to keep login timing similar when the username does not exist.
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


def validate_username(username):
    if not isinstance(username, str) or not USERNAME_RE.match(username):
        return "Username must be 3-32 characters: letters, digits or underscore."
    return None


def validate_password(password):
    if not isinstance(password, str):
        return "Password must be a string."
    if len(password) < 10 or len(password) > 128:
        return "Password must be 10-128 characters long."
    if not re.search(r"[a-z]", password):
        return "Password must contain a lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password must contain an uppercase letter."
    if not re.search(r"\d", password):
        return "Password must contain a digit."
    return None


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        # Secure is on by default. Set INSECURE_DEV=1 only for local http testing.
        SESSION_COOKIE_SECURE=os.environ.get("INSECURE_DEV") != "1",
        SESSION_COOKIE_NAME="session_id",
        SESSION_IDLE_SECONDS=15 * 60,       # expire after 15 min of inactivity
        SESSION_MAX_SECONDS=8 * 60 * 60,    # hard limit of 8 hours
        MAX_FAILED_ATTEMPTS=5,              # failures allowed per window
        RATE_LIMIT_WINDOW=60,               # seconds
        CLOCK=time.time,                    # injectable so tests can fake time
    )
    if config:
        app.config.update(config)

    users = {}      # username -> password hash
    sessions = {}   # token -> {"user", "created", "last_seen"}
    failures = {}   # (ip, username) -> [timestamps of failed attempts]

    def now():
        return app.config["CLOCK"]()

    # ---------- rate limiting ----------
    def recent_failures(key):
        window = app.config["RATE_LIMIT_WINDOW"]
        stamps = [t for t in failures.get(key, []) if now() - t < window]
        failures[key] = stamps
        return stamps

    def is_rate_limited(key):
        return len(recent_failures(key)) >= app.config["MAX_FAILED_ATTEMPTS"]

    def record_failure(key):
        recent_failures(key).append(now())

    # ---------- sessions ----------
    def current_user():
        token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        data = sessions.get(token) if token else None
        if not data:
            return None
        t = now()
        expired = (
            t - data["last_seen"] > app.config["SESSION_IDLE_SECONDS"]
            or t - data["created"] > app.config["SESSION_MAX_SECONDS"]
        )
        if expired:
            sessions.pop(token, None)
            return None
        data["last_seen"] = t
        return data["user"]

    def set_session_cookie(response, token, max_age):
        response.set_cookie(
            app.config["SESSION_COOKIE_NAME"],
            token,
            max_age=max_age,
            httponly=True,
            secure=app.config["SESSION_COOKIE_SECURE"],
            samesite="Strict",
            path="/",
        )

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = "default-src 'none'"
        return resp

    # ---------- routes ----------
    @app.post("/register")
    def register():
        body = request.get_json(silent=True) or {}
        username = body.get("username")
        password = body.get("password")

        error = validate_username(username) or validate_password(password)
        if error:
            return jsonify(error=error), 400
        if username.lower() in users:
            return jsonify(error="Registration failed. Try a different username."), 409

        users[username.lower()] = generate_password_hash(password)
        return jsonify(message="Account created."), 201

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        username = body.get("username")
        password = body.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify(error=GENERIC_AUTH_ERROR), 401

        key = (request.remote_addr, username.lower())
        if is_rate_limited(key):
            resp = jsonify(error="Too many attempts. Try again later.")
            resp.status_code = 429
            resp.headers["Retry-After"] = str(app.config["RATE_LIMIT_WINDOW"])
            return resp

        stored = users.get(username.lower())
        # Always run one hash check so response time does not reveal valid usernames.
        valid = check_password_hash(stored or _DUMMY_HASH, password) and stored is not None
        if not valid:
            record_failure(key)
            return jsonify(error=GENERIC_AUTH_ERROR), 401

        failures.pop(key, None)
        token = secrets.token_urlsafe(32)   # new token on every login
        sessions[token] = {"user": username.lower(), "created": now(), "last_seen": now()}
        resp = jsonify(message="Logged in.")
        set_session_cookie(resp, token, app.config["SESSION_MAX_SECONDS"])
        return resp

    @app.get("/me")
    def me():
        user = current_user()
        if not user:
            return jsonify(error="Not authenticated."), 401
        return jsonify(username=user)

    @app.post("/logout")
    def logout():
        token = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        sessions.pop(token, None)           # invalidate on the server
        resp = jsonify(message="Logged out.")
        set_session_cookie(resp, "", 0)     # and clear the cookie in the browser
        return resp

    return app


if __name__ == "__main__":
    # Local only. Use INSECURE_DEV=1 so the Secure cookie works over plain http.
    create_app().run(host="127.0.0.1", port=5000)
