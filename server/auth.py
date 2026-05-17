"""
auth.py - Authentication Manager for VPN Server
Wraps database calls with security policy logic:
  - Brute-force lockout (5 failed attempts → 5-min ban)
  - Session lifecycle management
  - Role-based access checks
"""

from __future__ import annotations
from . import database as db

# Maximum failed attempts before temporary lockout
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 300   # 5-minute sliding window
SESSION_DURATION = 3600        # 1-hour sessions


class AuthError(Exception):
    """Raised when authentication or authorisation fails."""


class AuthManager:
    """Stateless authentication helper used by the VPN server."""

    # ── Initialise ────────────────────────────────────────────────────────────

    @staticmethod
    def setup():
        """Ensure the database schema and default admin exist."""
        db.initialize_db()

    # ── Registration ──────────────────────────────────────────────────────────

    @staticmethod
    def register(username: str, password: str, role: str = "user") -> bool:
        """
        Register a new user.
        Returns True on success; raises AuthError if the username is taken.
        """
        if len(username) < 3 or len(password) < 6:
            raise AuthError("Username ≥ 3 chars and password ≥ 6 chars required.")
        ok = db.register_user(username, password, role)
        if not ok:
            raise AuthError(f"Username '{username}' is already taken.")
        return True

    # ── Login ─────────────────────────────────────────────────────────────────

    @staticmethod
    def login(username: str, password: str, ip: str) -> str:
        """
        Authenticate a user and return a session token.

        Flow:
          1. Check brute-force lockout.
          2. Verify credentials.
          3. Log the attempt.
          4. Create and return a session token.

        Raises AuthError on any failure.
        """
        # Step 1: Brute-force protection
        failed = db.count_failed_attempts(username, LOCKOUT_WINDOW_SECONDS)
        if failed >= MAX_FAILED_ATTEMPTS:
            raise AuthError(
                f"Account temporarily locked after {MAX_FAILED_ATTEMPTS} failed attempts. "
                f"Try again in {LOCKOUT_WINDOW_SECONDS // 60} minutes."
            )

        # Step 2: Verify credentials
        valid = db.authenticate_user(username, password)
        db.log_login_attempt(username, ip, valid)  # Step 3: Always log

        if not valid:
            remaining = MAX_FAILED_ATTEMPTS - (failed + 1)
            raise AuthError(
                f"Invalid credentials. {max(remaining, 0)} attempts remaining."
            )

        # Step 4: Create session
        token = db.create_session(username, ip, SESSION_DURATION)
        db.update_last_login(username)
        return token

    # ── Session validation ────────────────────────────────────────────────────

    @staticmethod
    def validate(token: str) -> str:
        """
        Validate a session token.
        Returns the username if valid; raises AuthError otherwise.
        """
        username = db.validate_session(token)
        if username is None:
            raise AuthError("Session expired or invalid. Please log in again.")
        return username

    # ── Logout ────────────────────────────────────────────────────────────────

    @staticmethod
    def logout(token: str):
        """Invalidate a session (explicit logout or server-side kick)."""
        db.invalidate_session(token)

    # ── Role checks ───────────────────────────────────────────────────────────

    @staticmethod
    def require_admin(username: str):
        """Raise AuthError if the user is not an admin."""
        user = db.get_user(username)
        if not user or user.get("role") != "admin":
            raise AuthError("Admin privileges required.")

    # ── Admin actions ─────────────────────────────────────────────────────────

    @staticmethod
    def ban_user(admin_username: str, target_username: str):
        """Ban a user account. Only admins may do this."""
        AuthManager.require_admin(admin_username)
        db.ban_user(target_username)

    @staticmethod
    def list_users(admin_username: str) -> list:
        """Return all user records. Only admins may call this."""
        AuthManager.require_admin(admin_username)
        return db.get_all_users()
