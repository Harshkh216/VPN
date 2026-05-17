"""
database.py - SQLite Database Manager for VPN Server
Handles user registration, authentication, session tracking, and connection history.
"""

import sqlite3
import hashlib
import os
import time
from datetime import datetime


DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'users.db')


def get_connection():
    """Return a new SQLite connection to the users database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allow dict-like access
    return conn


def initialize_db():
    """
    Create all required tables if they don't already exist.
    Tables: users, sessions, connection_history, login_attempts
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Users table: stores credentials and metadata
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,          -- SHA-256 hashed
            salt        TEXT NOT NULL,
            role        TEXT DEFAULT 'user',    -- 'admin' or 'user'
            created_at  TEXT NOT NULL,
            last_login  TEXT,
            is_active   INTEGER DEFAULT 1       -- 1=active, 0=banned
        )
    """)

    # Sessions table: active/expired session tokens
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            token       TEXT UNIQUE NOT NULL,
            ip_address  TEXT,
            created_at  TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            is_active   INTEGER DEFAULT 1
        )
    """)

    # Connection history: log every connect/disconnect
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connection_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT NOT NULL,
            ip_address   TEXT,
            connected_at TEXT NOT NULL,
            disconnected_at TEXT,
            bytes_sent   INTEGER DEFAULT 0,
            bytes_recv   INTEGER DEFAULT 0
        )
    """)

    # Login attempts: track failed logins for brute-force detection
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            ip_address  TEXT,
            attempted_at TEXT NOT NULL,
            success     INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()

    # Seed default admin account if not present
    _seed_admin()


def _hash_password(password: str, salt: str) -> str:
    """Return SHA-256 hex digest of password+salt."""
    return hashlib.sha256((password + salt).encode()).hexdigest()


def _seed_admin():
    """Create a default admin account on first run."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        salt = os.urandom(16).hex()
        hashed = _hash_password("admin123", salt)
        cursor.execute("""
            INSERT INTO users (username, password, salt, role, created_at)
            VALUES (?, ?, ?, 'admin', ?)
        """, ("admin", hashed, salt, datetime.now().isoformat()))
        conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def register_user(username: str, password: str, role: str = "user") -> bool:
    """
    Register a new user. Returns True on success, False if username exists.
    Passwords are salted and hashed before storage.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        salt = os.urandom(16).hex()
        hashed = _hash_password(password, salt)
        cursor.execute("""
            INSERT INTO users (username, password, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (username, hashed, salt, role, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already taken


def authenticate_user(username: str, password: str) -> bool:
    """
    Verify username and password. Returns True if credentials are valid
    and the account is active.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT password, salt, is_active FROM users WHERE username = ?
    """, (username,))
    row = cursor.fetchone()
    conn.close()

    if not row or not row["is_active"]:
        return False
    return _hash_password(password, row["salt"]) == row["password"]


def get_user(username: str) -> dict | None:
    """Return user record as a dict, or None if not found."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_last_login(username: str):
    """Stamp last_login timestamp for a user."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users SET last_login = ? WHERE username = ?
    """, (datetime.now().isoformat(), username))
    conn.commit()
    conn.close()


def log_login_attempt(username: str, ip: str, success: bool):
    """Record every login attempt for security auditing."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO login_attempts (username, ip_address, attempted_at, success)
        VALUES (?, ?, ?, ?)
    """, (username, ip, datetime.now().isoformat(), int(success)))
    conn.commit()
    conn.close()


def count_failed_attempts(username: str, window_seconds: int = 300) -> int:
    """
    Count failed login attempts for a user in the last `window_seconds`.
    Used to detect brute-force attacks.
    """
    conn = get_connection()
    cursor = conn.cursor()
    since = datetime.fromtimestamp(time.time() - window_seconds).isoformat()
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM login_attempts
        WHERE username = ? AND success = 0 AND attempted_at >= ?
    """, (username, since))
    count = cursor.fetchone()["cnt"]
    conn.close()
    return count


def create_session(username: str, ip: str, duration_seconds: int = 3600) -> str:
    """
    Generate and store a session token. Returns the token string.
    Default session duration: 1 hour.
    """
    token = os.urandom(32).hex()
    now = datetime.now().isoformat()
    expires = datetime.fromtimestamp(time.time() + duration_seconds).isoformat()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO sessions (username, token, ip_address, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (username, token, ip, now, expires))
    conn.commit()
    conn.close()
    return token


def validate_session(token: str) -> str | None:
    """
    Check if a session token is active and not expired.
    Returns username on success, None otherwise.
    """
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
        SELECT username FROM sessions
        WHERE token = ? AND is_active = 1 AND expires_at > ?
    """, (token, now))
    row = cursor.fetchone()
    conn.close()
    return row["username"] if row else None


def invalidate_session(token: str):
    """Mark a session as inactive (logout)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sessions SET is_active = 0 WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def log_connection(username: str, ip: str) -> int:
    """
    Record the start of a VPN connection. Returns the connection record ID
    so it can be updated on disconnect.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO connection_history (username, ip_address, connected_at)
        VALUES (?, ?, ?)
    """, (username, ip, datetime.now().isoformat()))
    conn.commit()
    conn_id = cursor.lastrowid
    conn.close()
    return conn_id


def close_connection_log(conn_id: int, bytes_sent: int = 0, bytes_recv: int = 0):
    """Update the connection record with disconnect time and traffic stats."""
    db = get_connection()
    cursor = db.cursor()
    cursor.execute("""
        UPDATE connection_history
        SET disconnected_at = ?, bytes_sent = ?, bytes_recv = ?
        WHERE id = ?
    """, (datetime.now().isoformat(), bytes_sent, bytes_recv, conn_id))
    db.commit()
    db.close()


def get_all_users() -> list:
    """Return all user records (admin use)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, role, created_at, last_login, is_active FROM users
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_connection_history(limit: int = 50) -> list:
    """Return recent connection history records."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM connection_history ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def ban_user(username: str):
    """Disable a user account (admin action)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = 0 WHERE username = ?", (username,))
    conn.commit()
    conn.close()