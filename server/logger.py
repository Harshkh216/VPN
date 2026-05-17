"""
logger.py - Centralised Logging for the VPN Server
Writes structured log entries to both a rotating file and stdout.
All modules import `get_logger(__name__)` to get a named logger.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR  = os.path.join(os.path.dirname(__file__), '..', 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'vpn_logs.txt')

# Ensure the logs directory exists at import time
os.makedirs(LOG_DIR, exist_ok=True)

# ── Format ────────────────────────────────────────────────────────────────────
_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
_DATE   = "%Y-%m-%d %H:%M:%S"

# ── Root logger setup (called once) ──────────────────────────────────────────
def _configure_root():
    root = logging.getLogger("vpn")
    if root.handlers:
        return  # Already configured

    root.setLevel(logging.DEBUG)

    # File handler — rotates at 5 MB, keeps 3 backup files
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3,
                             encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(_FORMAT, _DATE))

    # Console handler — INFO and above
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(_FORMAT, _DATE))

    root.addHandler(fh)
    root.addHandler(ch)

_configure_root()


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the 'vpn' namespace.
    Usage:  log = get_logger(__name__)
    """
    return logging.getLogger(f"vpn.{name}")


# ── Convenience shortcuts ─────────────────────────────────────────────────────
_server_log = get_logger("server")

def log_info(msg: str):    _server_log.info(msg)
def log_warning(msg: str): _server_log.warning(msg)
def log_error(msg: str):   _server_log.error(msg)
def log_debug(msg: str):   _server_log.debug(msg)


def read_log_tail(lines: int = 200) -> str:
    """
    Read the last `lines` lines of the log file as a single string.
    Used by the server GUI to populate the log panel.
    """
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
        return "".join(all_lines[-lines:])
    except FileNotFoundError:
        return "(log file not yet created)"