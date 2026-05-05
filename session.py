# session.py
# Session lifecycle — creation, timeout checks, idle reset.

import time
from datetime import datetime
from config import SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS
from audit import log_action
from logger import debug, info


def fmt_time(iso_str):
    # Turns "2026-05-02T15:44:57.123456" into "2026-05-02 15:44:57" for display.
    try:
        return datetime.fromisoformat(iso_str).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso_str


def make_session(db_row, password):
    username, pw_hash, role, public_key, private_key = db_row
    now = time.time()
    debug("session", "make_session", f"{username} ({role})")
    return {
        "username":      username,
        "role":          role,
        "public_key":    public_key,
        "private_key":   private_key,  # still encrypted — needs password to use
        "password":      password,      # lives in memory for session duration only
        "login_time":    now,
        "last_activity": now
    }


def touch_session(session):
    session["last_activity"] = time.time()


def check_session(session):
    now = time.time()
    idle = now - session["last_activity"]
    total = now - session["login_time"]

    debug("session", "check_session", f"idle={int(idle)}s total={int(total)}s")

    if idle >= SESSION_IDLE_SECONDS:
        print(f"\n  [!] Session timed out after {int(idle)}s idle. Logging out.\n")
        log_action(session["username"], "session_expired_idle", f"idle={int(idle)}s")
        return False

    if total >= SESSION_MAX_SECONDS:
        print(f"\n  [!] Session reached the {SESSION_MAX_SECONDS}s limit. Logging out.\n")
        log_action(session["username"], "session_expired_max", f"total={int(total)}s")
        return False

    return True


def session_time_remaining(session):
    now = time.time()
    idle_left = SESSION_IDLE_SECONDS - (now - session["last_activity"])
    total_left = SESSION_MAX_SECONDS - (now - session["login_time"])
    return f"{max(0, int(min(idle_left, total_left)))}s left"