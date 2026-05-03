# =============================================================
# session.py -- Session Management
# =============================================================
# Handles session creation timing, expiry checks (idle + absolute),
# and the shared fmt_time() helper used across all display functions.
# =============================================================

import time
from config import SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS
from audit import log_action
from logger import debug, info


def fmt_time(iso_str):
    # Convert a raw ISO 8601 DB timestamp to a clean readable format.
    # "2026-05-02T15:44:57.123456" -> "2026-05-02 15:44:57"
    # Falls back to the raw string if parsing fails.
    from datetime import datetime
    try:
        return datetime.fromisoformat(iso_str).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso_str


def make_session(db_row, password):
    # Build a session dict from a DB user row.
    # login_time and last_activity both start at the moment of login.
    username, pw_hash, role, public_key, private_key = db_row
    now = time.time()
    debug("session", "make_session",
          f"Creating session for {username} ({role})")
    return {
        "username":      username,
        "role":          role,
        "public_key":    public_key,
        "private_key":   private_key,   # still passphrase-encrypted -- safe in memory
        "password":      password,       # held in memory for session only, never re-stored
        "login_time":    now,            # used for absolute session timeout
        "last_activity": now             # reset after every action (idle timeout)
    }


def touch_session(session):
    # Reset the idle timer after any user action.
    # Call this at the end of every successful menu operation.
    session["last_activity"] = time.time()
    debug("session", "touch_session",
          f"Idle timer reset for {session['username']}")


def check_session(session):
    # Check whether the current session is still valid.
    # Two independent expiry conditions -- either one triggers logout:
    #   1. Idle timeout  : no action within SESSION_IDLE_SECONDS
    #   2. Absolute limit: session older than SESSION_MAX_SECONDS
    # Returns True if valid, False if expired.
    now           = time.time()
    idle_elapsed  = now - session["last_activity"]
    total_elapsed = now - session["login_time"]

    debug("session", "check_session",
          f"idle={int(idle_elapsed)}s / {SESSION_IDLE_SECONDS}s  "
          f"total={int(total_elapsed)}s / {SESSION_MAX_SECONDS}s")

    if idle_elapsed >= SESSION_IDLE_SECONDS:
        info("session", "check_session",
             f"Session expired (idle) for {session['username']}",
             f"idle={int(idle_elapsed)}s")
        print(f"\n  [!] Session expired: idle for {int(idle_elapsed)}s "
              f"(limit: {SESSION_IDLE_SECONDS}s). Logging out.\n")
        log_action(session["username"], "session_expired_idle",
                   f"idle={int(idle_elapsed)}s")
        return False

    if total_elapsed >= SESSION_MAX_SECONDS:
        info("session", "check_session",
             f"Session expired (max) for {session['username']}",
             f"total={int(total_elapsed)}s")
        print(f"\n  [!] Session expired: max session time reached "
              f"({int(total_elapsed)}s). Logging out.\n")
        log_action(session["username"], "session_expired_max",
                   f"total={int(total_elapsed)}s")
        return False

    return True


def session_time_remaining(session):
    # Return a short string showing the minimum time left before expiry.
    # Displayed in every menu header so the user is never surprised.
    now        = time.time()
    idle_left  = SESSION_IDLE_SECONDS - (now - session["last_activity"])
    total_left = SESSION_MAX_SECONDS  - (now - session["login_time"])
    remaining  = max(0, int(min(idle_left, total_left)))
    return f"{remaining}s left"