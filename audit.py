# =============================================================
# audit.py -- Tamper-Evident Audit Logging
# =============================================================
# Every significant action in the platform writes a record here.
# Each record is HMAC-signed before storage so auditors can detect
# if entries were modified or deleted after the fact.
#
# GDPR Article 5(2) requires accountability -- this log provides it.
# =============================================================

import hmac
import hashlib
from datetime import datetime, timezone

from config import AUDIT_HMAC_KEY
from database import get_conn
from logger import debug


def log_action(actor, action, detail=""):
    # Write a tamper-evident entry to the audit log.
    #
    # The HMAC is computed over the full entry string:
    #   "timestamp|actor|action|detail"
    # Changing any one of those fields invalidates the HMAC.
    timestamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    raw = f"{timestamp}|{actor}|{action}|{detail}"
    mac = hmac.new(AUDIT_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()
    ## hmac.new() uses AUDIT_HMAC_KEY from .env -- never stored in the DB

    debug("audit", "log_action",
          f"Writing log entry: {actor} -> {action}", detail[:40])

    conn = get_conn()
    conn.execute(
        "INSERT INTO audit_log (timestamp, actor, action, detail, hmac) VALUES (?,?,?,?,?)",
        (timestamp, actor, action, detail, mac)
    )
    conn.commit()
    conn.close()


def verify_log_entry(entry):
    # Re-derive the HMAC for a log row and compare with what's stored.
    # Returns True if the entry is intact, False if it was modified.
    #
    # hmac.compare_digest() is constant-time -- this prevents timing attacks
    # where an attacker could guess the HMAC byte-by-byte based on response time.
    raw      = f"{entry['timestamp']}|{entry['actor']}|{entry['action']}|{entry['detail']}"
    expected = hmac.new(AUDIT_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()

    result = hmac.compare_digest(expected, entry["hmac"])
    debug("audit", "verify_log_entry",
          f"Entry integrity: {'VALID' if result else 'TAMPERED'}")
    return result