# audit.py
# Tamper-evident audit log.
# Every entry is HMAC-signed on write. Auditors re-derive the tag on read
# to catch any rows that were modified after the fact.

import hmac
import hashlib
from datetime import datetime, timezone

from config import AUDIT_HMAC_KEY
from database import get_conn
from logger import debug


def log_action(actor, action, detail=""):
    timestamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    # The HMAC covers all four fields joined together.
    # Changing any one of them invalidates the tag.
    raw = f"{timestamp}|{actor}|{action}|{detail}"
    mac = hmac.new(AUDIT_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()

    debug("audit", "log_action", f"{actor} -> {action}")

    conn = get_conn()
    conn.execute(
        "INSERT INTO audit_log (timestamp, actor, action, detail, hmac) VALUES (?,?,?,?,?)",
        (timestamp, actor, action, detail, mac)
    )
    conn.commit()
    conn.close()


def verify_log_entry(entry):
    raw = f"{entry['timestamp']}|{entry['actor']}|{entry['action']}|{entry['detail']}"
    expected = hmac.new(AUDIT_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()
    # compare_digest is constant-time — prevents timing-based HMAC guessing.
    return hmac.compare_digest(expected, entry["hmac"])