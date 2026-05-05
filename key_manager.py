# key_manager.py
# Manages the Master Data Key (MDK) and everything that touches it.
#
# Key hierarchy:
#   ROOT_KEY (.env) -> encrypts MDK in DB -> wraps per-dataset PDKs -> patient data
#
# Researchers get an RSA-wrapped copy of the MDK on registration, which lets
# them decrypt any dataset regardless of when it was uploaded. The trade-off
# is that a compromised researcher key exposes the MDK — documented in the report.

from datetime import datetime, timezone
from base64 import b64encode, b64decode

from Crypto.Random import get_random_bytes

from config import ROOT_KEY
from database import get_conn
from crypto_utils import aes_encrypt, aes_decrypt, rsa_wrap_key, rsa_unwrap_key
from logger import debug, info, warn


def generate_mdk():
    mdk = get_random_bytes(32)
    debug("key_manager", "generate_mdk", "new MDK generated")
    return mdk


def store_mdk(mdk):
    # Encrypt before touching the DB — ROOT_KEY never leaves memory.
    iv_b64, encrypted_mdk_b64 = aes_encrypt(mdk, ROOT_KEY)
    timestamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    conn = get_conn()
    conn.execute(
        "INSERT INTO platform_keys (encrypted_mdk, iv, created_at) VALUES (?,?,?)",
        (encrypted_mdk_b64, iv_b64, timestamp)
    )
    conn.commit()
    conn.close()
    info("key_manager", "store_mdk", "MDK stored (encrypted)")


def load_mdk():
    conn = get_conn()
    row = conn.execute(
        "SELECT encrypted_mdk, iv FROM platform_keys ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if not row:
        warn("key_manager", "load_mdk", "no MDK in database")
        return None

    encrypted_mdk_b64, iv_b64 = row
    mdk = aes_decrypt(iv_b64, encrypted_mdk_b64, ROOT_KEY)
    debug("key_manager", "load_mdk", "MDK decrypted OK")
    return mdk


def ensure_mdk_exists():
    # Called at startup — only generates if the table is empty.
    mdk = load_mdk()
    if mdk is None:
        info("key_manager", "ensure_mdk_exists", "first run — generating MDK")
        mdk = generate_mdk()
        store_mdk(mdk)
    return mdk


def wrap_mdk_for_researcher(researcher_username, researcher_public_key_pem):
    # Gives a researcher their own encrypted copy of the MDK.
    # One row per researcher in mdk_wrappers. Revoking = deleting that row.
    mdk = load_mdk()
    if mdk is None:
        warn("key_manager", "wrap_mdk_for_researcher", "MDK missing — cannot wrap")
        return False

    wrapped_mdk = rsa_wrap_key(mdk, researcher_public_key_pem)

    conn = get_conn()
    # INSERT OR REPLACE handles re-registration gracefully
    conn.execute(
        "INSERT OR REPLACE INTO mdk_wrappers (researcher_username, wrapped_mdk) VALUES (?,?)",
        (researcher_username, wrapped_mdk)
    )
    conn.commit()
    conn.close()

    info("key_manager", "wrap_mdk_for_researcher", f"MDK wrapped for {researcher_username}")
    return True


def get_mdk_for_researcher(researcher_username, private_key_obj):
    conn = get_conn()
    row = conn.execute(
        "SELECT wrapped_mdk FROM mdk_wrappers WHERE researcher_username=?",
        (researcher_username,)
    ).fetchone()
    conn.close()

    if not row:
        warn("key_manager", "get_mdk_for_researcher", f"no wrapper found for {researcher_username}")
        return None

    mdk = rsa_unwrap_key(row[0], private_key_obj)
    debug("key_manager", "get_mdk_for_researcher", f"MDK unwrapped for {researcher_username}")
    return mdk


def wrap_dataset_key(pdk):
    # PDK is AES-encrypted with the MDK before going into the DB.
    # The raw PDK only ever lives in memory during an upload.
    mdk = load_mdk()
    if mdk is None:
        raise RuntimeError("MDK unavailable — cannot wrap dataset key")

    iv_b64, wrapped_pdk_b64 = aes_encrypt(pdk, mdk)
    debug("key_manager", "wrap_dataset_key", f"PDK wrapped ({len(pdk)} bytes)")
    return iv_b64, wrapped_pdk_b64


def unwrap_dataset_key(wrapped_pdk_b64, pdk_iv_b64, researcher_username, private_key_obj):
    # Full chain: researcher private key -> MDK -> PDK
    mdk = get_mdk_for_researcher(researcher_username, private_key_obj)
    if mdk is None:
        return None

    pdk = aes_decrypt(pdk_iv_b64, wrapped_pdk_b64, mdk)
    debug("key_manager", "unwrap_dataset_key", "PDK recovered")
    return pdk
    