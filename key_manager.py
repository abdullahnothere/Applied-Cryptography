# =============================================================
# key_manager.py -- Master Data Key (MDK) Management
# =============================================================
# Implements the platform key hierarchy:
#
#   ROOT_KEY (.env)
#       └── encrypts/decrypts the MDK stored in the database
#               └── wraps per-dataset AES keys (PDKs)
#                       └── encrypts patient datasets
#
#   Researchers get the MDK wrapped with their RSA public key.
#   Decrypt flow for a researcher:
#     RSA private key -> unwrap MDK -> unwrap PDK -> decrypt dataset
#
# Why this design?
#   - Clinicians can upload datasets even before any researchers exist
#   - When a researcher registers, they automatically get MDK access
#   - Individual researchers can be revoked by deleting their mdk_wrappers row
#   - The MDK itself is never stored in plaintext -- always encrypted with ROOT_KEY
#
# Trade-off acknowledged:
#   A compromised researcher's private key exposes the MDK and all datasets.
#   This is the fundamental tension between group key convenience and isolation.
#   Mitigation: strong per-user password protection on private keys.
# =============================================================

from datetime import datetime, timezone
from base64 import b64encode, b64decode

from Crypto.Random import get_random_bytes

from config import ROOT_KEY
from database import get_conn
from crypto_utils import aes_encrypt, aes_decrypt, rsa_wrap_key, rsa_unwrap_key
from logger import debug, info, warn


def generate_mdk():
    # Generate a new 32-byte (256-bit) Master Data Key.
    # Called once on first startup when no MDK exists in the DB.
    mdk = get_random_bytes(32)
    debug("key_manager", "generate_mdk",
          "Generated new MDK", f"mdk_preview={mdk.hex()[:8]}...")
    return mdk


def store_mdk(mdk):
    # Encrypt the MDK with the ROOT_KEY and persist it to the database.
    # ROOT_KEY comes from .env -- never stored in the DB.
    # This is the "Key Encryption Key" (KEK) pattern.
    debug("key_manager", "store_mdk", "Encrypting MDK with ROOT_KEY")

    iv_b64, encrypted_mdk_b64 = aes_encrypt(mdk, ROOT_KEY)
    ## The MDK is AES-encrypted using the ROOT_KEY before storage.
    ## Without the ROOT_KEY, the stored encrypted_mdk is useless.

    timestamp = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    conn = get_conn()
    conn.execute(
        "INSERT INTO platform_keys (encrypted_mdk, iv, created_at) VALUES (?,?,?)",
        (encrypted_mdk_b64, iv_b64, timestamp)
    )
    conn.commit()
    conn.close()
    info("key_manager", "store_mdk", "MDK encrypted and stored in platform_keys")


def load_mdk():
    # Retrieve and decrypt the MDK from the database.
    # Returns the raw 32-byte MDK, or None if no MDK exists yet.
    debug("key_manager", "load_mdk", "Loading MDK from database")

    conn = get_conn()
    row = conn.execute(
        "SELECT encrypted_mdk, iv FROM platform_keys ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if not row:
        warn("key_manager", "load_mdk", "No MDK found in database")
        return None

    encrypted_mdk_b64, iv_b64 = row
    mdk = aes_decrypt(iv_b64, encrypted_mdk_b64, ROOT_KEY)
    ## AES-decrypt using ROOT_KEY -- this only works if ROOT_KEY matches
    ## what was used when store_mdk() was called.

    debug("key_manager", "load_mdk",
          "MDK decrypted successfully", f"mdk_preview={mdk.hex()[:8]}...")
    return mdk


def ensure_mdk_exists():
    # Called at startup. Creates the MDK if one doesn't exist yet.
    # Safe to call every time -- only generates if truly absent.
    mdk = load_mdk()
    if mdk is None:
        info("key_manager", "ensure_mdk_exists",
             "No MDK found -- generating platform MDK for the first time")
        mdk = generate_mdk()
        store_mdk(mdk)
    else:
        debug("key_manager", "ensure_mdk_exists", "MDK already exists")
    return mdk


def wrap_mdk_for_researcher(researcher_username, researcher_public_key_pem):
    # Give a researcher access to the MDK by wrapping it with their RSA public key.
    # Called automatically when a new researcher registers.
    # The wrapped copy is stored in mdk_wrappers -- one row per researcher.
    debug("key_manager", "wrap_mdk_for_researcher",
          f"Wrapping MDK for {researcher_username}")

    mdk = load_mdk()
    if mdk is None:
        warn("key_manager", "wrap_mdk_for_researcher",
             "MDK not found -- cannot wrap for researcher")
        return False

    wrapped_mdk = rsa_wrap_key(mdk, researcher_public_key_pem)
    ## MDK encrypted with researcher's RSA public key.
    ## Only this researcher's private key can unwrap it.

    conn = get_conn()
    # Use INSERT OR REPLACE so re-registration doesn't fail with a duplicate error
    conn.execute(
        "INSERT OR REPLACE INTO mdk_wrappers (researcher_username, wrapped_mdk) VALUES (?,?)",
        (researcher_username, wrapped_mdk)
    )
    conn.commit()
    conn.close()

    info("key_manager", "wrap_mdk_for_researcher",
         f"MDK wrapped and stored for {researcher_username}")
    return True


def get_mdk_for_researcher(researcher_username, private_key_obj):
    # Retrieve and unwrap the MDK for a specific researcher.
    # Requires their RSA private key object (unlocked from session).
    # Returns the raw MDK bytes, or None if no wrapper found.
    debug("key_manager", "get_mdk_for_researcher",
          f"Fetching wrapped MDK for {researcher_username}")

    conn = get_conn()
    row = conn.execute(
        "SELECT wrapped_mdk FROM mdk_wrappers WHERE researcher_username=?",
        (researcher_username,)
    ).fetchone()
    conn.close()

    if not row:
        warn("key_manager", "get_mdk_for_researcher",
             f"No MDK wrapper found for {researcher_username}")
        return None

    mdk = rsa_unwrap_key(row[0], private_key_obj)
    debug("key_manager", "get_mdk_for_researcher",
          f"MDK unwrapped for {researcher_username}")
    return mdk


def wrap_dataset_key(pdk):
    # Wrap a per-dataset AES key (PDK) with the MDK.
    # Called during clinician upload -- the PDK is never stored raw.
    # Decrypt flow: MDK -> unwrap PDK -> decrypt dataset.
    debug("key_manager", "wrap_dataset_key",
          f"Wrapping {len(pdk)}-byte PDK with MDK")

    mdk = load_mdk()
    if mdk is None:
        raise RuntimeError("MDK not available -- cannot wrap dataset key")

    iv_b64, wrapped_pdk_b64 = aes_encrypt(pdk, mdk)
    ## AES-encrypt the PDK using the MDK.
    ## This is symmetric key wrapping -- both keys are AES-256.

    debug("key_manager", "wrap_dataset_key", "PDK wrapped with MDK")
    return iv_b64, wrapped_pdk_b64


def unwrap_dataset_key(wrapped_pdk_b64, pdk_iv_b64, researcher_username, private_key_obj):
    # Unwrap a per-dataset key for a researcher.
    # The researcher uses their private key to get the MDK,
    # then uses the MDK to unwrap the PDK.
    debug("key_manager", "unwrap_dataset_key",
          f"Unwrapping dataset key for {researcher_username}")

    mdk = get_mdk_for_researcher(researcher_username, private_key_obj)
    if mdk is None:
        return None

    pdk = aes_decrypt(pdk_iv_b64, wrapped_pdk_b64, mdk)
    ## AES-decrypt the wrapped PDK using the MDK

    debug("key_manager", "unwrap_dataset_key",
          "Dataset key unwrapped successfully")
    return pdk