# =============================================================
# config.py -- Configuration Loader
# =============================================================
# Reads the .env file and exposes every setting as a typed
# Python constant. All other modules import from here instead
# of reading .env directly -- one place to change everything.
#
# We parse .env manually to avoid a python-dotenv dependency.
# UPGRADE: Replace the manual parser with python-dotenv if the
#          project grows to need variable interpolation or comments
#          in values.
# =============================================================

import os
from pathlib import Path

def _load_env(env_path=".env"):
    # Walk up from the current working directory to find the .env file.
    # This means the project can be run from any subdirectory.
    env_file = Path(env_path)
    if not env_file.exists():
        # Try finding it relative to this config.py file's location
        env_file = Path(__file__).parent / env_path

    if not env_file.exists():
        print(f"  [WARN] .env file not found at {env_file.resolve()}")
        print("  [WARN] Falling back to environment variables / defaults.")
        return

    with open(env_file) as f:
        for line in f:
            line = line.strip()
            # Skip blank lines and comments
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key   = key.strip()
            value = value.strip()
            # Only set if not already present -- env vars override .env
            if key and key not in os.environ:
                os.environ[key] = value


# Load the .env file before reading anything
_load_env()


# -------------------------------------------------------------
# Cryptographic settings
# -------------------------------------------------------------

def _require_hex_key(name, length_bytes):
    # Pull a hex-encoded key from env and decode it to bytes.
    # Raises a clear error if missing or wrong length -- better than a
    # cryptic downstream failure.
    hex_val = os.environ.get(name, "")
    if not hex_val:
        raise EnvironmentError(
            f"[config] Required key '{name}' is missing from .env. "
            f"Generate one with: python3 -c \"import os; print(os.urandom({length_bytes}).hex())\""
        )
    try:
        key_bytes = bytes.fromhex(hex_val)
    except ValueError:
        raise EnvironmentError(f"[config] '{name}' in .env is not valid hex.")

    if len(key_bytes) != length_bytes:
        raise EnvironmentError(
            f"[config] '{name}' must be {length_bytes} bytes ({length_bytes * 2} hex chars). "
            f"Got {len(key_bytes)} bytes."
        )
    return key_bytes


# ROOT_KEY: AES-256 key that encrypts the Master Data Key in the database.
# This is the top of the key hierarchy. Losing it means losing access to all data.
ROOT_KEY = _require_hex_key("ROOT_KEY", 32)

# AUDIT_HMAC_KEY: HMAC-SHA256 key for signing audit log entries.
AUDIT_HMAC_KEY = _require_hex_key("AUDIT_HMAC_KEY", 32)


# -------------------------------------------------------------
# Database
# -------------------------------------------------------------

DB_PATH = os.environ.get("DB_PATH", "clinical_platform.db")


# -------------------------------------------------------------
# Debug logging
# -------------------------------------------------------------

# Set DEBUG=1 in .env to enable step-by-step verbose output.
# Set DEBUG=0 (or omit) for clean production output.
DEBUG = os.environ.get("DEBUG", "0").strip() == "1"


# -------------------------------------------------------------
# Session timeouts
# -------------------------------------------------------------

SESSION_IDLE_SECONDS = int(os.environ.get("SESSION_IDLE_SECONDS", "300"))
SESSION_MAX_SECONDS  = int(os.environ.get("SESSION_MAX_SECONDS",  "3600"))


# -------------------------------------------------------------
# Role definitions
# -------------------------------------------------------------

# Centralised so adding a new role only requires a change here
VALID_ROLES = ("researcher", "clinician", "auditor")

# -------------------------------------------------------------
# RSA key size
# -------------------------------------------------------------

RSA_KEY_BITS = 2048
# UPGRADE: Change to 3072 for post-2030 deployments per NIST SP 800-131A Rev 2