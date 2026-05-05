# config.py
# Loads .env and exposes everything as typed constants.
# All other modules import from here — change a value once, applies everywhere.

import os
from pathlib import Path


def _load_env(env_path=".env"):
    env_file = Path(env_path)
    if not env_file.exists():
        env_file = Path(__file__).parent / env_path

    if not env_file.exists():
        print(f"  [WARN] .env not found at {env_file.resolve()} — using env vars")
        return

    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            # Don't overwrite values already set in the actual environment
            if key and key not in os.environ:
                os.environ[key] = value


_load_env()


def _require_hex_key(name, length_bytes):
    # Validates at startup so a missing key fails loudly instead of
    # producing a confusing error deep in a crypto function.
    hex_val = os.environ.get(name, "")
    if not hex_val:
        raise EnvironmentError(
            f"'{name}' is missing from .env. "
            f"Generate one: python3 -c \"import os; print(os.urandom({length_bytes}).hex())\""
        )
    try:
        key_bytes = bytes.fromhex(hex_val)
    except ValueError:
        raise EnvironmentError(f"'{name}' in .env is not valid hex.")

    if len(key_bytes) != length_bytes:
        raise EnvironmentError(
            f"'{name}' must be {length_bytes} bytes ({length_bytes * 2} hex chars), "
            f"got {len(key_bytes)}."
        )
    return key_bytes


ROOT_KEY       = _require_hex_key("ROOT_KEY", 32)
AUDIT_HMAC_KEY = _require_hex_key("AUDIT_HMAC_KEY", 32)

DB_PATH = os.environ.get("DB_PATH", "clinical_platform.db")

DEBUG = os.environ.get("DEBUG", "0").strip() == "1"

SESSION_IDLE_SECONDS = int(os.environ.get("SESSION_IDLE_SECONDS", "300"))
SESSION_MAX_SECONDS  = int(os.environ.get("SESSION_MAX_SECONDS", "3600"))

VALID_ROLES = ("researcher", "clinician", "auditor")

RSA_KEY_BITS = 2048  # UPGRADE: 3072 for deployments beyond 2030