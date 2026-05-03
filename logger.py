# =============================================================
# logger.py -- Debug Logging Wrapper
# =============================================================
# Provides four log levels: DEBUG, INFO, WARN, ERROR.
#
# DEBUG messages are only printed when DEBUG=1 in .env.
# INFO / WARN / ERROR always print regardless of the flag.
#
# Usage in any module:
#   from logger import debug, info, warn, error
#
#   debug("crypto_utils", "aes_encrypt", "Generated IV", iv.hex())
#   info("auth", "register_user", f"New account: {username}")
#   warn("key_manager", "get_mdk", "No MDK found in DB -- will generate")
#   error("database", "get_conn", str(e))
# =============================================================

from config import DEBUG


def _fmt(level, module, func, message, detail=""):
    # Build a consistent log line:
    #   [LEVEL]  module.func  |  message  |  detail
    base = f"  [{level:<5}]  {module}.{func:<30}  |  {message}"
    if detail:
        base += f"  |  {detail}"
    return base


def debug(module, func, message, detail=""):
    # Only prints when DEBUG=1 in .env.
    # Use for step-by-step crypto operations, key derivations, DB reads/writes.
    if DEBUG:
        print(_fmt("DEBUG", module, func, message, detail))


def info(module, func, message, detail=""):
    # Always prints. Use for significant state changes: login, upload, sign, verify.
    print(_fmt("INFO ", module, func, message, detail))


def warn(module, func, message, detail=""):
    # Always prints. Use for non-fatal issues: missing optional config, fallbacks.
    print(_fmt("WARN ", module, func, message, detail))


def error(module, func, message, detail=""):
    # Always prints. Use for failures: DB errors, decryption failures, bad input.
    print(_fmt("ERROR", module, func, message, detail))