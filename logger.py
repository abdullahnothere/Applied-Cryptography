# logger.py
# Four log levels. DEBUG only fires when DEBUG=1 in .env.
# Set it to 0 before taking screenshots.

from config import DEBUG


def _fmt(level, module, func, message, detail=""):
    base = f"  [{level:<5}]  {module}.{func:<30}  |  {message}"
    return base + f"  |  {detail}" if detail else base


def debug(module, func, message, detail=""):
    if DEBUG:
        print(_fmt("DEBUG", module, func, message, detail))


def info(module, func, message, detail=""):
    print(_fmt("INFO ", module, func, message, detail))


def warn(module, func, message, detail=""):
    print(_fmt("WARN ", module, func, message, detail))


def error(module, func, message, detail=""):
    print(_fmt("ERROR", module, func, message, detail))