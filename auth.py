# auth.py
# Registration, login, and the initial test account seeding.

import bcrypt
from config import VALID_ROLES
from database import get_conn
from crypto_utils import generate_rsa_keypair, export_private_key_encrypted
from key_manager import wrap_mdk_for_researcher
from audit import log_action
from session import make_session
from logger import debug, info, warn


def register_user(username, password, role):
    if not username or not password or not role:
        return False, "All fields are required."
    if role not in VALID_ROLES:
        return False, f"Invalid role. Choose from: {', '.join(VALID_ROLES)}"
    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    conn = get_conn()
    existing = conn.execute(
        "SELECT id FROM users WHERE username=?", (username,)
    ).fetchone()

    if existing:
        conn.close()
        return False, "Username already exists."

    # bcrypt auto-generates a salt per user, so identical passwords produce
    # different hashes. UPGRADE: Argon2id is stronger against GPU cracking.
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    print("\n  [*] Generating RSA key pair... (this takes a moment)")
    private_key_bytes, public_key_bytes = generate_rsa_keypair()
    private_key_pem = export_private_key_encrypted(private_key_bytes, password.encode())
    public_key_pem = public_key_bytes.decode()

    conn.execute(
        "INSERT INTO users (username, password_hash, role, public_key, private_key) VALUES (?,?,?,?,?)",
        (username, pw_hash, role, public_key_pem, private_key_pem)
    )
    conn.commit()
    conn.close()

    log_action("system", "user_registered", f"username={username} role={role}")
    info("auth", "register_user", f"{username} registered", f"role={role}")

    # Researchers get an MDK wrapper immediately so they can decrypt existing datasets.
    if role == "researcher":
        ok = wrap_mdk_for_researcher(username, public_key_pem)
        if not ok:
            warn("auth", "register_user", f"MDK wrap failed for {username}")

    return True, "Account created successfully."


def login_user(username, password):
    # Same error for wrong username and wrong password — prevents username enumeration.
    conn = get_conn()
    row = conn.execute(
        "SELECT username, password_hash, role, public_key, private_key FROM users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()

    if not row:
        return None

    _, pw_hash, *_ = row
    if not bcrypt.checkpw(password.encode(), pw_hash.encode()):
        return None

    log_action(username, "login", f"role={row[2]}")
    info("auth", "login_user", f"{username} logged in")
    return make_session(row, password)


def seed_test_accounts():
    # Demo credentials — fine for testing, not for anything real.
    accounts = [
        ("alice", "ResearchPass1!", "researcher"),
        ("bob",    "ClinicPass1!",   "clinician"),
        ("abd",    "AuditPass1!",    "auditor"),
    ]
    for username, password, role in accounts:
        ok, _ = register_user(username, password, role)
        if ok:
            print(f"  [+] {username:<22}  role={role}")