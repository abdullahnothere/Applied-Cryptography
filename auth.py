# =============================================================
# auth.py -- Authentication and User Registration
# =============================================================
# Handles user registration and login.
# Password hashing uses bcrypt (auto-salted, intentionally slow).
# Private keys are passphrase-encrypted before DB storage.
# =============================================================

import bcrypt
from config import VALID_ROLES
from database import get_conn
from crypto_utils import generate_rsa_keypair, export_private_key_encrypted
from key_manager import wrap_mdk_for_researcher
from audit import log_action
from session import make_session
from logger import debug, info, warn, error


def register_user(username, password, role):
    # Register a new user account.
    #
    # Steps:
    #   1. Validate inputs
    #   2. Hash password with bcrypt
    #   3. Generate RSA-2048 key pair
    #   4. Encrypt private key with user's password (PBKDF2+AES128)
    #   5. Store everything in the users table
    #   6. If researcher, wrap MDK with their public key
    #
    # Returns (True, success_message) or (False, error_reason).

    debug("auth", "register_user", f"Attempting registration for '{username}' role='{role}'")

    # Input validation
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
        warn("auth", "register_user", f"Username '{username}' already exists")
        return False, "Username already exists."

    # Hash password with bcrypt.
    # bcrypt.gensalt() generates a unique random salt per user -- baked into the hash.
    # This prevents rainbow table attacks even if two users have the same password.
    # UPGRADE: Argon2id (Password Hashing Competition 2015 winner) gives stronger
    # GPU-cracking resistance and is preferred for new systems.
    debug("auth", "register_user", "Hashing password with bcrypt")
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Generate RSA key pair
    print("\n  [*] Generating RSA key pair... (this takes a moment)")
    debug("auth", "register_user", "Generating RSA key pair")
    private_key_bytes, public_key_bytes = generate_rsa_keypair()

    # Encrypt private key with user's password before storage.
    # DB read access alone is not enough -- attacker also needs the password.
    private_key_pem = export_private_key_encrypted(
        private_key_bytes, password.encode()
    )
    public_key_pem = public_key_bytes.decode()

    conn.execute(
        "INSERT INTO users (username, password_hash, role, public_key, private_key) VALUES (?,?,?,?,?)",
        (username, pw_hash, role, public_key_pem, private_key_pem)
    )
    conn.commit()
    conn.close()

    info("auth", "register_user",
         f"User '{username}' registered", f"role={role}")
    log_action("system", "user_registered", f"username={username} role={role}")

    # If this is a researcher, give them a wrapped copy of the MDK immediately.
    # This means they can decrypt any dataset uploaded before or after they registered.
    if role == "researcher":
        debug("auth", "register_user",
              f"Wrapping MDK for new researcher '{username}'")
        success = wrap_mdk_for_researcher(username, public_key_pem)
        if success:
            info("auth", "register_user",
                 f"MDK wrapped and granted to '{username}'")
        else:
            warn("auth", "register_user",
                 f"MDK wrap failed for '{username}' -- MDK may not exist yet")

    return True, "Account created successfully."


def login_user(username, password):
    # Authenticate a user and return a session dict on success.
    #
    # Returns None for both "not found" and "wrong password" -- deliberately
    # vague to prevent username enumeration attacks. An attacker cannot
    # distinguish "that username doesn't exist" from "wrong password".
    debug("auth", "login_user", f"Login attempt for '{username}'")

    conn = get_conn()
    row = conn.execute(
        "SELECT username, password_hash, role, public_key, private_key FROM users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()

    if not row:
        warn("auth", "login_user", f"Username '{username}' not found")
        return None

    db_username, pw_hash, role, public_key, private_key = row

    if not bcrypt.checkpw(password.encode(), pw_hash.encode()):
        ## bcrypt.checkpw() extracts the embedded salt from pw_hash automatically
        warn("auth", "login_user", f"Wrong password for '{username}'")
        return None

    info("auth", "login_user", f"Login successful for '{username}'", f"role={role}")
    log_action(username, "login", f"role={role}")

    return make_session(row, password)


def seed_test_accounts():
    # Create one account per role on first run -- skips if already exists.
    # These accounts exist purely for development and testing.
    #
    # Credentials (demo only -- use strong unique passwords in production):
    #   alice_researcher / ResearchPass1!
    #   bob_clinician    / ClinicPass1!
    #   carol_auditor    / AuditPass1!
    info("auth", "seed_test_accounts", "Seeding test accounts")
    accounts = [
        ("alice_researcher", "ResearchPass1!", "researcher"),
        ("bob_clinician",    "ClinicPass1!",   "clinician"),
        ("carol_auditor",    "AuditPass1!",    "auditor"),
    ]
    any_created = False
    for username, password, role in accounts:
        ok, msg = register_user(username, password, role)
        if ok:
            print(f"  [+] Test account created: {username:<22}  role={role}")
            any_created = True
    if any_created:
        print()