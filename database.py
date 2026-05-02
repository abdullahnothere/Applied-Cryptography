# =============================================================
# database.py -- Database Initialisation and Connection
# =============================================================
# All table definitions live here. No business logic -- just
# schema creation and the get_conn() helper.
#
# SQLite is used for portability. In production, switch to
# PostgreSQL with encrypted storage at the infrastructure level
# (e.g. AWS RDS with encryption-at-rest enabled).
# =============================================================

import sqlite3
from config import DB_PATH
from logger import debug, info, warn


def get_conn():
    # Return a database connection.
    # Centralised here so DB_PATH is only specified in one place.
    debug("database", "get_conn", f"Opening connection to {DB_PATH}")
    return sqlite3.connect(DB_PATH)


def init_db():
    # Create all tables on first run.
    # Uses IF NOT EXISTS so this is safe to call on every startup.
    info("database", "init_db", "Initialising database schema")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ----------------------------------------------------------
    # platform_keys
    # Stores the Master Data Key (MDK) encrypted with the ROOT_KEY.
    # Only one row should ever exist -- the platform has one MDK.
    # UPGRADE: Add MDK versioning to support key rotation without
    #          re-encrypting all datasets at once.
    # ----------------------------------------------------------
    c.execute("""
        CREATE TABLE IF NOT EXISTS platform_keys (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_mdk   TEXT NOT NULL,
            iv              TEXT NOT NULL,
            created_at      TEXT NOT NULL
        )
    """)
    # encrypted_mdk : base64 AES-CBC ciphertext of the 32-byte MDK
    # iv            : base64 AES IV used when encrypting the MDK
    debug("database", "init_db", "Table ready: platform_keys")

    # ----------------------------------------------------------
    # mdk_wrappers
    # Each row gives one researcher their own RSA-encrypted copy
    # of the MDK. When a researcher joins, a new row is added.
    # Revoking a researcher = deleting their row.
    # ----------------------------------------------------------
    c.execute("""
        CREATE TABLE IF NOT EXISTS mdk_wrappers (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            researcher_username TEXT UNIQUE NOT NULL,
            wrapped_mdk         TEXT NOT NULL
        )
    """)
    # wrapped_mdk : MDK encrypted with this researcher's RSA public key (base64)
    debug("database", "init_db", "Table ready: mdk_wrappers")

    # ----------------------------------------------------------
    # users
    # Credentials and RSA key pairs per user.
    # ----------------------------------------------------------
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL,
            public_key    TEXT NOT NULL,
            private_key   TEXT NOT NULL
        )
    """)
    # role        : 'researcher' | 'clinician' | 'auditor'
    # public_key  : RSA public key PEM -- safe to store plaintext
    # private_key : RSA private key PEM -- encrypted with user's password via PBKDF2+AES
    debug("database", "init_db", "Table ready: users")

    # ----------------------------------------------------------
    # datasets
    # Encrypted patient data uploaded by clinicians.
    # Each dataset has its own per-dataset AES key (PDK).
    # The PDK is wrapped with the MDK -- so decrypting requires:
    #   RSA private key -> MDK -> PDK -> plaintext
    # ----------------------------------------------------------
    c.execute("""
        CREATE TABLE IF NOT EXISTS datasets (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            filename            TEXT NOT NULL,
            uploaded_by         TEXT NOT NULL,
            ciphertext          TEXT NOT NULL,
            iv                  TEXT NOT NULL,
            wrapped_dataset_key TEXT NOT NULL,
            uploaded_at         TEXT NOT NULL
        )
    """)
    # ciphertext          : base64 AES-CBC encrypted patient data
    # iv                  : base64 AES IV for the dataset ciphertext
    # wrapped_dataset_key : per-dataset AES key encrypted with the MDK (base64)
    debug("database", "init_db", "Table ready: datasets")

    # ----------------------------------------------------------
    # findings
    # Digitally signed research findings (RSA-PSS).
    # ----------------------------------------------------------
    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            researcher TEXT NOT NULL,
            content    TEXT NOT NULL,
            signature  TEXT NOT NULL,
            signed_at  TEXT NOT NULL
        )
    """)
    # signature : base64 RSA-PSS signature over content using researcher's private key
    debug("database", "init_db", "Table ready: findings")

    # ----------------------------------------------------------
    # audit_log
    # Tamper-evident record of every significant action.
    # HMAC-SHA256 on each row lets auditors detect modifications.
    # Satisfies GDPR Article 5(2) accountability requirements.
    # ----------------------------------------------------------
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor     TEXT NOT NULL,
            action    TEXT NOT NULL,
            detail    TEXT DEFAULT '',
            hmac      TEXT NOT NULL
        )
    """)
    # hmac : HMAC-SHA256 over "timestamp|actor|action|detail"
    debug("database", "init_db", "Table ready: audit_log")

    conn.commit()
    conn.close()
    info("database", "init_db", "Database ready")