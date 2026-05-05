# database.py
# Table definitions and connection helper.
# Nothing else lives here — keeps schema changes easy to find.

import sqlite3
from config import DB_PATH
from logger import debug, info


def get_conn():
    debug("database", "get_conn", DB_PATH)
    return sqlite3.connect(DB_PATH)


def init_db():
    info("database", "init_db", "checking schema")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # MDK encrypted with ROOT_KEY. Should only ever be one row.
    c.execute("""
        CREATE TABLE IF NOT EXISTS platform_keys (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_mdk TEXT NOT NULL,
            iv            TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )
    """)

    # One row per researcher — their RSA-wrapped copy of the MDK.
    # Delete a row to revoke that researcher's access.
    c.execute("""
        CREATE TABLE IF NOT EXISTS mdk_wrappers (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            researcher_username TEXT UNIQUE NOT NULL,
            wrapped_mdk         TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL,        -- researcher | clinician | auditor
            public_key    TEXT NOT NULL,        -- PEM, unencrypted
            private_key   TEXT NOT NULL         -- PEM, PBKDF2+AES encrypted with user password
        )
    """)

    # wrapped_dataset_key stores "pdk_iv:wrapped_pdk" as a single field.
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

    # Personal notes per researcher. Encrypted with a per-file key wrapped with
    # the author's own RSA public key, not the MDK — so notes are private to the author.
    c.execute("""
        CREATE TABLE IF NOT EXISTS research_files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            researcher  TEXT NOT NULL,
            dataset_id  INTEGER NOT NULL,
            filename    TEXT NOT NULL,
            ciphertext  TEXT NOT NULL,
            iv          TEXT NOT NULL,
            wrapped_key TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (dataset_id) REFERENCES datasets(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            researcher TEXT NOT NULL,
            content    TEXT NOT NULL,
            signature  TEXT NOT NULL,   -- base64 RSA-PSS over content
            signed_at  TEXT NOT NULL
        )
    """)

    # hmac column covers "timestamp|actor|action|detail" — any edit breaks the tag.
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

    conn.commit()
    conn.close()
    info("database", "init_db", "schema ready")