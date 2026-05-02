# =============================================================
# roles/clinician.py -- Clinician Functions and Menu
# =============================================================
# Clinicians upload encrypted patient datasets.
# They never interact with the key hierarchy directly -- the
# platform handles encryption transparently on upload.
# =============================================================

from datetime import datetime, timezone

from Crypto.Random import get_random_bytes

from database import get_conn
from crypto_utils import aes_encrypt, aes_decrypt
from key_manager import wrap_dataset_key, unwrap_dataset_key
from audit import log_action
from session import check_session, touch_session, session_time_remaining, fmt_time
from logger import debug, info, warn


def clinician_upload(session, filename, data):
    # Encrypt and upload a patient dataset.
    #
    # The plaintext never touches the database -- encryption happens in memory.
    # This directly satisfies GDPR Article 32: encryption of personal data at rest.
    #
    # Key flow:
    #   1. Generate a fresh per-dataset AES key (PDK)
    #   2. Encrypt data with PDK
    #   3. Wrap PDK with the platform MDK (so any researcher can later unwrap it)
    #   4. Store only ciphertext + wrapped PDK -- no plaintext, no raw keys in DB
    #
    # Unlike the previous design, this does NOT require researchers to exist
    # at the time of upload. The MDK is always available; researchers get access
    # to the MDK when they register.
    info("clinician", "clinician_upload",
         f"Starting upload for '{filename}'")

    # Step 1: Fresh per-dataset AES-256 key
    pdk = get_random_bytes(32)
    debug("clinician", "clinician_upload",
          "Generated per-dataset key (PDK)", f"pdk_preview={pdk.hex()[:8]}...")

    # Step 2: Encrypt the data with the PDK
    iv_b64, ciphertext_b64 = aes_encrypt(data, pdk)
    debug("clinician", "clinician_upload",
          f"Data encrypted, ciphertext_len={len(ciphertext_b64)}")

    # Step 3: Wrap the PDK with the MDK (symmetric key wrapping)
    pdk_iv_b64, wrapped_pdk_b64 = wrap_dataset_key(pdk)
    debug("clinician", "clinician_upload",
          "PDK wrapped with MDK")

    # Step 4: Store everything -- no raw PDK, no plaintext
    conn = get_conn()
    cursor = conn.execute(
        """INSERT INTO datasets
           (filename, uploaded_by, ciphertext, iv, wrapped_dataset_key, uploaded_at)
           VALUES (?,?,?,?,?,?)""",
        (
            filename,
            session["username"],
            ciphertext_b64,
            iv_b64,
            f"{pdk_iv_b64}:{wrapped_pdk_b64}",  # IV and wrapped key stored together
            datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        )
    )
    dataset_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # PDK goes out of scope here -- only the MDK-wrapped version persists
    log_action(session["username"], "dataset_uploaded",
               f"file={filename} id={dataset_id}")
    info("clinician", "clinician_upload",
         f"Upload complete", f"dataset_id={dataset_id}")

    print(f"\n  [OK] '{filename}' encrypted and uploaded (Dataset ID: {dataset_id}).")
    print(f"  [OK] Dataset is accessible to all registered researchers.")


def clinician_list_uploads(session):
    # Show datasets this clinician has uploaded.
    debug("clinician", "clinician_list_uploads",
          f"Fetching uploads for {session['username']}")

    conn = get_conn()
    rows = conn.execute(
        "SELECT id, filename, uploaded_at FROM datasets WHERE uploaded_by=?",
        (session["username"],)
    ).fetchall()
    conn.close()

    if not rows:
        print("\n  No uploads yet.")
        return

    print("\n  Your uploaded datasets:")
    print(f"  {'ID':<6} {'Filename':<32} {'Uploaded At'}")
    print(f"  {'-'*6} {'-'*32} {'-'*19}")
    for row in rows:
        print(f"  [{row[0]:<4}] {row[1]:<32} {fmt_time(row[2])}")


def clinician_menu(session):
    while True:
        if not check_session(session):
            return

        print("\n  ╔════════════════════════════════════════════╗")
        print(f"  ║  CLINICIAN  |  {session['username']:<17} |  {session_time_remaining(session):<9} ║")
        print("  ╠════════════════════════════════════════════╣")
        print("  ║  1.  Upload patient dataset                ║")
        print("  ║  2.  View my uploads                       ║")
        print("  ║  3.  Logout                                ║")
        print("  ╚════════════════════════════════════════════╝")
        choice = input("\n  > ").strip()

        if not check_session(session):
            return

        if choice == "1":
            print("\n  (Enter 'q' at any prompt to cancel)\n")
            filename = input("  Filename (e.g. patient_data.txt): ").strip()
            if filename.lower() == "q" or not filename:
                print("\n  Cancelled.")
                continue
            print("  Enter dataset content:")
            data = input("  > ").strip()
            if data.lower() == "q" or not data:
                print("\n  Cancelled.")
                continue
            clinician_upload(session, filename, data.encode())
            touch_session(session)

        elif choice == "2":
            clinician_list_uploads(session)
            touch_session(session)

        elif choice == "3":
            break

        else:
            print("\n  [!] Invalid choice -- enter 1, 2, or 3.")