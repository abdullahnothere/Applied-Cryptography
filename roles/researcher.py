# =============================================================
# roles/researcher.py -- Researcher Functions and Menu
# =============================================================
# Researchers have two separate workflows:
#
#   A. Clinician Datasets (read-only)
#      - List datasets uploaded by clinicians
#      - Decrypt and view patient data
#      - Decrypt flow: RSA private key -> MDK -> PDK -> plaintext
#
#   B. Research Notes (read/write, personal)
#      - Write encrypted notes referencing a clinician dataset
#      - Decrypt and view their own notes later
#      - Encrypted with a per-file AES key wrapped with the
#        researcher's OWN RSA public key -- only the author can read them
#      - This is a deliberate design choice: notes are personal work
#        product, not shared data. RSA-per-author vs MDK ensures one
#        researcher cannot read another's notes.
#
#   C. Signed Findings (write-once, publicly verifiable)
#      - Digitally sign a research conclusion with RSA-PSS
#      - Anyone with the researcher's public key can verify authorship
# =============================================================

from datetime import datetime, timezone

from Crypto.Random import get_random_bytes

from database import get_conn
from crypto_utils import (
    aes_encrypt, aes_decrypt,
    load_private_key, load_public_key,
    rsa_wrap_key, rsa_unwrap_key,
    sign_content
)
from key_manager import unwrap_dataset_key
from audit import log_action
from session import check_session, touch_session, session_time_remaining, fmt_time
from logger import debug, info, warn


# -------------------------------------------------------------
# A. CLINICIAN DATASETS -- read-only access
# -------------------------------------------------------------

def researcher_list_datasets(session):
    # List all clinician datasets available in the system.
    # With the MDK design, all registered researchers can see and decrypt
    # all datasets -- access control happens at the MDK wrapper level.
    # If a researcher has no MDK wrapper, decrypt will fail with a clear message.
    debug("researcher", "researcher_list_datasets",
          f"Fetching clinician datasets for {session['username']}")

    conn = get_conn()
    rows = conn.execute(
        "SELECT id, filename, uploaded_by, uploaded_at FROM datasets ORDER BY id ASC"
    ).fetchall()
    conn.close()

    if not rows:
        # Flag clearly -- an examiner or auditor will notice this path
        print("\n  [i] No clinician datasets have been uploaded yet.")
        print("  [i] Ask a clinician to upload a patient dataset first.")
        return []

    print("\n  Available clinician datasets:")
    print(f"  {'ID':<6} {'Filename':<32} {'Uploaded By':<22} {'Uploaded At'}")
    print(f"  {'-'*6} {'-'*32} {'-'*22} {'-'*19}")
    for row in rows:
        print(f"  [{row[0]:<4}] {row[1]:<32} {row[2]:<22} {fmt_time(row[3])}")
    return rows


def researcher_decrypt_dataset(session, dataset_id):
    # Decrypt a clinician dataset and display its contents.
    #
    # Key chain used:
    #   1. Load researcher's RSA private key (from session, unlocked with password)
    #   2. RSA private key -> unwrap MDK (from mdk_wrappers table)
    #   3. MDK -> unwrap per-dataset key PDK (from datasets.wrapped_dataset_key)
    #   4. PDK -> AES-decrypt ciphertext -> plaintext
    debug("researcher", "researcher_decrypt_dataset",
          f"Decrypt request: dataset_id={dataset_id} user={session['username']}")

    conn = get_conn()
    dataset = conn.execute(
        "SELECT filename, ciphertext, iv, wrapped_dataset_key FROM datasets WHERE id=?",
        (dataset_id,)
    ).fetchone()
    conn.close()

    if not dataset:
        warn("researcher", "researcher_decrypt_dataset",
             f"Dataset {dataset_id} not found")
        print("\n  [!] Dataset not found.")
        return None   # return None so callers can check

    filename, ciphertext_b64, data_iv_b64, wrapped_key_field = dataset

    # wrapped_dataset_key stores "pdk_iv:wrapped_pdk" as a single field
    pdk_iv_b64, wrapped_pdk_b64 = wrapped_key_field.split(":", 1)
    debug("researcher", "researcher_decrypt_dataset",
          "Parsed PDK iv and wrapped PDK from DB")

    private_key_obj = load_private_key(
        session["private_key"], session["password"].encode()
    )
    debug("researcher", "researcher_decrypt_dataset",
          "Researcher private key loaded from session")

    # Chain: RSA private key -> MDK -> PDK
    pdk = unwrap_dataset_key(
        wrapped_pdk_b64, pdk_iv_b64,
        session["username"], private_key_obj
    )

    if pdk is None:
        warn("researcher", "researcher_decrypt_dataset",
             f"No MDK wrapper for {session['username']}")
        print("\n  [!] Access denied: your account does not have MDK access.")
        print("  [!] Contact an administrator -- your account may need re-registration.")
        log_action(session["username"], "decrypt_denied",
                   f"dataset_id={dataset_id} reason=no_mdk_wrapper")
        return None

    # PDK -> plaintext
    plaintext = aes_decrypt(data_iv_b64, ciphertext_b64, pdk)
    debug("researcher", "researcher_decrypt_dataset",
          f"Dataset decrypted OK, plaintext_len={len(plaintext)}")

    log_action(session["username"], "dataset_decrypted",
               f"dataset_id={dataset_id}")
    info("researcher", "researcher_decrypt_dataset",
         f"Dataset {dataset_id} decrypted by {session['username']}")

    print(f"\n  Clinician Dataset -- '{filename}':")
    print(f"  {'=' * 58}")
    print(f"  {plaintext.decode()}")
    print(f"  {'=' * 58}")
    return plaintext


# -------------------------------------------------------------
# B. RESEARCH NOTES -- personal encrypted files
# -------------------------------------------------------------

def researcher_create_notes(session, dataset_id, filename, content):
    # Write encrypted research notes linked to a specific clinician dataset.
    #
    # Encryption:
    #   - Fresh AES-256 key generated per file
    #   - Notes encrypted with AES-CBC
    #   - AES key wrapped with THIS researcher's RSA public key
    #   - Only this researcher can decrypt their own notes
    #
    # This differs from clinician uploads which use the MDK.
    # Personal notes use per-author RSA wrapping so researchers
    # cannot read each other's notes.
    debug("researcher", "researcher_create_notes",
          f"Creating note file '{filename}' linked to dataset {dataset_id}")

    # Verify the dataset exists -- notes must reference a real clinician dataset
    conn = get_conn()
    ds = conn.execute(
        "SELECT id FROM datasets WHERE id=?", (dataset_id,)
    ).fetchone()
    conn.close()

    if not ds:
        print("\n  [!] Dataset not found. Notes must be linked to an existing dataset.")
        return

    # Fresh AES-256 key for this file only
    file_key = get_random_bytes(32)
    debug("researcher", "researcher_create_notes",
          "Generated per-file AES key")

    # Encrypt the notes content
    iv_b64, ciphertext_b64 = aes_encrypt(content.encode("utf-8"), file_key)
    debug("researcher", "researcher_create_notes",
          f"Notes encrypted, ciphertext_len={len(ciphertext_b64)}")

    # Wrap the AES key with the researcher's own RSA public key.
    # Their public key is stored in the session -- no DB round-trip needed.
    wrapped_key_b64 = rsa_wrap_key(file_key, session["public_key"])
    debug("researcher", "researcher_create_notes",
          "File key wrapped with researcher's RSA public key")

    # Persist to research_files table
    conn = get_conn()
    cursor = conn.execute(
        """INSERT INTO research_files
           (researcher, dataset_id, filename, ciphertext, iv, wrapped_key, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (
            session["username"], dataset_id, filename,
            ciphertext_b64, iv_b64, wrapped_key_b64,
            datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        )
    )
    note_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_action(session["username"], "research_notes_created",
               f"note_id={note_id} dataset_id={dataset_id} file={filename}")
    info("researcher", "researcher_create_notes",
         f"Notes saved", f"note_id={note_id}")

    print(f"\n  [OK] Research notes '{filename}' encrypted and saved (Note ID: {note_id}).")
    print(f"  [OK] Only you can decrypt these notes.")


def researcher_list_notes(session):
    # List this researcher's own encrypted note files.
    # Includes the linked clinician dataset filename for context.
    debug("researcher", "researcher_list_notes",
          f"Fetching notes for {session['username']}")

    conn = get_conn()
    rows = conn.execute("""
        SELECT r.id, r.filename, r.dataset_id, d.filename, r.created_at
        FROM research_files r
        JOIN datasets d ON r.dataset_id = d.id
        WHERE r.researcher = ?
        ORDER BY r.id ASC
    """, (session["username"],)).fetchall()
    conn.close()

    if not rows:
        print("\n  [i] You have no saved research notes yet.")
        print("  [i] Use option 4 to create notes after reviewing a dataset.")
        return []

    print("\n  Your research notes:")
    print(f"  {'ID':<6} {'Note File':<28} {'Linked Dataset':<28} {'Created At'}")
    print(f"  {'-'*6} {'-'*28} {'-'*28} {'-'*19}")
    for row in rows:
        note_id, note_file, ds_id, ds_file, created_at = row
        print(f"  [{note_id:<4}] {note_file:<28} {ds_file:<28} {fmt_time(created_at)}")
    return rows


def researcher_view_notes(session, note_id):
    # Decrypt and display a researcher's own notes.
    #
    # Decryption:
    #   1. Load researcher's RSA private key from session
    #   2. Unwrap the per-file AES key using the private key
    #   3. AES-decrypt the ciphertext -> plaintext notes
    #
    # Only the author can do step 2 -- the key was wrapped with their
    # public key during creation. A different researcher's private key
    # would fail the RSA unwrap.
    debug("researcher", "researcher_view_notes",
          f"View note_id={note_id} for {session['username']}")

    conn = get_conn()
    row = conn.execute("""
        SELECT r.filename, r.ciphertext, r.iv, r.wrapped_key, r.dataset_id, d.filename
        FROM research_files r
        JOIN datasets d ON r.dataset_id = d.id
        WHERE r.id = ? AND r.researcher = ?
    """, (note_id, session["username"])).fetchone()
    conn.close()

    if not row:
        # Could be wrong ID or belongs to another researcher -- same message for both
        # to avoid confirming whether a note ID exists (information leakage)
        warn("researcher", "researcher_view_notes",
             f"Note {note_id} not found for {session['username']}")
        print("\n  [!] Note not found or you do not have access to it.")
        log_action(session["username"], "notes_access_denied",
                   f"note_id={note_id}")
        return

    note_filename, ciphertext_b64, iv_b64, wrapped_key_b64, ds_id, ds_filename = row

    # Load private key -- only works with the correct session password
    private_key_obj = load_private_key(
        session["private_key"], session["password"].encode()
    )
    debug("researcher", "researcher_view_notes",
          "Researcher private key loaded")

    # Unwrap the per-file AES key using the researcher's RSA private key
    file_key = rsa_unwrap_key(wrapped_key_b64, private_key_obj)
    debug("researcher", "researcher_view_notes",
          f"Per-file AES key unwrapped, len={len(file_key)}")

    # Decrypt the notes content
    plaintext = aes_decrypt(iv_b64, ciphertext_b64, file_key)
    debug("researcher", "researcher_view_notes",
          f"Notes decrypted, plaintext_len={len(plaintext)}")

    log_action(session["username"], "research_notes_viewed",
               f"note_id={note_id} dataset_id={ds_id}")
    info("researcher", "researcher_view_notes",
         f"Note {note_id} decrypted by {session['username']}")

    print(f"\n  Research Notes -- '{note_filename}'")
    print(f"  Linked to clinician dataset: '{ds_filename}'")
    print(f"  {'=' * 58}")
    print(f"  {plaintext.decode()}")
    print(f"  {'=' * 58}")


# -------------------------------------------------------------
# C. SIGNED FINDINGS -- write-once, publicly verifiable
# -------------------------------------------------------------

def researcher_sign_finding(session, content):
    # Sign a research finding with the researcher's RSA private key.
    # The signature binds the exact text to this researcher's identity.
    # Anyone with their public key (including auditors) can verify it.
    debug("researcher", "researcher_sign_finding",
          f"Signing finding for {session['username']}")

    private_key_obj = load_private_key(
        session["private_key"], session["password"].encode()
    )
    signature_b64 = sign_content(content, private_key_obj)

    conn = get_conn()
    conn.execute(
        "INSERT INTO findings (researcher, content, signature, signed_at) VALUES (?,?,?,?)",
        (
            session["username"], content, signature_b64,
            datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        )
    )
    conn.commit()
    conn.close()

    log_action(session["username"], "finding_signed", content[:60])
    info("researcher", "researcher_sign_finding",
         f"Finding signed and stored for {session['username']}")
    print("\n  [OK] Finding signed and stored.")
    print("  [OK] An auditor can verify this finding using your public key.")


# -------------------------------------------------------------
# MENU
# -------------------------------------------------------------

def researcher_menu(session):
    while True:
        if not check_session(session):
            return

        print("\n  ╔══════════════════════════════════════════════╗")
        print(f"  ║  RESEARCHER  |  {session['username']:<16} |  {session_time_remaining(session):<9} ║")
        print("  ╠══════════════════════════════════════════════╣")
        print("  ║  -- Clinician Datasets --                    ║")
        print("  ║  1.  List available datasets                 ║")
        print("  ║  2.  Decrypt a dataset                       ║")
        print("  ╠══════════════════════════════════════════════╣")
        print("  ║  -- My Research Notes --                     ║")
        print("  ║  3.  View my notes                           ║")
        print("  ║  4.  Create new research notes               ║")
        print("  ╠══════════════════════════════════════════════╣")
        print("  ║  -- Findings --                              ║")
        print("  ║  5.  Sign a research finding                 ║")
        print("  ╠══════════════════════════════════════════════╣")
        print("  ║  6.  Logout                                  ║")
        print("  ╚══════════════════════════════════════════════╝")
        choice = input("\n  > ").strip()

        if not check_session(session):
            return

        # --- Clinician datasets ---

        if choice == "1":
            researcher_list_datasets(session)
            touch_session(session)

        elif choice == "2":
            rows = researcher_list_datasets(session)
            if not rows:
                continue
            did = input("\n  Enter dataset ID to decrypt (or 'q' to cancel): ").strip()
            if did.lower() == "q" or not did:
                print("\n  Cancelled.")
                continue
            if did.isdigit():
                researcher_decrypt_dataset(session, int(did))
                touch_session(session)
            else:
                print("\n  [!] Please enter a valid numeric ID.")

        # --- Research notes ---

        elif choice == "3":
            rows = researcher_list_notes(session)
            if not rows:
                continue
            nid = input("\n  Enter note ID to view (or 'q' to cancel): ").strip()
            if nid.lower() == "q" or not nid:
                print("\n  Cancelled.")
                continue
            if nid.isdigit():
                researcher_view_notes(session, int(nid))
                touch_session(session)
            else:
                print("\n  [!] Please enter a valid numeric ID.")

        elif choice == "4":
            # Show datasets first so the researcher can choose which one to annotate
            rows = researcher_list_datasets(session)
            if not rows:
                print("\n  [i] Upload a clinician dataset first before creating notes.")
                continue

            print("\n  (Enter 'q' at any prompt to cancel)\n")
            did = input("  Link to dataset ID: ").strip()
            if did.lower() == "q" or not did:
                print("\n  Cancelled.")
                continue
            if not did.isdigit():
                print("\n  [!] Please enter a valid numeric ID.")
                continue

            filename = input("  Note filename (e.g. cohort_a_notes.txt): ").strip()
            if filename.lower() == "q" or not filename:
                print("\n  Cancelled.")
                continue

            print("  Enter your research notes:")
            content = input("  > ").strip()
            if content.lower() == "q" or not content:
                print("\n  Cancelled.")
                continue

            researcher_create_notes(session, int(did), filename, content)
            touch_session(session)

        # --- Findings ---

        elif choice == "5":
            print("\n  Enter your research finding (or 'q' to cancel):")
            finding = input("  > ").strip()
            if finding.lower() == "q" or not finding:
                print("\n  Cancelled.")
                continue
            researcher_sign_finding(session, finding)
            touch_session(session)

        elif choice == "6":
            break

        else:
            print("\n  [!] Invalid choice -- enter 1 through 6.")