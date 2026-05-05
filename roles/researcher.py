# roles/researcher.py
# Three things a researcher can do:
#   - Decrypt clinician datasets (shared via MDK)
#   - Create and view their own encrypted notes (wrapped with their own RSA key)
#   - Sign research findings

from datetime import datetime, timezone

from Crypto.Random import get_random_bytes

from database import get_conn
from crypto_utils import (
    aes_encrypt, aes_decrypt,
    load_private_key,
    rsa_wrap_key, rsa_unwrap_key,
    sign_content
)
from key_manager import unwrap_dataset_key
from audit import log_action
from session import check_session, touch_session, session_time_remaining, fmt_time
from logger import debug, info, warn


def researcher_list_datasets(session):
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, filename, uploaded_by, uploaded_at FROM datasets ORDER BY id ASC"
    ).fetchall()
    conn.close()

    if not rows:
        print("\n  [i] No clinician datasets uploaded yet.")
        print("  [i] Ask a clinician to upload a patient dataset first.")
        return []

    print("\n  Available datasets:")
    print(f"  {'ID':<6} {'Filename':<32} {'Uploaded By':<22} {'Uploaded At'}")
    print(f"  {'-'*6} {'-'*32} {'-'*22} {'-'*19}")
    for row in rows:
        print(f"  [{row[0]:<4}] {row[1]:<32} {row[2]:<22} {fmt_time(row[3])}")
    return rows


def researcher_decrypt_dataset(session, dataset_id):
    conn = get_conn()
    dataset = conn.execute(
        "SELECT filename, ciphertext, iv, wrapped_dataset_key FROM datasets WHERE id=?",
        (dataset_id,)
    ).fetchone()
    conn.close()

    if not dataset:
        print("\n  [!] Dataset not found.")
        return None

    filename, ciphertext_b64, data_iv_b64, wrapped_key_field = dataset

    # wrapped_dataset_key is stored as "pdk_iv:wrapped_pdk"
    pdk_iv_b64, wrapped_pdk_b64 = wrapped_key_field.split(":", 1)

    private_key_obj = load_private_key(session["private_key"], session["password"].encode())

    pdk = unwrap_dataset_key(wrapped_pdk_b64, pdk_iv_b64, session["username"], private_key_obj)
    if pdk is None:
        print("\n  [!] Access denied — no MDK wrapper found for your account.")
        print("  [!] Try re-registering or contact an administrator.")
        log_action(session["username"], "decrypt_denied", f"dataset_id={dataset_id}")
        return None

    plaintext = aes_decrypt(data_iv_b64, ciphertext_b64, pdk)
    log_action(session["username"], "dataset_decrypted", f"dataset_id={dataset_id}")
    info("researcher", "researcher_decrypt_dataset", f"dataset {dataset_id} decrypted")

    print(f"\n  '{filename}':")
    print(f"  {'=' * 58}")
    print(f"  {plaintext.decode()}")
    print(f"  {'=' * 58}")
    return plaintext


def researcher_create_notes(session, dataset_id, filename, content):
    # Notes use a per-file AES key wrapped with the researcher's own RSA public key —
    # not the MDK. This keeps notes private to their author.
    conn = get_conn()
    ds = conn.execute("SELECT id FROM datasets WHERE id=?", (dataset_id,)).fetchone()
    conn.close()

    if not ds:
        print("\n  [!] Dataset not found. Notes must reference an existing dataset.")
        return

    file_key = get_random_bytes(32)
    iv_b64, ciphertext_b64 = aes_encrypt(content.encode("utf-8"), file_key)

    # Public key comes from the session — no extra DB call needed.
    wrapped_key_b64 = rsa_wrap_key(file_key, session["public_key"])

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
               f"note_id={note_id} dataset_id={dataset_id}")
    print(f"\n  [OK] '{filename}' saved (Note ID: {note_id}).")
    print(f"  [OK] Only you can decrypt these notes.")


def researcher_list_notes(session):
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
        print("\n  [i] No research notes yet. Use option 4 to create some.")
        return []

    print("\n  Your research notes:")
    print(f"  {'ID':<6} {'Note File':<28} {'Linked Dataset':<28} {'Created At'}")
    print(f"  {'-'*6} {'-'*28} {'-'*28} {'-'*19}")
    for note_id, note_file, ds_id, ds_file, created_at in rows:
        print(f"  [{note_id:<4}] {note_file:<28} {ds_file:<28} {fmt_time(created_at)}")
    return rows


def researcher_view_notes(session, note_id):
    conn = get_conn()
    row = conn.execute("""
        SELECT r.filename, r.ciphertext, r.iv, r.wrapped_key, r.dataset_id, d.filename
        FROM research_files r
        JOIN datasets d ON r.dataset_id = d.id
        WHERE r.id = ? AND r.researcher = ?
    """, (note_id, session["username"])).fetchone()
    conn.close()

    if not row:
        # Same message whether the ID doesn't exist or belongs to someone else —
        # avoids revealing which note IDs are valid.
        print("\n  [!] Note not found or you do not have access to it.")
        log_action(session["username"], "notes_access_denied", f"note_id={note_id}")
        return

    note_filename, ciphertext_b64, iv_b64, wrapped_key_b64, ds_id, ds_filename = row

    private_key_obj = load_private_key(session["private_key"], session["password"].encode())
    file_key = rsa_unwrap_key(wrapped_key_b64, private_key_obj)
    plaintext = aes_decrypt(iv_b64, ciphertext_b64, file_key)

    log_action(session["username"], "research_notes_viewed",
               f"note_id={note_id} dataset_id={ds_id}")

    print(f"\n  '{note_filename}'  (linked to: '{ds_filename}')")
    print(f"  {'=' * 58}")
    print(f"  {plaintext.decode()}")
    print(f"  {'=' * 58}")


def researcher_sign_finding(session, content):
    private_key_obj = load_private_key(session["private_key"], session["password"].encode())
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
    print("\n  [OK] Finding signed and stored.")
    print("  [OK] An auditor can verify this using your public key.")


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

        if choice == "1":
            researcher_list_datasets(session)
            touch_session(session)

        elif choice == "2":
            rows = researcher_list_datasets(session)
            if not rows:
                continue
            did = input("\n  Dataset ID to decrypt (or 'q'): ").strip()
            if did.lower() == "q" or not did:
                print("\n  Cancelled.")
                continue
            if did.isdigit():
                researcher_decrypt_dataset(session, int(did))
                touch_session(session)
            else:
                print("\n  [!] Enter a valid numeric ID.")

        elif choice == "3":
            rows = researcher_list_notes(session)
            if not rows:
                continue
            nid = input("\n  Note ID to view (or 'q'): ").strip()
            if nid.lower() == "q" or not nid:
                print("\n  Cancelled.")
                continue
            if nid.isdigit():
                researcher_view_notes(session, int(nid))
                touch_session(session)
            else:
                print("\n  [!] Enter a valid numeric ID.")

        elif choice == "4":
            rows = researcher_list_datasets(session)
            if not rows:
                continue
            print("\n  (Enter 'q' at any prompt to cancel)\n")
            did = input("  Link to dataset ID: ").strip()
            if did.lower() == "q" or not did:
                print("\n  Cancelled.")
                continue
            if not did.isdigit():
                print("\n  [!] Enter a valid numeric ID.")
                continue
            filename = input("  Note filename: ").strip()
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
            print("\n  [!] Invalid choice — enter 1 through 6.")