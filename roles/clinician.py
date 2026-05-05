# roles/clinician.py

from datetime import datetime, timezone

from Crypto.Random import get_random_bytes

from database import get_conn
from crypto_utils import aes_encrypt
from key_manager import wrap_dataset_key
from audit import log_action
from session import check_session, touch_session, session_time_remaining, fmt_time
from logger import debug, info


def clinician_upload(session, filename, data):
    # Data is encrypted in memory before anything touches the database.
    # The raw PDK only exists for the duration of this function call.
    pdk = get_random_bytes(32)
    iv_b64, ciphertext_b64 = aes_encrypt(data, pdk)

    # PDK gets wrapped with the MDK so any researcher can unwrap it later.
    pdk_iv_b64, wrapped_pdk_b64 = wrap_dataset_key(pdk)

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
            f"{pdk_iv_b64}:{wrapped_pdk_b64}",
            datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        )
    )
    dataset_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_action(session["username"], "dataset_uploaded", f"file={filename} id={dataset_id}")
    info("clinician", "clinician_upload", f"'{filename}' uploaded", f"id={dataset_id}")
    print(f"\n  [OK] '{filename}' encrypted and uploaded (Dataset ID: {dataset_id}).")
    print(f"  [OK] Accessible to all registered researchers.")


def clinician_list_uploads(session):
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, filename, uploaded_by, uploaded_at FROM datasets ORDER BY id ASC"
    ).fetchall()
    conn.close()

    if not rows:
        print("\n  No datasets on record yet.")
        return

    print("\n  All datasets:")
    print(f"  {'ID':<6} {'Filename':<32} {'Uploaded By':<22} {'Uploaded At'}")
    print(f"  {'-'*6} {'-'*32} {'-'*22} {'-'*19}")
    for row in rows:
        # asterisk marks datasets this clinician uploaded themselves
        mine = " *" if row[2] == session["username"] else ""
        print(f"  [{row[0]:<4}] {row[1]:<32} {row[2]:<22} {fmt_time(row[3])}{mine}")


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