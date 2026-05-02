# =============================================================
# roles/researcher.py -- Researcher Functions and Menu
# =============================================================
# Researchers decrypt patient datasets and sign research findings.
#
# Decryption flow:
#   1. Load researcher's RSA private key (unlocked with session password)
#   2. Use private key to unwrap their copy of the MDK
#   3. Use MDK to unwrap the per-dataset key (PDK)
#   4. Use PDK to decrypt the dataset ciphertext
# =============================================================

from datetime import datetime, timezone

from database import get_conn
from crypto_utils import (
    load_private_key, aes_decrypt, sign_content, verify_content_signature
)
from key_manager import unwrap_dataset_key
from audit import log_action
from session import check_session, touch_session, session_time_remaining, fmt_time
from logger import debug, info, warn


def researcher_list_datasets(session):
    # List all datasets in the system.
    # With the MDK design, all researchers can access all datasets --
    # access is controlled at the MDK level, not per-dataset.
    debug("researcher", "researcher_list_datasets",
          f"Fetching all datasets for {session['username']}")

    conn = get_conn()
    rows = conn.execute(
        "SELECT id, filename, uploaded_by, uploaded_at FROM datasets ORDER BY id ASC"
    ).fetchall()
    conn.close()

    if not rows:
        print("\n  No datasets available yet.")
        return []

    print("\n  Available datasets:")
    print(f"  {'ID':<6} {'Filename':<32} {'Uploaded By':<22} {'Uploaded At'}")
    print(f"  {'-'*6} {'-'*32} {'-'*22} {'-'*19}")
    for row in rows:
        print(f"  [{row[0]:<4}] {row[1]:<32} {row[2]:<22} {fmt_time(row[3])}")
    return rows


def researcher_decrypt(session, dataset_id):
    # Decrypt a dataset.
    #
    # Full key derivation chain:
    #   RSA private key (session) -> MDK -> PDK -> plaintext
    debug("researcher", "researcher_decrypt",
          f"Decrypt request: dataset_id={dataset_id} user={session['username']}")

    conn = get_conn()
    dataset = conn.execute(
        "SELECT filename, ciphertext, iv, wrapped_dataset_key FROM datasets WHERE id=?",
        (dataset_id,)
    ).fetchone()
    conn.close()

    if not dataset:
        warn("researcher", "researcher_decrypt",
             f"Dataset {dataset_id} not found")
        print("\n  [!] Dataset not found.")
        return

    filename, ciphertext_b64, data_iv_b64, wrapped_key_field = dataset

    # The wrapped_dataset_key column stores "pdk_iv:wrapped_pdk" together
    pdk_iv_b64, wrapped_pdk_b64 = wrapped_key_field.split(":", 1)
    debug("researcher", "researcher_decrypt",
          "Parsed PDK iv and wrapped PDK from DB field")

    # Load the researcher's private key from session memory
    debug("researcher", "researcher_decrypt",
          "Loading researcher private key from session")
    private_key_obj = load_private_key(
        session["private_key"], session["password"].encode()
    )

    # Full chain: RSA private key -> MDK -> PDK
    pdk = unwrap_dataset_key(
        wrapped_pdk_b64, pdk_iv_b64,
        session["username"], private_key_obj
    )

    if pdk is None:
        warn("researcher", "researcher_decrypt",
             f"No MDK wrapper found for {session['username']}")
        print("\n  [!] Access denied: your account does not have MDK access.")
        print("  [!] Contact an administrator to grant you access.")
        log_action(session["username"], "decrypt_denied",
                   f"dataset_id={dataset_id} reason=no_mdk_wrapper")
        return

    # Decrypt the actual dataset content using the PDK
    plaintext = aes_decrypt(data_iv_b64, ciphertext_b64, pdk)
    debug("researcher", "researcher_decrypt",
          f"Dataset decrypted, plaintext_len={len(plaintext)}")

    log_action(session["username"], "dataset_decrypted",
               f"dataset_id={dataset_id}")
    info("researcher", "researcher_decrypt",
         f"Dataset {dataset_id} decrypted by {session['username']}")

    print(f"\n  Decrypted '{filename}':")
    print(f"  {'=' * 56}")
    print(f"  {plaintext.decode()}")
    print(f"  {'=' * 56}")


def researcher_sign_finding(session, content):
    # Sign a research finding with the researcher's RSA private key.
    # The signature binds the exact text to this researcher's identity.
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


def researcher_menu(session):
    while True:
        if not check_session(session):
            return

        print("\n  ╔════════════════════════════════════════════╗")
        print(f"  ║  RESEARCHER |  {session['username']:<17} |  {session_time_remaining(session):<9} ║")
        print("  ╠════════════════════════════════════════════╣")
        print("  ║  1.  List available datasets               ║")
        print("  ║  2.  Decrypt a dataset                     ║")
        print("  ║  3.  Sign a research finding               ║")
        print("  ║  4.  Logout                                ║")
        print("  ╚════════════════════════════════════════════╝")
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
            did = input("\n  Enter dataset ID to decrypt (or 'q' to cancel): ").strip()
            if did.lower() == "q" or not did:
                print("\n  Cancelled.")
                continue
            if did.isdigit():
                researcher_decrypt(session, int(did))
                touch_session(session)
            else:
                print("\n  [!] Please enter a valid numeric ID.")

        elif choice == "3":
            print("\n  Enter your research finding (or 'q' to cancel):")
            finding = input("  > ").strip()
            if finding.lower() == "q" or not finding:
                print("\n  Cancelled.")
                continue
            researcher_sign_finding(session, finding)
            touch_session(session)

        elif choice == "4":
            break

        else:
            print("\n  [!] Invalid choice -- enter 1, 2, 3, or 4.")