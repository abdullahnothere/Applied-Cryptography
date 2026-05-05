# roles/auditor.py
# Auditors can verify signatures and read the audit log.
# No private keys, no MDK access, no dataset decryption — by design.

from database import get_conn
from crypto_utils import verify_content_signature
from audit import log_action, verify_log_entry
from session import check_session, touch_session, session_time_remaining, fmt_time
from logger import info


def auditor_verify_findings(session):
    conn = get_conn()
    rows = conn.execute("""
        SELECT f.id, f.researcher, f.content, f.signature, f.signed_at, u.public_key
        FROM findings f
        JOIN users u ON f.researcher = u.username
        ORDER BY f.id ASC
    """).fetchall()
    conn.close()

    if not rows:
        print("\n  No findings on record.")
        return

    print("\n  Research Findings — Signature Verification:")
    print(f"  {'=' * 64}")

    for fid, researcher, content, signature, signed_at, pub_key in rows:
        valid = verify_content_signature(content, signature, pub_key)
        status = "VALID    [OK]" if valid else "INVALID  [!!] — possible tampering"
        print(f"\n  Finding #{fid}  |  {researcher}  |  {fmt_time(signed_at)}")
        print(f"  Content  : {content[:72]}{'...' if len(content) > 72 else ''}")
        print(f"  Status   : {status}")

    log_action(session["username"], "findings_verified", f"count={len(rows)}")
    info("auditor", "auditor_verify_findings", f"verified {len(rows)} finding(s)")


def auditor_view_logs(session):
    conn = get_conn()
    rows = conn.execute(
        "SELECT timestamp, actor, action, detail, hmac FROM audit_log ORDER BY id ASC"
    ).fetchall()
    conn.close()

    print("\n  Audit Log  (HMAC-verified):")
    print(f"  {'Timestamp':<21} {'Actor':<22} {'Action':<28} {'Detail':<32} Status")
    print(f"  {'-'*21} {'-'*22} {'-'*28} {'-'*32} {'-'*10}")

    tampered = 0
    for row in rows:
        entry = {
            "timestamp": row[0], "actor": row[1],
            "action": row[2], "detail": row[3], "hmac": row[4]
        }
        ok = verify_log_entry(entry)
        if not ok:
            tampered += 1
        tag = "[OK]      " if ok else "[TAMPERED]"
        print(f"  {fmt_time(entry['timestamp']):<21} {entry['actor']:<22} "
              f"{entry['action']:<28} {entry['detail'][:32]:<32} {tag}")

    if tampered:
        print(f"\n  [!!] WARNING: {tampered} tampered entry/entries detected.")

    log_action(session["username"], "audit_log_viewed", f"entries={len(rows)}")


def auditor_menu(session):
    while True:
        if not check_session(session):
            return

        print("\n  ╔════════════════════════════════════════════╗")
        print(f"  ║  AUDITOR    |  {session['username']:<17} |  {session_time_remaining(session):<9} ║")
        print("  ╠════════════════════════════════════════════╣")
        print("  ║  1.  Verify research findings              ║")
        print("  ║  2.  View audit log                        ║")
        print("  ║  3.  Logout                                ║")
        print("  ╚════════════════════════════════════════════╝")
        choice = input("\n  > ").strip()

        if not check_session(session):
            return

        if choice == "1":
            auditor_verify_findings(session)
            touch_session(session)

        elif choice == "2":
            auditor_view_logs(session)
            touch_session(session)

        elif choice == "3":
            break

        else:
            print("\n  [!] Invalid choice — enter 1, 2, or 3.")