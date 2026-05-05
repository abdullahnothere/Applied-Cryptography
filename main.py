# main.py
# Entry point. Boots the platform, seeds test accounts, runs the login loop.
# Run: python3 main.py

from config import SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS, VALID_ROLES
from database import init_db
from key_manager import ensure_mdk_exists
from auth import register_user, login_user, seed_test_accounts
from audit import log_action
from session import check_session
from roles.clinician import clinician_menu
from roles.researcher import researcher_menu
from roles.auditor import auditor_menu
from logger import info


def registration_flow():
    print("\n  ╔══════════════════════════════════════╗")
    print("  ║       Register New Account           ║")
    print("  ╚══════════════════════════════════════╝")
    print("  (Press Enter with no input to cancel)\n")

    username = input("  Username              : ").strip()
    if not username:
        print("\n  Cancelled.")
        return

    password = input("  Password (min 8 chars): ").strip()
    if not password:
        print("\n  Cancelled.")
        return

    print(f"\n  Available roles: {', '.join(VALID_ROLES)}")
    role = input("  Role                  : ").strip().lower()
    if not role:
        print("\n  Cancelled.")
        return

    ok, message = register_user(username, password, role)
    if ok:
        print(f"\n  [OK] {message}")
    else:
        print(f"\n  [!] {message}")


if __name__ == "__main__":
    print("\n  ╔══════════════════════════════════════════════════════╗")
    print("  ║     Secure Clinical Research Platform  v2.0          ║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print(f"  ║  Idle: {SESSION_IDLE_SECONDS}s  |  Max session: {SESSION_MAX_SECONDS}s                      ║")
    print("  ╚══════════════════════════════════════════════════════╝\n")

    init_db()
    ensure_mdk_exists()
    seed_test_accounts()
    info("main", "__main__", "platform ready")

    while True:
        print("  ┌────────────────────────────────┐")
        print("  │  1.  Login                     │")
        print("  │  2.  Register new account      │")
        print("  │  3.  Exit                      │")
        print("  └────────────────────────────────┘")
        choice = input("\n  > ").strip()

        if choice == "3":
            print("\n  Goodbye.\n")
            info("main", "__main__", "shutdown")
            break

        elif choice == "2":
            registration_flow()

        elif choice == "1":
            print()
            username = input("  Username : ").strip()
            if not username:
                continue
            password = input("  Password : ").strip()
            if not password:
                continue

            print("\n  [*] Authenticating...")
            session = login_user(username, password)

            if not session:
                print("\n  [!] Invalid credentials.\n")
                continue

            print(f"\n  [OK] Welcome, {session['username']}  ({session['role'].upper()})")
            print(f"  [i]  Session expires after {SESSION_IDLE_SECONDS}s idle or {SESSION_MAX_SECONDS}s total.\n")

            if session["role"] == "researcher":
                researcher_menu(session)
            elif session["role"] == "clinician":
                clinician_menu(session)
            elif session["role"] == "auditor":
                auditor_menu(session)

            if check_session(session):
                log_action(session["username"], "logout")

            print(f"\n  Logged out — {session['username']}.\n")

        else:
            print("\n  [!] Invalid choice — enter 1, 2, or 3.\n")