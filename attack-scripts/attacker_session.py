#!/usr/bin/env python3
"""
attacker_session.py — shared helper for Phase 06 attack scripts.

Most of the remaining vulnerabilities (IDOR, Mass Assignment, Excessive
Data Exposure, CORS misconfig, Refresh Token Theft) don't require a
cracked password at all. The realistic attacker model for all of them is
"I signed up for my own ordinary account" via the app's own public
/api/auth/register endpoint — exactly what any real user does. That's
zero-knowledge too: no insider info, no guessing, just normal signup.

This module gives every other attack script a one-call way to get a
valid, authenticated session:

    from attacker_session import get_attacker_session
    session = get_attacker_session()
    # session = {"email": ..., "password": ..., "token": ..., "user_id": ..., "role": ...}

Priority order:
  1. A cracked credential from brute_force_login.py's discovered_creds.json,
     if one exists (strongest finding — a REAL compromised account).
  2. A previously self-registered throwaway attacker account, cached in
     attacker_account.json (so repeat runs don't spam new accounts).
  3. A brand-new self-registered throwaway account via POST /register.

Usage (standalone sanity check):
    python attacker_session.py
"""

import json
import os
import random
import string
import sys

import requests

DEFAULT_BASE_URL = "http://localhost:5001"
REGISTER_PATH = "/api/auth/register"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DISCOVERED_CREDS_FILE = os.path.join(SCRIPT_DIR, "discovered_creds.json")
ATTACKER_ACCOUNT_FILE = os.path.join(SCRIPT_DIR, "attacker_account.json")


def _random_string(n: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _try_cracked_creds(base_url: str, verbose: bool) -> dict | None:
    """If brute_force_login.py already found a real account, prefer it —
    it's a genuinely compromised account, which is the strongest possible
    demonstration for chained attacks."""
    if not os.path.exists(DISCOVERED_CREDS_FILE):
        return None
    with open(DISCOVERED_CREDS_FILE) as f:
        cracked = json.load(f)
    if not cracked:
        return None

    creds = cracked[0]
    if verbose:
        print(f"[*] Using previously cracked credentials: {creds['email']}")
    return {
        "email": creds["email"],
        "password": creds["password"],
        "token": creds.get("token"),
        "source": "brute_force",
    }


def _self_register(base_url: str, verbose: bool) -> dict:
    """Registers a brand-new throwaway account, same as any real user
    signing up — zero special knowledge required."""
    username = f"attacker_{_random_string(8)}"
    email = f"{username}@example.com"
    password = _random_string(12) + "A1"  # satisfies typical min-length rules

    url = base_url.rstrip("/") + REGISTER_PATH
    if verbose:
        print(f"[*] Self-registering a new throwaway account: {email}")

    resp = requests.post(url, json={
        "username": username,
        "email": email,
        "password": password,
    }, timeout=10)

    if resp.status_code not in (200, 201):
        raise RuntimeError(
            f"Self-registration failed: HTTP {resp.status_code} — {resp.text}"
        )

    body = resp.json()
    token = body.get("accessToken") or body.get("token")
    user = body.get("user", {})

    account = {
        "email": email,
        "password": password,
        "token": token,
        "user_id": user.get("id") or user.get("_id"),
        "role": user.get("role", "user"),
        "source": "self_registered",
    }

    with open(ATTACKER_ACCOUNT_FILE, "w") as f:
        json.dump(account, f, indent=2)
    if verbose:
        print(f"[*] Registered and cached to {ATTACKER_ACCOUNT_FILE}")

    return account


def get_attacker_session(base_url: str = DEFAULT_BASE_URL,
                          force_new: bool = False,
                          verbose: bool = True) -> dict:
    """Returns a dict with email, password, token, and (if self-registered)
    user_id/role for a valid, authenticated attacker session."""

    if not force_new:
        cracked = _try_cracked_creds(base_url, verbose)
        if cracked:
            return cracked

        if os.path.exists(ATTACKER_ACCOUNT_FILE):
            with open(ATTACKER_ACCOUNT_FILE) as f:
                cached = json.load(f)
            if verbose:
                print(f"[*] Using cached self-registered account: {cached['email']}")
                print(f"    (delete {ATTACKER_ACCOUNT_FILE}, or pass force_new=True, "
                      f"for a fresh one)")
            return cached

    return _self_register(base_url, verbose)


if __name__ == "__main__":
    session = get_attacker_session()
    print("\n[*] Attacker session ready:")
    print(f"    email : {session['email']}")
    print(f"    role  : {session.get('role', 'unknown')}")
    print(f"    token : {session['token'][:40]}..." if session.get("token") else "    token : (none)")