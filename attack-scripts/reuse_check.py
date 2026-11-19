import random
import string

import requests

BASE = "http://localhost:5001/api"
u = "victim_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))

# Victim logs in and gets refresh token A
r = requests.post(
    f"{BASE}/auth/register",
    json={"username": u, "email": f"{u}@example.com", "password": "Passw0rd!123"},
)
token_a = r.cookies.get("refreshToken")
print("1. Victim registered, holds token A")

# Victim refreshes normally: A is rotated into B
r = requests.post(f"{BASE}/auth/refresh", cookies={"refreshToken": token_a})
token_b = r.cookies.get("refreshToken")
print(f"2. Victim refresh with A: HTTP {r.status_code} (got token B)")

# Attacker replays stolen token A
r = requests.post(f"{BASE}/auth/refresh", cookies={"refreshToken": token_a})
print(f"3. Attacker replays A: HTTP {r.status_code}")

# Victim tries B: should now be dead because the whole family was revoked
r = requests.post(f"{BASE}/auth/refresh", cookies={"refreshToken": token_b})
print(f"4. Victim uses B afterwards: HTTP {r.status_code} (expected 401 = revoked)")