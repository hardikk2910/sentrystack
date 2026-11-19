import random
import string
import time

import jwt  # PyJWT; if missing: pip install pyjwt
import requests

BASE = "http://localhost:5001/api"


def rand():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def register():
    u = f"fp_{rand()}"
    r = requests.post(
        f"{BASE}/auth/register",
        json={"username": u, "email": f"{u}@example.com", "password": "Passw0rd!123"},
    )
    return r.json()["token"], r.cookies.get("refreshToken"), r.json()["user"]["id"]


# ---- Case 1: logout, then replay the refresh token ----
access, refresh, user_id = register()
requests.post(
    f"{BASE}/auth/logout",
    headers={"Authorization": f"Bearer {access}"},
    cookies={"refreshToken": refresh},
)
r = requests.post(f"{BASE}/auth/refresh", cookies={"refreshToken": refresh})
print(f"Case 1 (replay after logout): HTTP {r.status_code}  <- expect 401, NO security alert")

time.sleep(1)

# ---- Case 2: forged token (weak secret) with a jti we never issued, aimed at a real user ----
access2, refresh2, victim_id = register()
forged = jwt.encode(
    {"id": victim_id, "jti": "forged-" + rand(), "exp": int(time.time()) + 3600},
    "secret123",  # the weak VULN-03 secret
    algorithm="HS256",
)
r = requests.post(f"{BASE}/auth/refresh", cookies={"refreshToken": forged})
print(f"Case 2 (forged token): HTTP {r.status_code}  <- expect 401, NO security alert")

# Victim's real session must still be intact
r = requests.post(f"{BASE}/auth/refresh", cookies={"refreshToken": refresh2})
print(f"Case 2b (victim's real token still works): HTTP {r.status_code}  <- expect 200")