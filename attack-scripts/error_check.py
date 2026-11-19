import random
import string

import requests

BASE = "http://localhost:5001/api"
u = "probe_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))

r = requests.post(
    f"{BASE}/auth/register",
    json={"username": u, "email": f"{u}@example.com", "password": "Passw0rd!123"},
)
token = r.json()["token"]
headers = {"Authorization": f"Bearer {token}"}

# Malformed ObjectId should make Mongoose throw a CastError
r = requests.get(f"{BASE}/users/not-a-valid-id", headers=headers)
print(f"HTTP {r.status_code}")
print(r.text[:300])