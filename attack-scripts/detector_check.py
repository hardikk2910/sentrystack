import random
import string

import requests

BASE = "http://localhost:5001/api"


def rand():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def register(name):
    u = f"{name}_{rand()}"
    r = requests.post(
        f"{BASE}/auth/register",
        json={"username": u, "email": f"{u}@example.com", "password": "Passw0rd!123"},
    )
    data = r.json()
    return data["token"], data["user"]["id"], u


alice_token, alice_id, alice_name = register("alice")
bob_token, bob_id, bob_name = register("bob")
print(f"Alice: {alice_name} ({alice_id})  Bob: {bob_name} ({bob_id})")

headers = {"Authorization": f"Bearer {alice_token}"}

# Test 1: IDOR - Alice reads Bob's profile
r = requests.get(f"{BASE}/users/{bob_id}", headers=headers)
print(f"Test 1 (IDOR GET): HTTP {r.status_code}")
print("   password field in GET response:", "password" in r.json())

# Test 2: Mass assignment - Alice makes herself admin
r = requests.put(f"{BASE}/users/{alice_id}", headers=headers, json={"role": "admin"})
print(f"Test 2 (mass assignment PUT): HTTP {r.status_code}")
print("   password field in PUT response:", "password" in r.json()) 