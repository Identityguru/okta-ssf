import json
from jwt.utils import to_base64url_uint
from cryptography.hazmat.primitives import serialization

with open("rsa-keypair.json", "r") as f:
    key_data = json.load(f)

public_key = serialization.load_pem_public_key(key_data["publicKey"].encode())
numbers = public_key.public_numbers()

jwk = {
    "kty": "RSA",
    "kid": key_data["kid"],
    "use": "sig",
    "alg": "RS256",
    "n": to_base64url_uint(numbers.n).decode('utf-8'),
    "e": to_base64url_uint(numbers.e).decode('utf-8')
}

import os
os.makedirs("public", exist_ok=True)
with open("public/jwks.json", "w") as f:
    json.dump({"keys": [jwk]}, f, indent=2)

print("Created public/jwks.json")
