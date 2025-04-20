import requests
import base64
from prover_core import Prover

FILES = ["app_files/start.sh", "app_files/config.json"]
SERVER = "http://verifier:8000"


prover = Prover(key_dir="keys")

# Step 1: Request nonce
nonce_res = requests.post(f"{SERVER}/nonce")
nonce_res.raise_for_status()
nonce = base64.b64decode(nonce_res.json()["nonce"])

# Step 2: Generate quote and signature
quote, signature = prover.generate_quote(nonce, FILES)

# Step 3: Prepare attestation payload
payload = {
    "quote": base64.b64encode(quote).decode(),
    "signature": base64.b64encode(signature).decode(),
    "public_key": prover.get_public_pem()
}

requests.post(f"{SERVER}/attestation-push", json=payload)

# Step 4: Send attestation to verifier
attest_res = requests.post(f"{SERVER}/attest", json=payload)
print("Attestation response:", attest_res.status_code, attest_res.json())

print("\nPaste the following into the web UI:")

print("\nquote:")
print(payload["quote"])

print("\nsignature:")
print(payload["signature"])

print("\npublic_key:")
print(payload["public_key"])
