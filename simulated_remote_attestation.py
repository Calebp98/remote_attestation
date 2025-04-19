from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import os

# Step 1: Generate a keypair (simulated TPM Attestation Key)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Step 2: Simulate a PCR value (e.g., hash of known system state)
pcr_input = b"bootloader=v1 kernel=v5 app=trusted"
pcr_digest = hashes.Hash(hashes.SHA256())
pcr_digest.update(pcr_input)
pcr_value = pcr_digest.finalize()

# Step 3: Verifier creates a nonce
nonce = os.urandom(16)

# Step 4: Prover builds a "quote" (nonce + PCR value) and signs it
quote = nonce + pcr_value
signature = private_key.sign(
    quote,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# Step 5: Verifier checks the signature
try:
    public_key.verify(
        signature,
        quote,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("✅ Attestation verified: signature is valid.")
except InvalidSignature:
    print("❌ Invalid attestation: signature check failed.")
