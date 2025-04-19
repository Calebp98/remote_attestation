from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import os

class Prover():
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
    
    def compute_pcr(self, state: str):
        pcr_input = state.encode()
        pcr_digest = hashes.Hash(hashes.SHA256())
        pcr_digest.update(pcr_input)
        pcr_value = pcr_digest.finalize()
        return pcr_value
    
    def padding_scheme(self):
        return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    
    def hash_algorithm(self):
        return hashes.SHA256()
    
    def generate_quote(self, nonce: bytes, state: str):
        quote = nonce + self.compute_pcr(state)
        signature = self.private_key.sign(
            quote,
            self.padding_scheme(),
            self.hash_algorithm()
            )
        return quote, signature
    
    def get_public_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

