from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import os

class Prover():
    def __init__(self, key_dir="keys"):
        priv_path = os.path.join(key_dir, "priv.pem")
        pub_path = os.path.join(key_dir, "pub.pem")

        if os.path.exists(priv_path):
            # Load private key from PEM
            with open(priv_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
        else:
            print("Generating new private key...")
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            # Save to PEM
            with open(priv_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

        self.public_key = self.private_key.public_key()


        if not os.path.exists(pub_path):
            print("Generating new public key...")
            with open(pub_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

    
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

