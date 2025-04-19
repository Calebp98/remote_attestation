import requests
import base64
from prover_core import Prover

res = requests.post("http://localhost:8000/nonce")
res.raise_for_status()
nonce_b64 = res.json()["nonce"]
nonce = base64.b64decode(nonce_b64)

prover = Prover()  
state = "bootloader=v1 kernel=v5 app=trusted"

quote, signature = prover.generate_quote(nonce, state)

payload = {
    "quote": base64.b64encode(quote).decode(),
    "signature": base64.b64encode(signature).decode(),
    "public_key": prover.get_public_pem() 
}

res = requests.post("http://localhost:8000/attest", json=payload)
print("Verifier response:", res.status_code, res.json())