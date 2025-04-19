from flask import Flask, render_template, jsonify
import base64
import requests
from prover_core import Prover

app = Flask(__name__)

STATE = "bootloader=v1 kernel=v5 app=trusted"
VERIFIER = "http://localhost:8000"

prover = Prover(key_dir="keys")

@app.route("/")
def index():
    try:
        # Get current nonce from verifier (do NOT generate one)
        res = requests.get(f"{VERIFIER}/current_nonce")
        res.raise_for_status()
        nonce = base64.b64decode(res.json()["nonce"])

        # Generate quote and signature
        quote, signature = prover.generate_quote(nonce, STATE)

        # Prepare base64-encoded output for display
        encoded = {
            "nonce": base64.b64encode(nonce).decode(),
            "quote": base64.b64encode(quote).decode(),
            "signature": base64.b64encode(signature).decode(),
            "public_key": prover.get_public_pem(),
            "state": STATE
        }

        return render_template("prover.html", **encoded)

    except Exception as e:
        return f"Error: {e}", 500

if __name__ == "__main__":
    app.run(port=5000, debug=True)
