import os
import base64
from flask import Flask, render_template, request, jsonify

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

CURRENT_NONCE = None
EXPECTED_STATE = "bootloader=v1 kernel=v5 app=trusted"

@app.route("/")
def index():
    return render_template("index.html", status=None)

@app.route("/configure", methods=["POST"])
def configure():
    global EXPECTED_STATE
    EXPECTED_STATE = request.form["state"].strip()
    return render_template("index.html", status="Configured: " + EXPECTED_STATE)

@app.route("/attest", methods=["POST"])
def attest():
    global CURRENT_NONCE
    data = request.json

    try:
        # Decode fields
        quote = base64.b64decode(data["quote"])
        signature = base64.b64decode(data["signature"])
        public_key_pem = data["public_key"].encode()

        public_key = serialization.load_pem_public_key(public_key_pem)

        # Verify signature
        public_key.verify(
            signature,
            quote,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Check that the nonce matches
        expected_nonce = CURRENT_NONCE
        received_nonce = quote[:len(expected_nonce)]
        if received_nonce != expected_nonce:
            return jsonify({"status": "replay detected"}), 400

        # Extract actual PCR from the quote
        actual_pcr = quote[len(expected_nonce):]

        # Simulate expected PCR for known-good state
        digest = hashes.Hash(hashes.SHA256())
        digest.update(EXPECTED_STATE.encode())
        expected_pcr = digest.finalize()

        # Compare
        if actual_pcr != expected_pcr:
            return jsonify({"status": "unexpected pcr"}), 400

        return jsonify({"status": "ok"})

    except (InvalidSignature, KeyError, ValueError) as e:
        return jsonify({"status": "invalid", "error": str(e)}), 400

@app.route("/nonce", methods=["POST"])
def nonce():
    global CURRENT_NONCE
    CURRENT_NONCE = os.urandom(16)
    return jsonify({"nonce": base64.b64encode(CURRENT_NONCE).decode("utf-8")})

@app.route("/current_nonce", methods=["GET"])
def current_nonce():
    if CURRENT_NONCE is None:
        return jsonify({"error": "No nonce has been generated yet."}), 404
    return jsonify({"nonce": base64.b64encode(CURRENT_NONCE).decode("utf-8")})


if __name__ == "__main__":
    app.run(port=8000)