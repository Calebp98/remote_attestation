import os
import base64
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from werkzeug.utils import secure_filename

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.secret_key = "supersecret"  # Can be any string (for demo purposes)


CURRENT_NONCE = None
EXPECTED_PCR = None
UPLOAD_FOLDER = "expected_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html", status=None)

@app.route("/set_expected_files", methods=["POST"])
def set_expected_files():
    global EXPECTED_PCR
    files = request.files.getlist("expected_files")

    uploaded_names = []
    file_paths = []
    for file in files:
        filename = secure_filename(file.filename)
        uploaded_names.append(filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(path)
        file_paths.append(path)

    # TPM-style hash extension
    digest = b"\x00" * 32
    for path in file_paths:
        with open(path, "rb") as f:
            content = f.read()
            h = hashes.Hash(hashes.SHA256())
            h.update(digest + content)
            digest = h.finalize()

    EXPECTED_PCR = digest

    flash("✅ Expected PCR set from uploaded files.")
    return render_template("index.html", status="Expected PCR set", uploaded_files=uploaded_names)


@app.route("/attest", methods=["POST"])
def attest():
    global CURRENT_NONCE, EXPECTED_PCR
    data = request.json

    try:
        # Decode submitted data
        quote = base64.b64decode(data["quote"])
        signature = base64.b64decode(data["signature"])
        public_key_pem = data["public_key"].encode()

        public_key = serialization.load_pem_public_key(public_key_pem)

        # Signature verification
        public_key.verify(
            signature,
            quote,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Split quote
        expected_nonce = CURRENT_NONCE
        received_nonce = quote[:len(expected_nonce)]
        actual_pcr = quote[len(expected_nonce):]

        if received_nonce != expected_nonce:
            return jsonify({"status": "replay detected"}), 400

        if EXPECTED_PCR is None:
            return jsonify({"status": "no expected pcr set"}), 400

        if actual_pcr != EXPECTED_PCR:
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
    app.run(host="0.0.0.0", port=8000)

