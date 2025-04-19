Sure! Here's your complete `README.md` as a single copy-pasteable file:

---

```markdown
# 🛡️ Remote Attestation Simulator

This is a minimal Python-based implementation of remote attestation, inspired by how Trusted Platform Modules (TPMs) verify system integrity in real-world environments.

It simulates a secure quote-signing process between a **Prover** (device) and a **Verifier** (remote checker), using RSA keys, hashed system state (PCRs), and nonces to prevent replay attacks.

---

## ✨ Features

- Simulates TPM-style PCR hashing
- Generates verifiable signed quotes
- Prevents replay attacks using nonce challenge/response
- Full client-server model over HTTP using Flask and `requests`
- Signature verification using the `cryptography` library

---

## 🧪 How It Works

1. **Verifier** issues a fresh nonce (`POST /nonce`)
2. **Prover**:
   - Simulates a system state
   - Hashes it like a PCR
   - Signs the nonce + hash
   - Sends back the `quote`, `signature`, and `public key` (`POST /attest`)
3. **Verifier**:
   - Verifies the signature
   - Checks that the nonce matches
   - Validates the PCR hash against a known-good state

---

## 🚀 Quickstart

### Setup
```bash
git clone https://github.com/yourname/remote-attestation-simulator.git
cd remote-attestation-simulator
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run Verifier
```bash
python verifier.py
```

### Run Prover (in a separate terminal)
```bash
python prover.py
```

---

## 📁 File Structure

```
prover.py        # Prover client (generates and signs quote)
verifier.py      # Verifier HTTP server (issues nonce, validates quote)
prover_core.py   # Logic for quote creation and key management
```

---

## 📚 License

MIT – use it, build on it, break it, learn from it.

