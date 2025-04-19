

```markdown
# 🔐 Remote Attestation Demo

A hands-on, educational demo of TPM-style remote attestation, built with Python and Flask.

This project simulates how a **prover** (e.g., a client or device) can prove its system state to a **verifier**, using cryptographic signatures, nonce-based freshness, and hashed configuration values (PCRs).

It includes two browser-based user interfaces:
- 🛡️ Verifier UI (to issue and check attestations)
- 🧪 Prover UI (to generate quotes and provide identity)

---

## 🧠 What This Demonstrates

- TPM-style attestation using RSA keys
- Hash-based PCR state verification
- Signature verification using `cryptography`
- Nonce-based replay protection
- Two-sided web interaction (verifier + prover)

---

## 🧪 How It Works

1. **Verifier**:
   - Generates a nonce (challenge)
   - Defines an expected system state
   - Verifies attestation responses (quote, signature, public key)

2. **Prover**:
   - Fetches the current nonce from the verifier
   - Hashes its system state
   - Signs `nonce + pcr` with its private key
   - Displays everything for copy-paste into the verifier UI

---

## 🚀 Quickstart

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install flask cryptography requests
```

### 2. Start the verifier (port 8000)

```bash
python verifier.py
```

Visit: [http://localhost:8000](http://localhost:8000)

- Click **Request Nonce**
- Set the expected system state

### 3. Start the prover UI (port 5000)

```bash
python prover_ui.py
```

Visit: [http://localhost:5000](http://localhost:5000)

- View the generated quote, signature, and public key
- Copy them into the verifier UI

---

## 📁 Project Structure

```
verifier.py       # Flask server with web UI and attestation logic
prover_ui.py      # Flask server with UI to generate and show quote
prover_core.py    # Handles key generation, PCR hashing, and quote signing
templates/
  ├── index.html    # Verifier UI
  └── prover.html   # Prover UI
keys/             # Stores persistent prover keypair (priv.pem, pub.pem)
```

---

## ✨ Features

- Persistent keypair (saved in `keys/`)
- Manual quote inspection
- Web-based flow for learning and demoing
- Built using only Flask, requests, and Python cryptography

---
```
