```markdown
# 🔐 Remote Attestation Demo (Dockerized)

Simulates TPM-style attestation between a prover and verifier using Docker containers.

- 🛡️ **Verifier**: Flask app with a web UI to define trusted file state and verify attestations
- 🧪 **Prover**: Measures local files, signs a quote, and submits it to the verifier

---

## 🚀 Quickstart

### 1. Build and run both services
```bash
docker-compose up --build
```

### 2. In your browser:
- Visit: [http://localhost:8000](http://localhost:8000)
- Upload `start.sh` and `config.json`
- Click **Request Nonce**

### 3. Re-run the prover
```bash
docker-compose up --build prover
```

✅ You should see `status: ok` in the logs and/or UI.

---

## 🗂 Project Structure

```
verifier/      # Flask app, UI, and expected file logic
prover/        # Prover script + files to be measured
docker-compose.yml
```

---

## 🧠 What This Simulates

- TPM-style PCR extension (hash chaining of files)
- Remote attestation with signed quotes
- Replay prevention via nonces
- Manual attestation policy control (via file uploads)

---

## 📎 Notes

- Containers communicate via Docker network (`attestation-net`)
- Files are remeasured on each run
- No persistent volume: prover key and PCR reset every time

---

## 🧹 Cleanup

```bash
docker-compose down
```
```