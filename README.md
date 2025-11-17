# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

---

## 🧩 Overview

You are provided with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what you must implement.

Your main tasks:

- Implement the **application‑layer secure chat protocol**  
- Integrate cryptographic primitives (AES, RSA, DH, SHA‑256)  
- Demonstrate **CIANR** using Wireshark, tamper tests, replay tests, and signed session receipts  
- Produce professional documentation and reproducible evidence  

---

## 🏗 Folder Structure

```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (via cryptography)
│  │  ├─ dh.py               # Classic DH helpers + SHA-256→AES key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity period, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic models (hello/login/msg/receipt)
│  │  └─ utils.py            # Base64, now_ms(), sha256_hex helper functions
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark checklist
├─ certs/.keep               # Local certs/keys (never committed)
├─ transcripts/.keep         # Session logs (never committed)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, logs, binaries, certs, transcripts
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Syntax-check only (no execution)
```

---

## ⚙️ Setup Instructions

### 1️⃣ Create and activate environment

**Windows:**
```powershell
python -m venv .venv
.\.venv\Scriptsctivate
pip install -r requirements.txt
copy .env.example .env
```

**Linux/Mac:**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

---

### 2️⃣ Initialize MySQL (via Docker recommended)

```bash
docker run -d --name securechat-db   -e MYSQL_ROOT_PASSWORD=rootpass   -e MYSQL_DATABASE=securechat   -e MYSQL_USER=scuser   -e MYSQL_PASSWORD=scpass   -p 3306:3306 mysql:8
```

---

### 3️⃣ Create database tables

```bash
python -m app.storage.db --init
```

---

### 4️⃣ Generate PKI Certificates

```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
python scripts.gen_cert.py --cn server.local --out certs/server
python scripts.gen_cert.py --cn client.local --out certs/client
```

---

### 5️⃣ Run Server and Client

Start server:
```bash
python -m app.server
```

Start client:
```bash
python -m app.client
```

Then choose:
- Register
- Login
- Chat securely
- Exit → generates SessionReceipt + transcript hash

---

## ⚙️ Configuration Requirements

Your `.env` file must contain the following:

```
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=scuser
MYSQL_PASSWORD=scpass
MYSQL_DB=securechat

CA_CERT=certs/root_ca.crt
SERVER_CERT=certs/server.crt
SERVER_KEY=certs/server.key
CLIENT_CERT=certs/client.crt
CLIENT_KEY=certs/client.key

TRANSCRIPTS_DIR=transcripts
```

---

## ▶️ Sample Input / Output Formats

### ✔ Hello Message (Client → Server)
```json
{
  "type": "hello",
  "client_cert": "-----BEGIN CERTIFICATE----- ...",
  "nonce": "k28ff92Slw=="
}
```

### ✔ Encrypted Login Request
```json
{
  "type": "login",
  "email": "user@example.com",
  "pwd": "base64_of_sha256(salt||pwd)",
  "nonce": "AF93jf20sa=="
}
```

### ✔ Encrypted Chat Message
```json
{
  "type": "msg",
  "seqno": 4,
  "ts": 1731382892000,
  "ct": "kfu93nsQz01fsg==",
  "sig": "QkFTRTY0X1NPVUdORURfU0lHTkFUVVJF"
}
```

### ✔ Session Receipt
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "f3cd8c1a2736607f2f3cbf43026b868e...",
  "sig": "AJDJei92ls9=="
}
```

---

## 🏁 Expected SecureChat Behaviour

✔ All messages encrypted via **AES-128**  
✔ Integrity and authenticity via **RSA signatures**  
✔ Replay prevention via **sequence numbers**  
✔ Tamper detection (`SIG_FAIL`)  
✔ Certificate validation (`BAD_CERT`)  
✔ Non‑repudiation via signed transcript hash  

---

## 🔗 GitHub Repository Link

Replace this with your fork link:

📎 **https://github.com/ahmadsaeeduddin/securechat-skeleton-22i0938**

---

---

## 📝 Required for Submission (GCR)

- ZIP of GitHub repo  
- MySQL schema dump + sample rows  
- Updated README.md (this file)  
- `RollNumber-FullName-Report-A02.docx`  
