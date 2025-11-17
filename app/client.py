"""Client implementation — plain TCP; no TLS. See assignment spec."""

import json
import os
import socket
from typing import Tuple

from dotenv import load_dotenv

from app.crypto import aes, dh, pki, sign
from app.common import utils
from app.storage import db, transcript

# We won't strictly depend on Pydantic models here to keep JSON flexible.

load_dotenv()


# ============ Helpers ============

def send_json(f, obj: dict) -> None:
    """
    Send a JSON object over a file-like socket wrapper, newline-delimited.
    """
    data = json.dumps(obj).encode("utf-8") + b"\n"
    f.write(data)
    f.flush()


def recv_json(f) -> dict | None:
    """
    Receive one JSON object from newline-delimited stream.
    Returns None on EOF.
    """
    line = f.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    return json.loads(line.decode("utf-8"))


def load_client_crypto():
    ca_path = os.getenv("CA_CERT", "certs/root_ca.crt")
    client_cert_path = os.getenv("CLIENT_CERT", "certs/client.crt")
    client_key_path = os.getenv("CLIENT_KEY", "certs/client.key")

    ca_cert = pki.load_cert(ca_path)
    client_cert = pki.load_cert(client_cert_path)
    client_key = pki.load_private_key(client_key_path)

    return ca_cert, client_cert, client_key


# ============ Control Plane (Step 7) ============

def client_handshake_and_login(
    sock: socket.socket,
    f,
) -> Tuple[bytes, object, object, str]:
    """
    Full control plane on client side:
      - hello / server hello
      - certificate validation
      - DH for control-plane key K_tmp
      - register/login over AES(K_tmp)
      - session DH for data-plane key K_sess

    Returns:
      (session_key, client_cert, server_cert, transcript_path)
    """
    ca_cert, client_cert, client_key = load_client_crypto()

    # --- Hello: send client cert and nonce ---
    from cryptography.hazmat.primitives import serialization
    client_cert_pem = client_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")
    
    c_nonce = os.urandom(16)
    hello_msg = {
        "type": "hello",
        "client_cert": client_cert_pem,
        "nonce": utils.b64encode(c_nonce),
    }
    send_json(f, hello_msg)

    # --- Receive server hello ---
    resp = recv_json(f)
    if resp is None or resp.get("type") != "server hello":
        raise RuntimeError("Did not receive valid server hello")

    server_cert_pem = resp["server_cert"]
    s_nonce_b64 = resp["nonce"]

    # Load server cert object
    from cryptography import x509  # local import to avoid confusion
    server_cert = x509.load_pem_x509_certificate(server_cert_pem.encode("utf-8"))

    # Validate server cert against CA + expected CN
    if not pki.verify_cert_chain(
        server_cert_pem,
        ca_cert,
        expected_cn="server.local",  # must match how you created it
    ):
        raise RuntimeError("BAD_CERT: server certificate failed validation")

    # Optionally: verify we can parse nonce (not strictly necessary)
    _ = utils.b64decode(s_nonce_b64)

    # --- DH for control-plane key K_tmp ---
    a = dh.generate_private()
    A = dh.compute_public(a)

    dh_client_msg = {
        "type": "dh_client",
        "g": dh.G,
        "p": str(dh.P),
        "A": str(A),
    }
    send_json(f, dh_client_msg)

    dh_server_msg = recv_json(f)
    if dh_server_msg is None or dh_server_msg.get("type") != "dh_server":
        raise RuntimeError("Did not receive dh_server")

    B = int(dh_server_msg["B"])
    shared = dh.compute_shared(B, a)
    K_tmp = dh.derive_key(shared)  # 16-byte AES key

    # --- Registration / Login using AES(K_tmp) ---

    while True:
        print("\n[+] Choose action:")
        print("  1) Register")
        print("  2) Login")
        choice = input("Enter 1 or 2: ").strip()
        if choice in ("1", "2"):
            break

    if choice == "1":
        # Register
        email = input("Email: ").strip()
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        inner = json.dumps(
            {"email": email, "username": username, "password": password}
        ).encode("utf-8")
        ct = aes.encrypt_aes(K_tmp, inner)
        outer = {
            "type": "register",
            "ct": utils.b64encode(ct),
        }
        send_json(f, outer)

        resp = recv_json(f)
        if resp is None or resp.get("type") != "register_result":
            raise RuntimeError("No register_result from server")

        if resp.get("status") != "ok":
            raise RuntimeError(f"Registration failed: {resp.get('reason')}")
        print("[+] Registration successful. Now please login.")

    # Login (either directly or after register)
    email = input("Login Email: ").strip()
    password = input("Password: ").strip()

    inner = json.dumps(
        {"email": email, "password": password}
    ).encode("utf-8")
    ct = aes.encrypt_aes(K_tmp, inner)
    outer = {
        "type": "login",
        "ct": utils.b64encode(ct),
    }
    send_json(f, outer)

    resp = recv_json(f)
    if resp is None or resp.get("type") != "login_result":
        raise RuntimeError("No login_result from server")

    if resp.get("status") != "ok":
        raise RuntimeError(f"Login failed: {resp.get('reason')}")

    print("[+] Login successful. Establishing session key...")

    # --- New DH for session key K_sess (data plane) ---
    a2 = dh.generate_private()
    A2 = dh.compute_public(a2)
    send_json(f, {"type": "session_dh_client", "A": str(A2)})

    msg = recv_json(f)
    if msg is None or msg.get("type") != "session_dh_server":
        raise RuntimeError("No session_dh_server from server")
    B2 = int(msg["B"])

    shared2 = dh.compute_shared(B2, a2)
    K_sess = dh.derive_key(shared2)

    print("[+] Session key established.")

    # --- Prepare transcript file (client side) ---
    transcripts_dir = os.getenv("TRANSCRIPTS_DIR", "transcripts")
    os.makedirs(transcripts_dir, exist_ok=True)
    # Use a simple name; doesn't need to match server file path
    transcript_path = os.path.join(transcripts_dir, "client_transcript.log")

    # Return everything needed for chat
    return K_sess, client_cert, server_cert, transcript_path, client_key


# ============ Data Plane (Step 8) ============

def client_chat_loop(
    sock: socket.socket,
    f,
    session_key: bytes,
    client_cert,
    server_cert,
    transcript_path: str,
    client_key,
) -> None:
    """
    After login + session DH:
      - Send encrypted messages to server
      - Sign each message
      - Log to transcript
      - At end, verify server's session receipt (Step 9/10)
    """
    tf = transcript.open_transcript(transcript_path)
    last_seq = 0
    seq = 1

    print("\n[+] You can now send messages. Type 'quit' to end session.\n")

    while True:
        msg = input("> ").strip()
        if msg.lower() in ("quit", "exit", ""):
            # Send a simple bye to allow server to finish gracefully
            send_json(f, {"type": "bye"})
            break

        ts = utils.now_ms()
        pt = msg.encode("utf-8")

        from hashlib import sha256

        ct = aes.encrypt_aes(session_key, pt)
        ct_b64 = utils.b64encode(ct)

        # Build digest: SHA256(seqno || ts || ct)
        seq_bytes = seq.to_bytes(8, "big")
        ts_bytes = ts.to_bytes(8, "big")
        h = sha256(seq_bytes + ts_bytes + ct_b64.encode("utf-8")).digest()

        sig_bytes = sign.sign(client_key, h)
        sig_b64 = utils.b64encode(sig_bytes)

        out_msg = {
            "type": "msg",
            "seqno": seq,
            "ts": ts,
            "ct": ct_b64,
            "sig": sig_b64,
        }
        send_json(f, out_msg)

        # Log message; use client_cert as canonical fingerprint identity
        transcript.log_message(tf, seq, ts, ct_b64, sig_b64, client_cert)

        # Wait for ACK (optional)
        resp = recv_json(f)
        if resp and resp.get("type") == "ack":
            print(f"[server ack] {resp.get('note', '')}")

        last_seq = seq
        seq += 1

    tf.close()

    # --- Receive server's session receipt and verify (Non-Repudiation) ---
    print("[+] Waiting for server session receipt...")
    receipt = recv_json(f)
    if receipt is None or receipt.get("type") != "receipt":
        print("[!] No receipt from server (or invalid)")
        return

    # Recompute transcript hash locally
    th_local = transcript.compute_transcript_hash(transcript_path)
    th_bytes = bytes.fromhex(th_local)

    sig_b64 = receipt["sig"]
    sig_bytes = utils.b64decode(sig_b64)

    ok = sign.verify(server_cert, th_bytes, sig_bytes)
    if ok:
        print("[+] Session receipt VERIFIED. Non-repudiation achieved.")
    else:
        print("[!] Session receipt verification FAILED (transcript tampering or mismatch).")


# ============ Main ============

def main():
    server_host = os.getenv("SERVER_HOST", "127.0.0.1")
    server_port = int(os.getenv("SERVER_PORT", "5000"))

    print(f"[+] Connecting to server at {server_host}:{server_port} ...")
    with socket.create_connection((server_host, server_port)) as sock:
        # Wrap socket in file-like object for newline-based JSON
        f = sock.makefile("rwb")

        session_key, client_cert, server_cert, transcript_path, client_key = client_handshake_and_login(sock, f)
        client_chat_loop(sock, f, session_key, client_cert, server_cert, transcript_path, client_key)


if __name__ == "__main__":
    main()
