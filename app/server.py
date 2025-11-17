"""Server implementation — plain TCP; no TLS. See assignment spec."""

import json
import os
import socket
from typing import Tuple

from dotenv import load_dotenv

from app.crypto import aes, dh, pki, sign
from app.common import utils
from app.storage import db, transcript

load_dotenv()


# ============ Helpers ============

def send_json(f, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8") + b"\n"
    f.write(data)
    f.flush()


def recv_json(f) -> dict | None:
    line = f.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    return json.loads(line.decode("utf-8"))


def load_server_crypto():
    ca_path = os.getenv("CA_CERT", "certs/root_ca.crt")
    server_cert_path = os.getenv("SERVER_CERT", "certs/server.crt")
    server_key_path = os.getenv("SERVER_KEY", "certs/server.key")

    ca_cert = pki.load_cert(ca_path)
    server_cert = pki.load_cert(server_cert_path)
    server_key = pki.load_private_key(server_key_path)

    return ca_cert, server_cert, server_key


# ============ Control Plane (Step 7) ============

def handle_handshake_and_login(
    conn: socket.socket,
    f,
) -> Tuple[bytes, object, object, str, object]:
    """
    Full control plane on server side:
      - hello / server hello
      - client certificate validation
      - DH for control-plane K_tmp
      - register/login over AES(K_tmp)
      - session DH for K_sess
    Returns:
      (session_key, client_cert, server_cert, transcript_path, server_key)
    """
    ca_cert, server_cert, server_key = load_server_crypto()

    from cryptography import x509

    # --- Receive client's hello ---
    hello = recv_json(f)
    if hello is None or hello.get("type") != "hello":
        raise RuntimeError("Invalid or missing hello from client")

    client_cert_pem = hello["client_cert"]
    c_nonce_b64 = hello["nonce"]

    client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode("utf-8"))

    # Validate client certificate
    if not pki.verify_cert_chain(
        client_cert_pem,
        ca_cert,
        expected_cn="client.local",
    ):
        # BAD CERT – we can just close or send an error
        send_json(f, {"type": "error", "reason": "BAD_CERT"})
        raise RuntimeError("BAD_CERT: client certificate failed validation")

    _ = utils.b64decode(c_nonce_b64)

    # --- Send server hello ---
    from cryptography.hazmat.primitives import serialization
    server_cert_pem = server_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")
    
    s_nonce = os.urandom(16)
    server_hello = {
        "type": "server hello",
        "server_cert": server_cert_pem,
        "nonce": utils.b64encode(s_nonce),
    }
    send_json(f, server_hello)

    # --- Receive DH from client ---
    dh_client_msg = recv_json(f)
    if dh_client_msg is None or dh_client_msg.get("type") != "dh_client":
        raise RuntimeError("Missing dh_client")

    # We ignore g, p from client and use our own parameters (for safety)
    A = int(dh_client_msg["A"])

    b = dh.generate_private()
    B = dh.compute_public(b)

    shared = dh.compute_shared(A, b)
    K_tmp = dh.derive_key(shared)

    dh_server_msg = {"type": "dh_server", "B": str(B)}
    send_json(f, dh_server_msg)

    # --- Handle registration / login over AES(K_tmp) ---

    # Registration is optional; we accept either
    msg = recv_json(f)
    if msg is None:
        raise RuntimeError("No register/login message from client")

    # If registration first
    if msg.get("type") == "register":
        ct_b64 = msg["ct"]
        ct = utils.b64decode(ct_b64)
        inner = aes.decrypt_aes(K_tmp, ct)
        data = json.loads(inner.decode("utf-8"))

        email = data["email"]
        username = data["username"]
        password = data["password"]

        ok = db.create_user(email, username, password)
        if ok:
            send_json(f, {"type": "register_result", "status": "ok"})
        else:
            send_json(f, {"type": "register_result", "status": "fail", "reason": "db_insert_failed"})
            raise RuntimeError("Registration failed at DB level")

        # Next expect login
        msg = recv_json(f)
        if msg is None:
            raise RuntimeError("Expected login after register")

    # Now must be login
    if msg.get("type") != "login":
        raise RuntimeError("Expected login message")

    ct_b64 = msg["ct"]
    ct = utils.b64decode(ct_b64)
    inner = aes.decrypt_aes(K_tmp, ct)
    data = json.loads(inner.decode("utf-8"))

    email = data["email"]
    password = data["password"]

    if not db.verify_user(email, password):
        send_json(f, {"type": "login_result", "status": "fail", "reason": "bad_credentials"})
        raise RuntimeError("Login failed")

    send_json(f, {"type": "login_result", "status": "ok"})
    print(f"[+] User {email} authenticated successfully.")

    # --- Session DH for K_sess ---

    sess_client_msg = recv_json(f)
    if sess_client_msg is None or sess_client_msg.get("type") != "session_dh_client":
        raise RuntimeError("Missing session_dh_client")

    A2 = int(sess_client_msg["A"])
    b2 = dh.generate_private()
    B2 = dh.compute_public(b2)

    shared2 = dh.compute_shared(A2, b2)
    K_sess = dh.derive_key(shared2)

    send_json(f, {"type": "session_dh_server", "B": str(B2)})
    print("[+] Session key established for client.")

    # --- Prepare transcript file (server side) ---
    transcripts_dir = os.getenv("TRANSCRIPTS_DIR", "transcripts")
    os.makedirs(transcripts_dir, exist_ok=True)
    transcript_path = os.path.join(transcripts_dir, "server_transcript.log")

    return K_sess, client_cert, server_cert, transcript_path, server_key


# ============ Data Plane (Step 8) ============

def handle_chat(
    conn: socket.socket,
    f,
    session_key: bytes,
    client_cert,
    server_cert,
    transcript_path: str,
    server_key,
) -> None:
    """
    Receive encrypted messages from client, verify signatures, detect replay,
    log transcript, send ACKs, and finally issue a signed session receipt.
    """
    tf = transcript.open_transcript(transcript_path)
    last_seq = 0

    from hashlib import sha256

    while True:
        msg = recv_json(f)
        if msg is None:
            print("[*] Client disconnected")
            break

        mtype = msg.get("type")

        if mtype == "bye":
            print("[*] Client ended chat.")
            break

        if mtype != "msg":
            # ignore unexpected messages; could print or log
            continue

        seq = int(msg["seqno"])
        ts = int(msg["ts"])
        ct_b64 = msg["ct"]
        sig_b64 = msg["sig"]

        # Replay protection
        if seq <= last_seq:
            print(f"[!] REPLAY detected: seq={seq} (last_seq={last_seq})")
            send_json(f, {"type": "error", "reason": "REPLAY"})
            continue

        # Recompute digest
        seq_bytes = seq.to_bytes(8, "big")
        ts_bytes = ts.to_bytes(8, "big")
        h = sha256(seq_bytes + ts_bytes + ct_b64.encode("utf-8")).digest()

        sig_bytes = utils.b64decode(sig_b64)

        if not sign.verify(client_cert, h, sig_bytes):
            print("[!] Signature verification FAILED for message.")
            send_json(f, {"type": "error", "reason": "SIG_FAIL"})
            continue

        # Signature OK → decrypt
        ct = utils.b64decode(ct_b64)
        try:
            pt = aes.decrypt_aes(session_key, ct)
        except Exception as e:
            print(f"[!] AES decrypt failed: {e}")
            send_json(f, {"type": "error", "reason": "DECRYPT_FAIL"})
            continue

        text = pt.decode("utf-8", errors="replace")
        print(f"[msg seq={seq}] {text}")

        # Log message; to get identical transcript on both sides
        # we always log using client_cert as identity (same on client+server)
        transcript.log_message(tf, seq, ts, ct_b64, sig_b64, client_cert)

        # Simple ACK
        send_json(f, {"type": "ack", "note": f"received seq={seq}"})

        last_seq = seq

    tf.close()

    # --- Issue session receipt (Non-Repudiation) ---
    if last_seq == 0:
        print("[*] No messages exchanged; skipping receipt.")
        return

    th = transcript.compute_transcript_hash(transcript_path)
    th_bytes = bytes.fromhex(th)

    sig_bytes = sign.sign(server_key, th_bytes)
    sig_b64 = utils.b64encode(sig_bytes)

    receipt = {
        "type": "receipt",
        "peer": "server",
        "first_seq": 1,
        "last_seq": last_seq,
        "transcript_sha256": th,
        "sig": sig_b64,
    }
    send_json(f, receipt)
    print("[+] Session receipt sent to client.")


# ============ Main Server Loop ============

def main():
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "5000"))

    # Ensure DB schema exists (users table)
    db.init_schema()

    print(f"[+] SecureChat server listening on {host}:{port} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(5)

        while True:
            conn, addr = s.accept()
            print(f"[+] New connection from {addr}")
            with conn:
                f = conn.makefile("rwb")
                try:
                    session_key, client_cert, server_cert, transcript_path, server_key = handle_handshake_and_login(
                        conn, f
                    )
                    handle_chat(conn, f, session_key, client_cert, server_cert, transcript_path, server_key)
                except Exception as e:
                    print(f"[!] Error handling client {addr}: {e}")
                finally:
                    try:
                        f.close()
                    except Exception:
                        pass
                    print(f"[+] Connection {addr} closed.")


if __name__ == "__main__":
    main()
