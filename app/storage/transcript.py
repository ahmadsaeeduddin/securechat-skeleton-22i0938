# app/storage/transcript.py
import os
from typing import TextIO
from . import db  # if needed for paths, or use dotenv
from cryptography import x509
from app.crypto.pki import get_cert_fingerprint
from app.common.utils import sha256_hex


def open_transcript(path: str) -> TextIO:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return open(path, "a+", encoding="utf-8")


def log_message(
    f: TextIO,
    seqno: int,
    ts: int,
    ct_b64: str,
    sig_b64: str,
    peer_cert: x509.Certificate,
):
    fingerprint = get_cert_fingerprint(peer_cert)
    line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{fingerprint}\n"
    f.write(line)
    f.flush()


def compute_transcript_hash(path: str) -> str:
    with open(path, "rb") as f:
        data = f.read()
    return sha256_hex(data)
