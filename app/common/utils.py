# app/common/utils.py
import base64
import hashlib
import time


def b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def now_ms() -> int:
    return int(time.time() * 1000)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
