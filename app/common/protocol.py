# app/common/protocol.py
from pydantic import BaseModel
from typing import Literal


class Hello(BaseModel):
    type: Literal["hello"]
    client_cert: str
    nonce: str


class ServerHello(BaseModel):
    type: Literal["server hello"]
    server_cert: str
    nonce: str


class Register(BaseModel):
    type: Literal["register"]
    email: str
    username: str
    pwd: str     # base64(sha256(salt||pwd)) or encrypted blob, see spec
    salt: str    # base64


class Login(BaseModel):
    type: Literal["login"]
    email: str
    pwd: str     # base64(sha256(salt||pwd)) or encrypted blob
    nonce: str   # base64


class ChatMessage(BaseModel):
    type: Literal["msg"]
    seqno: int
    ts: int
    ct: str      # base64 ciphertext
    sig: str     # base64 signature


class SessionReceipt(BaseModel):
    type: Literal["receipt"]
    peer: Literal["client", "server"]
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str                # base64 signature
