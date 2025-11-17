# app/crypto/dh.py
import secrets
import hashlib


# You can pick fixed safe prime and generator, or generate them. For simplicity:
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
G = 2


def generate_private() -> int:
    # Large random < P
    return secrets.randbelow(P - 2) + 2


def compute_public(a: int) -> int:
    return pow(G, a, P)


def compute_shared(peer_pub: int, a: int) -> int:
    return pow(peer_pub, a, P)


def derive_key(shared_secret: int) -> bytes:
    """
    K = Trunc16(SHA256(big-endian(Ks)))
    """
    # Convert to big-endian bytes
    ss_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    h = hashlib.sha256(ss_bytes).digest()
    return h[:16]  # 16 bytes AES-128 key
