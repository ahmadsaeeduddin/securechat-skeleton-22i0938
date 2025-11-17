# app/crypto/pki.py
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from datetime import datetime


def load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def verify_cert_chain(
    peer_cert_pem: str,
    ca_cert: x509.Certificate,
    expected_cn: Optional[str] = None,
) -> bool:
    """
    Verify that peer_cert:
      - Is signed by CA
      - Is within validity period
      - Has CN == expected_cn (if provided)
    """
    cert = x509.load_pem_x509_certificate(peer_cert_pem.encode("utf-8"))

    # 1) Check validity period
    now = datetime.utcnow()
    if not (cert.not_valid_before <= now <= cert.not_valid_after):
        return False

    # 2) CN check
    if expected_cn is not None:
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        if cn_attr.value != expected_cn:
            return False

    # 3) Signature verification: cert signed by CA
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:
        return False

    return True


def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """Return SHA-256 fingerprint as hex string."""
    return cert.fingerprint(hashes.SHA256()).hex()
