# app/crypto/sign.py
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509


def sign(private_key, data: bytes) -> bytes:
    """
    RSA PKCS#1 v1.5 with SHA-256
    """
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def verify(cert: x509.Certificate, data: bytes, signature: bytes) -> bool:
    """
    Verify RSA signature using public key from certificate.
    """
    public_key = cert.public_key()
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
