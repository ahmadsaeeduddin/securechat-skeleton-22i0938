# app/crypto/aes.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def _pad(data: bytes, block_size: int = 128) -> bytes:
    padder = padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()


def _unpad(padded: bytes, block_size: int = 128) -> bytes:
    unpadder = padding.PKCS7(block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_aes(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-128 ECB + PKCS#7 padding
    key: 16 bytes
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padded = _pad(plaintext)
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_aes(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _unpad(padded)
