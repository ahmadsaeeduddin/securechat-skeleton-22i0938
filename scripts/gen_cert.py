# scripts/gen_cert.py
import argparse
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_ca(ca_key_path: str, ca_cert_path: str):
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def issue_cert(cn: str, out_prefix: str, ca_key_path: str = "certs/root_ca.key",
               ca_cert_path: str = "certs/root_ca.crt"):
    os.makedirs(os.path.dirname(out_prefix), exist_ok=True)
    key_path = f"{out_prefix}.key"
    cert_path = f"{out_prefix}.crt"

    ca_key, ca_cert = load_ca(ca_key_path, ca_cert_path)

    # 1) Generate entity keypair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2) Build certificate signed by CA
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 3) Write entity private key
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # 4) Write entity cert
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Entity key:  {key_path}")
    print(f"[+] Entity cert: {cert_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Issue a cert signed by Root CA")
    parser.add_argument("--cn", required=True, help="Common Name for the certificate")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., certs/server)")
    args = parser.parse_args()
    issue_cert(args.cn, args.out)
