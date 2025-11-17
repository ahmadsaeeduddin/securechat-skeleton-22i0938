# scripts/gen_ca.py
import argparse
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_root_ca(common_name: str, out_dir: str = "certs"):
    os.makedirs(out_dir, exist_ok=True)
    key_path = os.path.join(out_dir, "root_ca.key")
    cert_path = os.path.join(out_dir, "root_ca.crt")

    # 1) Generate RSA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2) Build self-signed X.509 certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))  # ~10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    # 3) Write private key
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # 4) Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Root CA key:  {key_path}")
    print(f"[+] Root CA cert: {cert_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", required=True, help="Common Name for Root CA")
    parser.add_argument("--out", default="certs", help="Output directory for CA files")
    args = parser.parse_args()
    generate_root_ca(args.name, args.out)
