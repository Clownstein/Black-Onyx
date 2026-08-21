#!/usr/bin/env python3
"""Generate internal CA + per-service TLS material for Compose mTLS (stdlib only).

Writes under infrastructure/tls/generated/ (gitignored). No openssl CLI required.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "infrastructure" / "tls" / "generated"
SERVICES = [
    "incident-api",
    "ingestion-gateway",
    "model-gateway",
    "correlation-engine",
    "asset-registry",
    "notification-service",
    "threat-intel-service",
    "inference-worker",
    "response-orchestrator",
    "integration-hub",
    "redpanda",
    "client",
]


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    ca_key_path = OUT / "ca.key"
    ca_crt_path = OUT / "ca.crt"
    if args.force or not ca_crt_path.exists():
        ca_key = _key()
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AutoAnalyzer Internal CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1))
            .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        _write_key(ca_key_path, ca_key)
        _write_cert(ca_crt_path, ca_cert)
    else:
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())

    for name in SERVICES:
        crt_path = OUT / f"{name}.crt"
        key_path = OUT / f"{name}.key"
        if not args.force and crt_path.exists():
            continue
        key = _key()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        san = x509.SubjectAlternativeName(
            [
                x509.DNSName(name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1))
            .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=825))
            .add_extension(san, critical=False)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        _write_key(key_path, key)
        _write_cert(crt_path, cert)

    print(f"wrote certs under {OUT}")


if __name__ == "__main__":
    main()
