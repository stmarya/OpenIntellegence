"""mTLS certificate authority for endpoint agents.

Enrollment flow
---------------
1. The installer is given a single-use ``ngs_agnt_`` enrollment key.
2. The agent generates a keypair **locally** and sends only a CSR. The
   private key never leaves the endpoint and is never transmitted to us.
3. The gateway validates the enrollment key, signs the CSR, and returns a
   short-lived client certificate plus the CA chain.
4. All later traffic authenticates with that certificate; the enrollment key
   is burned.

The subject CN is the agent UUID, not the hostname. Hostnames get renamed
and reused, so binding identity to one would let a re-imaged machine
impersonate its predecessor.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.core.config import Settings


class CertificateAuthorityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    serial: str
    fingerprint_sha256: str
    certificate_pem: str
    ca_chain_pem: str
    not_before: dt.datetime
    not_after: dt.datetime


def _fingerprint(cert: x509.Certificate) -> str:
    raw = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in raw)


class AgentCertificateAuthority:
    """Issues and verifies endpoint agent client certificates."""

    def __init__(self, ca_cert: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey) -> None:
        self._ca_cert = ca_cert
        self._ca_key = ca_key

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_settings(cls, settings: Settings) -> AgentCertificateAuthority:
        if not settings.agent_ca_cert_path or not settings.agent_ca_key_path:
            raise CertificateAuthorityError(
                "AGENT_CA_CERT_PATH and AGENT_CA_KEY_PATH must be configured"
            )

        cert_bytes = Path(settings.agent_ca_cert_path).read_bytes()
        key_bytes = Path(settings.agent_ca_key_path).read_bytes()
        password = (
            settings.agent_ca_key_password.get_secret_value().encode()
            if settings.agent_ca_key_password
            else None
        )

        ca_cert = x509.load_pem_x509_certificate(cert_bytes)
        ca_key = serialization.load_pem_private_key(key_bytes, password=password)
        if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
            raise CertificateAuthorityError("agent CA key must be an EC private key")

        return cls(ca_cert, ca_key)

    @classmethod
    def create_self_signed(
        cls, *, common_name: str = "OpenIntelligence Agent CA", valid_days: int = 3650
    ) -> tuple[AgentCertificateAuthority, str, str]:
        """Generate a fresh CA. Intended for development and tests.

        Returns the CA plus the certificate and private key in PEM form. In
        production the CA key belongs in an HSM or KMS, not on disk.
        """
        key = ec.generate_private_key(ec.SECP384R1())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenIntelligence"),
            ]
        )
        now = dt.datetime.now(dt.UTC)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA384())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        return cls(cert, key), cert_pem, key_pem

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------

    def sign_csr(
        self,
        csr_pem: str,
        *,
        agent_id: str,
        tenant_id: str,
        ttl_days: int = 90,
    ) -> IssuedCertificate:
        """Sign an agent CSR and return a client certificate.

        The CSR's own subject is discarded and replaced with one we control.
        Trusting a client-supplied subject would let an agent name itself
        anything, including another tenant's identity.
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except ValueError as exc:
            raise CertificateAuthorityError(f"malformed CSR: {exc}") from exc

        if not csr.is_signature_valid:
            raise CertificateAuthorityError("CSR signature is invalid")

        try:
            uuid.UUID(agent_id)
            uuid.UUID(tenant_id)
        except ValueError as exc:
            raise CertificateAuthorityError("agent_id and tenant_id must be UUIDs") from exc

        now = dt.datetime.now(dt.UTC)
        not_after = now + dt.timedelta(days=ttl_days)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, tenant_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenIntelligence Agent"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # Client auth only. Without this an agent certificate could be
            # used to stand up a server impersonating the platform.
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(
                    f"urn:openintelligence:agent:{agent_id}"
                )]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA384())
        )

        return IssuedCertificate(
            serial=format(cert.serial_number, "x"),
            fingerprint_sha256=_fingerprint(cert),
            certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            ca_chain_pem=self._ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
            not_before=now,
            not_after=not_after,
        )

    def parse_client_certificate(self, cert_pem: str) -> tuple[str, str]:
        """Extract ``(agent_id, tenant_id)`` from a presented client cert.

        The TLS terminator is responsible for verifying the chain; this only
        reads the identity out of an already-verified certificate.
        """
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        if not cn or not ou:
            raise CertificateAuthorityError("client certificate is missing CN or OU")
        return str(cn[0].value), str(ou[0].value)
