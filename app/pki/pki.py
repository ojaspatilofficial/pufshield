"""Public Key Infrastructure: a local root CA, intermediate CAs, and device certificates.

PUFShield bootstraps a trust chain:

* one self-signed root CA certificate (offline / trusted anchor),
* optional intermediate CA certificates signed by the root, and
* a device certificate per provisioned device, signed by a CA and
  embedding the device's public key.

The manager supports certificate creation, signature validation, expiry
checking, CA key-usage enforcement, and full chain-of-trust verification
(including RFC 5280 path-length constraints). CA private keys never leave
the key store and are never exposed through any API; only certificate
verification is exported to the service layer.
"""

from __future__ import annotations

import datetime as dt
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..config import get_settings
from .key_store import KeyStore

logger = logging.getLogger(__name__)

_CURVE = ec.SECP256R1()
_HASH = hashes.SHA256
_MAX_CHAIN_LENGTH = 8

_CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=None, decipher_only=None,
)
_DEVICE_KEY_USAGE = x509.KeyUsage(
    digital_signature=True, content_commitment=False, key_encipherment=True,
    data_encipherment=False, key_agreement=False, key_cert_sign=False,
    crl_sign=False, encipher_only=None, decipher_only=None,
)


def _utcnow() -> dt.datetime:
    return dt.datetime.utcnow()


def is_ca_certificate(cert: x509.Certificate) -> bool:
    """True if the certificate carries the CA basic constraint."""
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def is_valid_at(cert: x509.Certificate, at_time: dt.datetime | None = None) -> bool:
    """True if ``cert`` is inside its validity window at ``at_time`` (default: now)."""
    at = at_time or _utcnow()
    return cert.not_valid_before <= at <= cert.not_valid_after


def is_expired(cert: x509.Certificate, at_time: dt.datetime | None = None) -> bool:
    """True if ``cert`` has expired at ``at_time`` (default: now)."""
    at = at_time or _utcnow()
    return at > cert.not_valid_after


def _verify_signature(cert: x509.Certificate, public_key) -> None:
    """Verify the certificate's signature; raises on failure."""
    hash_algorithm = cert.signature_hash_algorithm
    if hash_algorithm is None:
        raise ValueError("certificate has no signature hash algorithm")
    public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hash_algorithm))


def _key_usage(cert: x509.Certificate) -> x509.KeyUsage | None:
    try:
        return cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return None


def _basic_constraints(cert: x509.Certificate) -> x509.BasicConstraints | None:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return None


def _cert_common_name(cert: x509.Certificate) -> str:
    attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attributes[0].value if attributes else str(cert.subject)


class PKIError(Exception):
    """Raised for PKI-related failures."""


class PKIManager:
    """Manages the root CA, intermediate CAs, and device certificate lifecycle."""

    def __init__(self, key_store: KeyStore | None = None) -> None:
        self.settings = get_settings()
        self.key_store = key_store or KeyStore()

    # -- generic certificate builder -----------------------------------

    def _build_certificate(
        self,
        *,
        subject: x509.Name,
        issuer: x509.Name,
        public_key,
        signing_key,
        serial_number: int,
        not_valid_before: dt.datetime,
        not_valid_after: dt.datetime,
        ca: bool,
        key_usage: x509.KeyUsage,
        path_length: int | None = None,
    ) -> x509.Certificate:
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
            .add_extension(key_usage, critical=True)
        )
        return builder.sign(signing_key, _HASH())

    # -- root CA -------------------------------------------------------

    def ensure_root_ca(self, common_name: str = "PUFShield Root CA") -> x509.Certificate:
        """Create and persist the root CA if it does not exist yet."""
        existing = self.key_store.load_certificate("ca", "ca_cert")
        if existing is not None:
            return existing

        key = ec.generate_private_key(_CURVE)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = _utcnow()
        cert = self._build_certificate(
            subject=subject,
            issuer=issuer,
            public_key=key.public_key(),
            signing_key=key,
            serial_number=x509.random_serial_number(),
            not_valid_before=now - dt.timedelta(minutes=1),
            not_valid_after=now + dt.timedelta(days=self.settings.ca_certificate_valid_days),
            ca=True,
            key_usage=_CA_KEY_USAGE,
            path_length=None,
        )
        self.key_store.save_private_key(key, "ca", "ca_key")
        self.key_store.save_certificate(cert, "ca", "ca_cert")
        logger.info("Root CA created: %s", common_name)
        return cert

    def get_root_ca(self) -> x509.Certificate:
        cert = self.key_store.load_certificate("ca", "ca_cert")
        if cert is None:
            raise PKIError("Root CA not provisioned; call ensure_root_ca() first")
        return cert

    # -- intermediate CAs ----------------------------------------------

    def issue_intermediate_ca(
        self,
        common_name: str,
        validity_days: int | None = None,
        path_length: int | None = 1,
    ) -> x509.Certificate:
        """Issue a subordinate CA signed by the root and persist it."""
        ca_cert = self.ensure_root_ca()
        ca_key = self.key_store.load_private_key("ca", "ca_key")
        if ca_key is None:
            raise PKIError("Root CA key missing")

        key = ec.generate_private_key(_CURVE)
        now = _utcnow()
        cert = self._build_certificate(
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]),
            issuer=ca_cert.subject,
            public_key=key.public_key(),
            signing_key=ca_key,
            serial_number=x509.random_serial_number(),
            not_valid_before=now - dt.timedelta(minutes=1),
            not_valid_after=now + dt.timedelta(days=validity_days or self.settings.intermediate_certificate_valid_days),
            ca=True,
            key_usage=_CA_KEY_USAGE,
            path_length=path_length,
        )
        self.key_store.save_private_key(key, "intermediate", common_name)
        self.key_store.save_certificate(cert, "intermediate", common_name)
        logger.info("Issued intermediate CA %s", common_name)
        return cert

    def get_intermediate_ca(self, common_name: str) -> x509.Certificate:
        cert = self.key_store.load_certificate("intermediate", common_name)
        if cert is None:
            raise PKIError(f"No intermediate CA {common_name!r}")
        return cert

    # -- device certificates -------------------------------------------

    def issue_device_certificate(
        self,
        device_id: str,
        public_key: ec.EllipticCurvePublicKey | None = None,
        common_name: str | None = None,
        serial: int | None = None,
        not_valid_before: dt.datetime | None = None,
        not_valid_after: dt.datetime | None = None,
        issuer_name: str = "root",
    ) -> x509.Certificate:
        """Issue a leaf certificate for a device.

        The certificate binds the device's public key to its identity.
        When ``public_key`` is omitted a fresh key pair is generated and
        persisted under the device's key alias. ``issuer_name`` selects
        the signing CA: ``"root"`` or an intermediate CA common name.
        """
        if issuer_name == "root":
            ca_cert = self.ensure_root_ca()
            ca_key = self.key_store.load_private_key("ca", "ca_key")
        else:
            ca_cert = self.get_intermediate_ca(issuer_name)
            ca_key = self.key_store.load_private_key("intermediate", issuer_name)
        if ca_key is None:
            raise PKIError(f"signing key missing for CA {issuer_name!r}")

        key = public_key
        if key is None:
            private = ec.generate_private_key(_CURVE)
            key = private.public_key()
            self.key_store.save_private_key(private, "device", device_id)

        cn = common_name or f"device:{device_id}"
        now = _utcnow()
        cert = self._build_certificate(
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]),
            issuer=ca_cert.subject,
            public_key=key,
            signing_key=ca_key,
            serial_number=serial if serial is not None else x509.random_serial_number(),
            not_valid_before=not_valid_before if not_valid_before is not None else now - dt.timedelta(minutes=1),
            not_valid_after=not_valid_after if not_valid_after is not None else now + dt.timedelta(
                days=self.settings.boot_certificate_valid_days
            ),
            ca=False,
            key_usage=_DEVICE_KEY_USAGE,
        )
        self.key_store.save_certificate(cert, "device", device_id)
        logger.info("Issued device certificate for %s (issuer %s)", device_id, _cert_common_name(ca_cert))
        return cert

    def get_device_certificate(self, device_id: str) -> x509.Certificate:
        cert = self.key_store.load_certificate("device", device_id)
        if cert is None:
            raise PKIError(f"No certificate for device {device_id!r}")
        return cert

    # -- validation ----------------------------------------------------

    def validate_ca_certificate(self, ca_cert: x509.Certificate, at_time: dt.datetime | None = None) -> list[str]:
        """Validate a self-signed CA anchor; returns a list of error strings (empty = valid)."""
        errors: list[str] = []
        if ca_cert.issuer != ca_cert.subject:
            errors.append("CA certificate is not self-signed")
        if not is_ca_certificate(ca_cert):
            errors.append("CA certificate lacks the CA basic constraint")
        usage = _key_usage(ca_cert)
        if usage is not None and not usage.key_cert_sign:
            errors.append("CA certificate KeyUsage lacks key_cert_sign")
        try:
            _verify_signature(ca_cert, ca_cert.public_key())
        except Exception:  # noqa: BLE001 - any failure is reported as an invalid CA
            errors.append("CA certificate self-signature verification failed")
        at = at_time or _utcnow()
        if not is_valid_at(ca_cert, at):
            errors.append("CA certificate is outside its validity window")
        return errors

    def validate_leaf_certificate(
        self,
        cert: x509.Certificate,
        ca_cert: x509.Certificate,
        at_time: dt.datetime | None = None,
    ) -> list[str]:
        """Validate a leaf certificate against its direct issuer; returns error strings."""
        errors: list[str] = []
        if is_ca_certificate(cert):
            errors.append("certificate must not carry the CA basic constraint")
        usage = _key_usage(cert)
        if usage is not None and not usage.digital_signature:
            errors.append("certificate KeyUsage lacks digital_signature")
        if cert.issuer != ca_cert.subject:
            errors.append("certificate issuer does not match the CA subject")
        try:
            _verify_signature(cert, ca_cert.public_key())
        except Exception:  # noqa: BLE001 - any failure is reported as an invalid signature
            errors.append("certificate signature does not verify against the CA public key")
        at = at_time or _utcnow()
        if at < cert.not_valid_before:
            errors.append("certificate is not yet valid")
        if at > cert.not_valid_after:
            errors.append("certificate has expired")
        return errors

    def validate_certificate(
        self,
        cert: x509.Certificate,
        ca_cert: x509.Certificate | None = None,
        at_time: dt.datetime | None = None,
    ) -> list[str]:
        """Validate a device certificate issued directly by ``ca_cert`` (default: root CA)."""
        ca = ca_cert or self.get_root_ca()
        at = at_time or _utcnow()
        return self.validate_leaf_certificate(cert, ca, at_time=at) + self.validate_ca_certificate(ca, at_time=at)

    def verify_device_certificate(
        self,
        device_cert: x509.Certificate,
        ca_cert: x509.Certificate | None = None,
        at_time: dt.datetime | None = None,
    ) -> bool:
        """True if the device certificate is valid now (or at ``at_time``)."""
        return not self.validate_certificate(device_cert, ca_cert=ca_cert, at_time=at_time)

    def verify_chain(
        self,
        leaf: x509.Certificate,
        intermediates: list[x509.Certificate] | None = None,
        root: x509.Certificate | None = None,
        at_time: dt.datetime | None = None,
    ) -> list[str]:
        """Verify ``leaf`` chains to ``root`` through any intermediates.

        Returns a list of error strings; an empty list means the chain is
        valid at ``at_time``. Checks each link's signature, issuer/subject
        match, validity window, CA basic constraints, key usage, and
        RFC 5280 path-length constraints.
        """
        root_cert = root or self.get_root_ca()
        pool = list(intermediates or [])
        if root_cert not in pool:
            pool.append(root_cert)
        at = at_time or _utcnow()
        errors: list[str] = []

        # Walk from the leaf toward a self-signed certificate.
        chain = [leaf]
        seen = {leaf}
        current = leaf
        while current.subject != current.issuer:
            if len(chain) >= _MAX_CHAIN_LENGTH:
                errors.append("certificate chain exceeds the maximum length")
                break
            parent = next((c for c in pool if c.subject == current.issuer and c not in seen), None)
            if parent is None:
                errors.append(f"no issuer found for certificate {_cert_common_name(current)!r}")
                break
            chain.append(parent)
            seen.add(parent)
            current = parent
        if current != root_cert:
            errors.append("certificate chain does not terminate at the trusted root CA")

        # Validate every certificate and every link.
        for index, cert in enumerate(chain):
            parent = chain[index + 1] if index + 1 < len(chain) else None
            if index == 0:
                if parent is None:
                    errors.append("leaf certificate has no issuer in the chain")
                else:
                    errors.extend(self.validate_leaf_certificate(cert, parent, at_time=at))
            elif parent is None:
                errors.extend(self.validate_ca_certificate(cert, at_time=at))
            else:
                name = _cert_common_name(cert)
                if not is_ca_certificate(cert):
                    errors.append(f"certificate {name!r} is not a CA")
                usage = _key_usage(cert)
                if usage is not None and not usage.key_cert_sign:
                    errors.append(f"certificate {name!r} KeyUsage lacks key_cert_sign")
                if not is_valid_at(cert, at):
                    errors.append(f"certificate {name!r} is outside its validity window")
                if cert.issuer != parent.subject:
                    errors.append(f"certificate {name!r} issuer does not match its parent")
                try:
                    _verify_signature(cert, parent.public_key())
                except Exception:  # noqa: BLE001 - any failure is reported as invalid
                    errors.append(f"certificate {name!r} signature does not verify against its issuer")

        # Path-length constraints (RFC 5280 4.2.1.9): every CA must permit
        # at least as many subordinate intermediate CAs as sit below it.
        for index in range(1, len(chain)):
            cert = chain[index]
            basic = _basic_constraints(cert)
            if basic is not None and basic.ca and basic.path_length is not None:
                intermediates_below = index - 1
                if basic.path_length < intermediates_below:
                    errors.append(
                        f"certificate {_cert_common_name(cert)!r} path length {basic.path_length} "
                        f"is too short for {intermediates_below} intermediate CA(s)"
                    )
        return errors

    def verify_certificate_chain(
        self,
        leaf: x509.Certificate,
        intermediates: list[x509.Certificate] | None = None,
        root: x509.Certificate | None = None,
        at_time: dt.datetime | None = None,
    ) -> bool:
        """True if ``leaf`` chains to the root CA and is valid at ``at_time``."""
        return not self.verify_chain(leaf, intermediates=intermediates, root=root, at_time=at_time)
