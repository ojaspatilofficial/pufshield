"""Tests for the PKI manager: creation, validation, expiry, and chain verification."""

import datetime as dt
import os
import stat
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.pki import KeyStore, PKIError, PKIManager, is_ca_certificate, is_expired, is_valid_at

CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=None, decipher_only=None,
)
DEVICE_KEY_USAGE = x509.KeyUsage(
    digital_signature=True, content_commitment=False, key_encipherment=True,
    data_encipherment=False, key_agreement=False, key_cert_sign=False,
    crl_sign=False, encipher_only=None, decipher_only=None,
)


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _build_cert(
    signer_cert: x509.Certificate,
    signer_key,
    *,
    common_name: str,
    key,
    ca: bool,
    key_usage: x509.KeyUsage,
    path_length: int | None = None,
    not_valid_before: dt.datetime | None = None,
    not_valid_after: dt.datetime | None = None,
) -> x509.Certificate:
    now = _utcnow()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(signer_cert.subject)
        .public_key(key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before if not_valid_before is not None else now - dt.timedelta(minutes=1))
        .not_valid_after(not_valid_after if not_valid_after is not None else now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(key_usage, critical=True)
    )
    return builder.sign(signer_key, hashes.SHA256())


@pytest.fixture
def pki() -> PKIManager:
    return PKIManager()


# -- creation -------------------------------------------------------------

def test_root_ca_created_once(pki: PKIManager):
    ca1 = pki.ensure_root_ca("Test CA")
    ca2 = pki.ensure_root_ca("Test CA")
    assert ca1 == ca2


def test_root_ca_is_self_signed(pki: PKIManager):
    ca = pki.ensure_root_ca("Test CA")
    assert ca.subject == ca.issuer
    assert is_ca_certificate(ca)
    assert pki.validate_ca_certificate(ca) == []


def test_get_root_ca_before_provisioning_raises():
    fresh = PKIManager(KeyStore(root=tempfile.mkdtemp()))
    with pytest.raises(PKIError):
        fresh.get_root_ca()


def test_issue_device_certificate(pki: PKIManager):
    cert = pki.issue_device_certificate("dev-cert-1")
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "device:dev-cert-1"
    assert not is_ca_certificate(cert)


def test_issue_device_certificate_generates_key_pair(pki: PKIManager):
    cert = pki.issue_device_certificate("dev-keys")
    private = pki.key_store.load_private_key("device", "dev-keys")
    assert private is not None
    assert private.public_key().public_numbers() == cert.public_key().public_numbers()


def test_get_device_certificate_missing_raises(pki: PKIManager):
    with pytest.raises(PKIError):
        pki.get_device_certificate("does-not-exist")


def test_intermediate_ca_issued_and_persisted(pki: PKIManager):
    mid = pki.issue_intermediate_ca("PUFShield Intermediate CA")
    assert is_ca_certificate(mid)
    assert mid.issuer == pki.get_root_ca().subject
    assert pki.get_intermediate_ca("PUFShield Intermediate CA") == mid
    assert pki.key_store.load_private_key("intermediate", "PUFShield Intermediate CA") is not None


# -- validation -----------------------------------------------------------

def test_verify_device_certificate(pki: PKIManager):
    pki.issue_device_certificate("dev-verify-1")
    cert = pki.get_device_certificate("dev-verify-1")
    assert pki.verify_device_certificate(cert)
    assert pki.verify_certificate_chain(cert) is True
    assert pki.validate_certificate(cert) == []


def test_verify_rejects_unrelated_certificate(pki: PKIManager):
    other = PKIManager(KeyStore(root=tempfile.mkdtemp()))
    other.issue_device_certificate("dev-other")
    foreign = other.get_device_certificate("dev-other")
    assert not pki.verify_device_certificate(foreign)


def test_verify_rejects_ca_certificate_as_device(pki: PKIManager):
    ca = pki.ensure_root_ca("Test CA")
    errors = pki.validate_certificate(ca)
    assert any("CA basic constraint" in e for e in errors)
    assert not pki.verify_device_certificate(ca)


def test_expired_certificate_rejected(pki: PKIManager):
    past = _utcnow() - dt.timedelta(days=10)
    cert = pki.issue_device_certificate(
        "dev-expired",
        not_valid_before=past - dt.timedelta(days=30),
        not_valid_after=past,
    )
    assert is_expired(cert)
    assert is_valid_at(cert, at_time=past) is False
    errors = pki.validate_certificate(cert)
    assert any("expired" in e for e in errors)
    assert not pki.verify_device_certificate(cert)


def test_not_yet_valid_certificate_rejected(pki: PKIManager):
    future = _utcnow() + dt.timedelta(days=10)
    cert = pki.issue_device_certificate(
        "dev-future",
        not_valid_before=future,
        not_valid_after=future + dt.timedelta(days=30),
    )
    assert is_valid_at(cert, at_time=future) is True
    errors = pki.validate_certificate(cert)
    assert any("not yet valid" in e for e in errors)
    assert not pki.verify_device_certificate(cert)


def test_validation_at_specific_time(pki: PKIManager):
    now = _utcnow()
    cert = pki.issue_device_certificate("dev-at-time")
    assert pki.verify_device_certificate(cert, at_time=now)
    assert not pki.verify_device_certificate(cert, at_time=cert.not_valid_before_utc - dt.timedelta(seconds=1))


def test_tampered_signature_rejected(pki: PKIManager):
    pki.issue_device_certificate("dev-tamper")
    cert = pki.get_device_certificate("dev-tamper")
    der = bytearray(cert.public_bytes(serialization.Encoding.DER))
    der[-2] ^= 0xFF  # flip a bit inside the signature value
    tampered = x509.load_der_x509_certificate(bytes(der))
    assert not pki.verify_device_certificate(tampered)
    errors = pki.validate_certificate(tampered)
    assert any("signature" in e for e in errors)


def test_certificate_signed_by_plain_key_rejected(pki: PKIManager):
    """A leaf signed by a non-CA device key must not validate."""
    pki.issue_device_certificate("dev-rogue-signer")
    signer_key = pki.key_store.load_private_key("device", "dev-rogue-signer")
    signer_cert = pki.get_device_certificate("dev-rogue-signer")
    leaf = _build_cert(
        signer_cert, signer_key,
        common_name="device:dev-under-rogue",
        key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        ca=False,
        key_usage=DEVICE_KEY_USAGE,
    )
    assert not pki.verify_certificate_chain(leaf, root=pki.get_root_ca())


def test_ca_without_cert_sign_key_usage_rejected(pki: PKIManager):
    root = pki.ensure_root_ca("Test CA")
    root_key = pki.key_store.load_private_key("ca", "ca_key")
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_ca = _build_cert(
        root, root_key,
        common_name="Rogue CA",
        key=rogue_key.public_key(),
        ca=True,
        key_usage=x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=None, decipher_only=None,
        ),
    )
    errors = pki.validate_ca_certificate(rogue_ca)
    assert any("key_cert_sign" in e for e in errors)

    leaf = _build_cert(
        rogue_ca, rogue_key,
        common_name="device:rogue-leaf",
        key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        ca=False,
        key_usage=DEVICE_KEY_USAGE,
    )
    assert not pki.verify_certificate_chain(leaf, intermediates=[rogue_ca], root=root)


# -- chain verification ---------------------------------------------------

def test_chain_with_intermediate_ca(pki: PKIManager):
    root = pki.ensure_root_ca("Test CA")
    mid = pki.issue_intermediate_ca("PUFShield Intermediate CA")
    cert = pki.issue_device_certificate("dev-under-mid", issuer_name="PUFShield Intermediate CA")
    assert pki.verify_certificate_chain(cert, intermediates=[mid], root=root)
    # Without the intermediate, the chain cannot be built.
    assert not pki.verify_certificate_chain(cert, root=root)


def test_chain_rejects_path_length_violation(pki: PKIManager):
    root = pki.ensure_root_ca("Test CA")
    root_key = pki.key_store.load_private_key("ca", "ca_key")

    ca1_key = ec.generate_private_key(ec.SECP256R1())
    ca1 = _build_cert(
        root, root_key, common_name="CA level 1",
        key=ca1_key.public_key(), ca=True, key_usage=CA_KEY_USAGE, path_length=0,
    )
    ca2_key = ec.generate_private_key(ec.SECP256R1())
    ca2 = _build_cert(
        ca1, ca1_key, common_name="CA level 2",
        key=ca2_key.public_key(), ca=True, key_usage=CA_KEY_USAGE, path_length=None,
    )
    leaf = _build_cert(
        ca2, ca2_key, common_name="device:too-deep",
        key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        ca=False, key_usage=DEVICE_KEY_USAGE,
    )
    errors = pki.verify_chain(leaf, intermediates=[ca1, ca2], root=root)
    assert any("path length" in e for e in errors)
    assert not pki.verify_certificate_chain(leaf, intermediates=[ca1, ca2], root=root)


def test_chain_with_two_intermediates_is_valid(pki: PKIManager):
    root = pki.ensure_root_ca("Test CA")
    root_key = pki.key_store.load_private_key("ca", "ca_key")
    ca1_key = ec.generate_private_key(ec.SECP256R1())
    ca1 = _build_cert(
        root, root_key, common_name="CA level 1",
        key=ca1_key.public_key(), ca=True, key_usage=CA_KEY_USAGE, path_length=1,
    )
    ca2_key = ec.generate_private_key(ec.SECP256R1())
    ca2 = _build_cert(
        ca1, ca1_key, common_name="CA level 2",
        key=ca2_key.public_key(), ca=True, key_usage=CA_KEY_USAGE, path_length=0,
    )
    leaf = _build_cert(
        ca2, ca2_key, common_name="device:deep-ok",
        key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        ca=False, key_usage=DEVICE_KEY_USAGE,
    )
    assert pki.verify_certificate_chain(leaf, intermediates=[ca1, ca2], root=root)


# -- key security ---------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions are not meaningful on Windows")
def test_private_key_files_are_restricted(pki: PKIManager):
    pki.ensure_root_ca("Test CA")
    path = pki.key_store._key_path("ca", "ca_key")
    assert path.exists()
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & 0o077 == 0


def test_api_never_exposes_private_keys(client, provisioned_device):
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-0001"})
    endpoints = [
        ("GET", "/api/devices"),
        ("GET", "/api/devices/dev-0001"),
        ("GET", "/api/puf/analysis"),
        ("POST", "/api/firmware"),
        ("POST", "/api/boot"),
        ("GET", "/api/manufacturer/key"),
        ("POST", "/api/firmware/verify"),
        ("GET", "/api/devices/dev-0001/minimum-version"),
    ]
    for method, path in endpoints:
        body = {}
        if method == "POST" and path == "/api/firmware":
            body = {"version": "2.0.0", "device_id": "dev-0001"}
        elif method == "POST" and path == "/api/firmware/verify":
            body = {"device_id": "dev-0001", "firmware_version": "1.0.0"}
        elif method == "GET" and path == "/api/devices/dev-0001/minimum-version":
            pass
        res = client.request(method, path, json=body)
        assert "PRIVATE KEY" not in res.text, f"private key leaked via {path}"
