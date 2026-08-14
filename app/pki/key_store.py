"""Filesystem-backed storage for keys and certificates (PEM format)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509

from ..config import get_settings

_PRIVATE_KEY_MODE = 0o600


def _restrict_private_key(path: Path) -> None:
    """Best-effort restriction of private-key file permissions.

    On POSIX the file is made owner-readable/writable only. Windows does
    not honour POSIX modes; access control there is out of scope for this
    development store.
    """
    try:
        os.chmod(path, _PRIVATE_KEY_MODE)
    except OSError:
        pass


class KeyStore:
    """Persists private keys and certificates as PEM files.

    Layout::

        <root>/ca/ca_key.pem
        <root>/ca/ca_cert.pem
        <root>/intermediate/<name>/key.pem
        <root>/intermediate/<name>/cert.pem
        <root>/device/<device_id>/key.pem
        <root>/device/<device_id>/cert.pem

    CA private keys are written with restrictive file permissions and are
    never exposed through the REST API; only the service layer reads them
    internally. NOTE: this is a development-grade store. Production
    deployments should place private keys in hardware-backed secure
    storage.
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root else get_settings().database_file.parent / "keys"
        self.root.mkdir(parents=True, exist_ok=True)

    # -- paths ---------------------------------------------------------

    def _key_path(self, scope: str, name: str) -> Path:
        path = self.root / scope
        if scope in ("device", "intermediate"):
            path = path / name
        path.mkdir(parents=True, exist_ok=True)
        return path / "key.pem"

    def _cert_path(self, scope: str, name: str) -> Path:
        path = self.root / scope
        if scope in ("device", "intermediate"):
            path = path / name
        path.mkdir(parents=True, exist_ok=True)
        return path / "cert.pem"

    # -- keys ----------------------------------------------------------

    def save_private_key(self, key: ec.EllipticCurvePrivateKey, scope: str, name: str) -> None:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path = self._key_path(scope, name)
        path.write_bytes(pem)
        _restrict_private_key(path)

    def load_private_key(self, scope: str, name: str) -> ec.EllipticCurvePrivateKey | None:
        path = self._key_path(scope, name)
        if not path.exists():
            return None
        return serialization.load_pem_private_key(path.read_bytes(), password=None)

    # -- certificates --------------------------------------------------

    def save_certificate(self, cert: x509.Certificate, scope: str, name: str) -> None:
        self._cert_path(scope, name).write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def load_certificate(self, scope: str, name: str) -> x509.Certificate | None:
        path = self._cert_path(scope, name)
        if not path.exists():
            return None
        return x509.load_pem_x509_certificate(path.read_bytes())

    def delete_scope(self, scope: str, name: str) -> bool:
        """Remove every persisted key/certificate under ``scope``/``name``.

        Used when a device is removed so it can be re-provisioned with a
        fresh identity. Returns ``True`` if anything was removed.
        """
        target = self.root / scope
        if scope in ("device", "intermediate"):
            target = target / name
        if not target.exists():
            return False
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        return True
