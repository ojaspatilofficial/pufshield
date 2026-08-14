"""SQLite persistence layer.

Tables
------
devices
    provisioned devices (identity, simulated SRAM seed).
puf_enrollments
    PUF enrollment metadata: stability mask + metrics + a derived
    credential tag. Raw startup responses are never stored here; the
    credential is an HMAC tag over the stable-only reference.
certificates
    device X.509 certificates (subject, issuer, serial, PEM) persisted
    at provisioning time and kept fresh on reads.
firmware_images
    signed firmware bundles available for boot.
boot_logs
    audit trail of every secure boot attempt (success or failure).
authentication_events
    audit trail of every challenge-response authentication attempt.
security_events
    unified, timestamped security event feed: every authentication,
    secure boot, and attack attempt writes exactly one row here.
auth_challenges
    one-time challenge-response nonces (issued, consumed, expired).
attack_logs
    audit trail of every simulated attack run through the boot pipeline
    (attack type, target, detection point, result, reason, timestamp).
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..config import get_settings
from ..fuzzy import FuzzyHelper
from ..puf import PUFEnrollment

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id           TEXT NOT NULL UNIQUE,
    bit_size            INTEGER NOT NULL,
    puf_seed            TEXT NOT NULL,
    min_firmware_version TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS puf_enrollments (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id           TEXT NOT NULL UNIQUE,
    bit_size            INTEGER NOT NULL,
    num_captures        INTEGER NOT NULL,
    stable_bit_count    INTEGER NOT NULL,
    unstable_bit_count  INTEGER NOT NULL,
    stability_mask      TEXT NOT NULL,
    reference           TEXT NOT NULL,
    credential_tag      TEXT NOT NULL,
    intra_device_hd     REAL NOT NULL,
    bit_error_rate      REAL NOT NULL,
    reliability         REAL NOT NULL,
    uniqueness          REAL,
    fuzzy_helper        TEXT,
    puf_binding         TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS certificates (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id              TEXT NOT NULL UNIQUE,
    subject                TEXT NOT NULL,
    issuer                 TEXT NOT NULL,
    serial_number          TEXT NOT NULL,
    not_valid_before       TEXT NOT NULL,
    not_valid_after        TEXT NOT NULL,
    public_key_algorithm   TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    pem                    TEXT NOT NULL,
    created_at             TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS firmware_images (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    version       TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    bundle        TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS boot_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     TEXT NOT NULL,
    image_version TEXT,
    status        TEXT NOT NULL,
    message       TEXT NOT NULL,
    checks        TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS authentication_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  TEXT NOT NULL,
    success    INTEGER NOT NULL,
    reason     TEXT NOT NULL,
    checks     TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS security_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    severity   TEXT NOT NULL,
    result     TEXT NOT NULL,
    summary    TEXT NOT NULL,
    details    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge  TEXT NOT NULL UNIQUE,
    device_id  TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attack_logs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    attack           TEXT NOT NULL,
    target           TEXT NOT NULL,
    firmware_version TEXT,
    detection_point  TEXT,
    result           TEXT NOT NULL,
    reason           TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def _utc_iso() -> str:
    """ISO-8601 UTC timestamp used for the security audit tables."""
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _public_key_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 fingerprint of a certificate's public key (SPKI bytes)."""
    import hashlib

    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


class _ThreadSafeConnection(sqlite3.Connection):
    """SQLite connection usable from any thread.

    ``check_same_thread=False`` permits cross-thread use; every statement
    and commit is serialised by a re-entrant lock so concurrent access to
    the shared connection never interleaves statements.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._lock = threading.RLock()

    def execute(self, sql: str, parameters=()):
        with self._lock:
            return super().execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters=()):
        with self._lock:
            return super().executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str):
        with self._lock:
            return super().executescript(sql_script)

    def commit(self):
        with self._lock:
            return super().commit()


class Database:
    """Thin SQLite wrapper with automatic schema initialisation."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else get_settings().database_file
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self.connect()

    def connect(self) -> None:
        self._conn = sqlite3.connect(
            str(self.path),
            check_same_thread=False,
            factory=_ThreadSafeConnection,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _migrate(self) -> None:
        """Apply lightweight schema migrations for pre-existing databases."""
        device_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(devices)").fetchall()}
        if "puf_seed" not in device_columns:
            self.conn.execute("ALTER TABLE devices ADD COLUMN puf_seed TEXT NOT NULL DEFAULT ''")
        if "min_firmware_version" not in device_columns:
            self.conn.execute("ALTER TABLE devices ADD COLUMN min_firmware_version TEXT NOT NULL DEFAULT ''")
        enrollment_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(puf_enrollments)").fetchall()}
        if "fuzzy_helper" not in enrollment_columns:
            self.conn.execute("ALTER TABLE puf_enrollments ADD COLUMN fuzzy_helper TEXT")
        if "puf_binding" not in enrollment_columns:
            self.conn.execute("ALTER TABLE puf_enrollments ADD COLUMN puf_binding TEXT")

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        return self._conn

    # -- devices -------------------------------------------------------

    def upsert_device(self, device_id: str, bit_size: int, puf_seed: bytes) -> None:
        self.conn.execute(
            """
            INSERT INTO devices (device_id, bit_size, puf_seed)
            VALUES (?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                bit_size = excluded.bit_size,
                puf_seed = excluded.puf_seed
            """,
            (device_id, bit_size, puf_seed.hex()),
        )
        self.conn.commit()

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        return dict(row) if row else None

    def list_devices(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
        return [dict(r) for r in rows]

    def delete_device(self, device_id: str) -> bool:
        """Remove a device and its operational state.

        Deletes the device row together with its PUF enrollment,
        certificate, firmware images, and one-time challenges so the same
        device id can be re-provisioned. Audit history (boot logs,
        authentication events, attack logs, security events) is preserved
        for forensics.
        """
        cursor = self.conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        self.conn.execute("DELETE FROM puf_enrollments WHERE device_id = ?", (device_id,))
        self.conn.execute("DELETE FROM certificates WHERE device_id = ?", (device_id,))
        self.conn.execute("DELETE FROM firmware_images WHERE device_id = ?", (device_id,))
        self.conn.execute("DELETE FROM auth_challenges WHERE device_id = ?", (device_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def set_min_firmware_version(self, device_id: str, version: str) -> None:
        """Set the anti-rollback floor for a device ('' = unrestricted).

        The service layer validates ``version`` before calling this; the
        database stores the raw string.
        """
        self.conn.execute(
            "UPDATE devices SET min_firmware_version = ? WHERE device_id = ?",
            (version, device_id),
        )
        self.conn.commit()

    def get_min_firmware_version(self, device_id: str) -> str:
        row = self.conn.execute(
            "SELECT min_firmware_version FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        return row["min_firmware_version"] if row else ""

    # -- PUF enrollments ------------------------------------------------

    def upsert_enrollment(self, enrollment: PUFEnrollment) -> None:
        self.conn.execute(
            """
            INSERT INTO puf_enrollments (
                device_id, bit_size, num_captures, stable_bit_count, unstable_bit_count,
                stability_mask, reference, credential_tag, intra_device_hd,
                bit_error_rate, reliability, uniqueness, fuzzy_helper, puf_binding
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                bit_size = excluded.bit_size,
                num_captures = excluded.num_captures,
                stable_bit_count = excluded.stable_bit_count,
                unstable_bit_count = excluded.unstable_bit_count,
                stability_mask = excluded.stability_mask,
                reference = excluded.reference,
                credential_tag = excluded.credential_tag,
                intra_device_hd = excluded.intra_device_hd,
                bit_error_rate = excluded.bit_error_rate,
                reliability = excluded.reliability,
                uniqueness = excluded.uniqueness,
                fuzzy_helper = excluded.fuzzy_helper,
                puf_binding = excluded.puf_binding
            """,
            (
                enrollment.device_id,
                enrollment.bit_size,
                enrollment.num_captures,
                enrollment.stable_bit_count,
                enrollment.unstable_bit_count,
                enrollment.stability_mask.hex(),
                enrollment.reference.hex(),
                enrollment.credential_tag.hex(),
                enrollment.intra_device_hd,
                enrollment.bit_error_rate,
                enrollment.reliability,
                enrollment.uniqueness,
                json.dumps(enrollment.fuzzy_helper.to_dict()) if enrollment.fuzzy_helper else None,
                enrollment.puf_binding.hex() if enrollment.puf_binding else None,
            ),
        )
        self.conn.commit()

    def get_enrollment(self, device_id: str) -> PUFEnrollment | None:
        row = self.conn.execute(
            "SELECT * FROM puf_enrollments WHERE device_id = ?", (device_id,)
        ).fetchone()
        if row is None:
            return None
        return self._enrollment_from_row(row)

    def list_enrollments(self) -> list[PUFEnrollment]:
        rows = self.conn.execute("SELECT * FROM puf_enrollments ORDER BY device_id").fetchall()
        return [self._enrollment_from_row(r) for r in rows]

    def recompute_uniqueness(self) -> None:
        """Recompute each device's uniqueness (mean HD to every other device).

        Devices with a different ``bit_size`` than the fleet are excluded
        from the comparison so a mixed-size fleet never crashes the metric.
        """
        enrollments = self.list_enrollments()
        references = [e.reference for e in enrollments]
        for enrollment in enrollments:
            others = [
                reference for other, reference in zip(enrollments, references)
                if other.device_id != enrollment.device_id
            ]
            uniqueness = PUFEnrollment.mean_device_vs_fleet(enrollment.reference, others) or 0.0
            self.conn.execute(
                "UPDATE puf_enrollments SET uniqueness = ? WHERE device_id = ?",
                (uniqueness, enrollment.device_id),
            )
        self.conn.commit()

    @staticmethod
    def _enrollment_from_row(row: sqlite3.Row) -> PUFEnrollment:
        return PUFEnrollment(
            device_id=row["device_id"],
            bit_size=row["bit_size"],
            num_captures=row["num_captures"],
            stable_bit_count=row["stable_bit_count"],
            unstable_bit_count=row["unstable_bit_count"],
            stability_mask=bytes.fromhex(row["stability_mask"]),
            reference=bytes.fromhex(row["reference"]),
            credential_tag=bytes.fromhex(row["credential_tag"]),
            intra_device_hd=row["intra_device_hd"],
            bit_error_rate=row["bit_error_rate"],
            reliability=row["reliability"],
            uniqueness=row["uniqueness"],
            fuzzy_helper=Database._fuzzy_helper_from_row(row["fuzzy_helper"]),
            puf_binding=bytes.fromhex(row["puf_binding"]) if row["puf_binding"] else None,
        )

    @staticmethod
    def _fuzzy_helper_from_row(raw: str | None) -> FuzzyHelper | None:
        if not raw:
            return None
        return FuzzyHelper.from_dict(json.loads(raw))

    # -- certificates --------------------------------------------------

    def save_certificate(self, device_id: str, cert: x509.Certificate) -> None:
        """Persist (or refresh) a device's X.509 certificate."""
        self.conn.execute(
            """
            INSERT INTO certificates (
                device_id, subject, issuer, serial_number, not_valid_before,
                not_valid_after, public_key_algorithm, public_key_fingerprint, pem
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                subject = excluded.subject,
                issuer = excluded.issuer,
                serial_number = excluded.serial_number,
                not_valid_before = excluded.not_valid_before,
                not_valid_after = excluded.not_valid_after,
                public_key_algorithm = excluded.public_key_algorithm,
                public_key_fingerprint = excluded.public_key_fingerprint,
                pem = excluded.pem
            """,
            (
                device_id,
                cert.subject.rfc4514_string(),
                cert.issuer.rfc4514_string(),
                str(cert.serial_number),
                cert.not_valid_before_utc.isoformat(),
                cert.not_valid_after_utc.isoformat(),
                cert.public_key().curve.name,
                _public_key_fingerprint(cert),
                cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            ),
        )
        self.conn.commit()

    def get_certificate(self, device_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM certificates WHERE device_id = ?", (device_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_certificates(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM certificates ORDER BY device_id").fetchall()
        return [dict(r) for r in rows]

    # -- firmware ------------------------------------------------------

    def save_firmware(self, version: str, device_id: str, bundle: dict) -> None:
        self.conn.execute(
            "INSERT INTO firmware_images (version, device_id, bundle) VALUES (?, ?, ?)",
            (version, device_id, json.dumps(bundle)),
        )
        self.conn.commit()

    def list_firmware(self, device_id: str | None = None) -> list[dict[str, Any]]:
        if device_id:
            rows = self.conn.execute(
                "SELECT * FROM firmware_images WHERE device_id = ? ORDER BY id DESC", (device_id,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM firmware_images ORDER BY id DESC").fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["bundle"] = json.loads(item["bundle"])
            result.append(item)
        return result

    # -- boot logs -----------------------------------------------------

    def log_boot(self, device_id: str, image_version: str | None, status: str, message: str, checks: dict | None) -> None:
        self.conn.execute(
            "INSERT INTO boot_logs (device_id, image_version, status, message, checks) VALUES (?, ?, ?, ?, ?)",
            (device_id, image_version, status, message, json.dumps(checks) if checks else None),
        )
        self.conn.commit()

    def list_boot_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM boot_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            if item.get("checks"):
                item["checks"] = json.loads(item["checks"])
            result.append(item)
        return result

    # -- authentication events -------------------------------------------

    def log_authentication_event(
        self,
        device_id: str,
        *,
        success: bool,
        reason: str,
        checks: dict | None = None,
        timestamp: str | None = None,
    ) -> None:
        """Persist one challenge-response authentication attempt."""
        self.conn.execute(
            "INSERT INTO authentication_events (device_id, success, reason, checks, created_at) VALUES (?, ?, ?, ?, ?)",
            (device_id, int(success), reason, json.dumps(checks) if checks else None, timestamp or _utc_iso()),
        )
        self.conn.commit()

    def list_authentication_events(
        self,
        limit: int = 100,
        device_id: str | None = None,
        only_failures: bool = False,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM authentication_events"
        conditions: list[str] = []
        params: list[Any] = []
        if device_id:
            conditions.append("device_id = ?")
            params.append(device_id)
        if only_failures:
            conditions.append("success = 0")
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = self.conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["success"] = bool(item["success"])
            if item.get("checks"):
                item["checks"] = json.loads(item["checks"])
            item["timestamp"] = item.pop("created_at")
            result.append(item)
        return result

    def count_authentication_events_by_result(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT success, COUNT(*) AS n FROM authentication_events GROUP BY success"
        ).fetchall()
        return {"successes": 0, "failures": 0, **{("successes" if row["success"] else "failures"): int(row["n"]) for row in rows}}

    # -- security events --------------------------------------------------

    def log_security_event(
        self,
        *,
        event_type: str,
        device_id: str,
        severity: str,
        result: str,
        summary: str,
        details: dict | None = None,
        timestamp: str | None = None,
    ) -> None:
        """Persist one timestamped security event.

        Called for every authentication, secure boot, and attack attempt,
        so the feed is an append-only audit trail of what the system saw.
        """
        self.conn.execute(
            """
            INSERT INTO security_events (event_type, device_id, severity, result, summary, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                device_id,
                severity,
                result,
                summary,
                json.dumps(details) if details else None,
                timestamp or _utc_iso(),
            ),
        )
        self.conn.commit()

    def list_security_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        device_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM security_events"
        conditions: list[str] = []
        params: list[Any] = []
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if device_id:
            conditions.append("device_id = ?")
            params.append(device_id)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = self.conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["timestamp"] = item.pop("created_at")
            if item.get("details"):
                for key, value in json.loads(item["details"]).items():
                    if key not in item:
                        item[key] = value
            item.pop("details", None)
            result.append(item)
        return result

    def count_security_events_by_severity(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT severity, COUNT(*) AS n FROM security_events GROUP BY severity").fetchall()
        return {row["severity"]: int(row["n"]) for row in rows}

    # -- authentication challenges ---------------------------------------

    def save_challenge(self, challenge_b64: str, device_id: str, expires_at: float) -> None:
        """Persist a fresh one-time challenge (base64 nonce)."""
        self.conn.execute(
            "INSERT INTO auth_challenges (challenge, device_id, expires_at) VALUES (?, ?, ?)",
            (challenge_b64, device_id, expires_at),
        )
        self.conn.commit()

    def consume_challenge(self, challenge_b64: str, device_id: str) -> dict[str, Any] | None:
        """Atomically consume a one-time challenge.

        Returns the challenge row only if it exists for ``device_id``,
        has not expired, and has not already been used; otherwise returns
        ``None``. Consuming is atomic, so a challenge can never be used
        twice even under concurrent requests (replay protection).
        """
        row = self.conn.execute(
            "SELECT * FROM auth_challenges WHERE challenge = ? AND device_id = ?",
            (challenge_b64, device_id),
        ).fetchone()
        if row is None or row["used"] or row["expires_at"] < time.time():
            return None
        cursor = self.conn.execute(
            "UPDATE auth_challenges SET used = 1 WHERE challenge = ? AND used = 0",
            (challenge_b64,),
        )
        self.conn.commit()
        return dict(row) if cursor.rowcount else None

    def purge_expired_challenges(self) -> None:
        """Remove expired challenges (housekeeping on new issuance)."""
        self.conn.execute("DELETE FROM auth_challenges WHERE expires_at < ?", (time.time(),))
        self.conn.commit()

    # -- attack logs ---------------------------------------------------

    def log_attack(
        self,
        *,
        attack: str,
        target: str,
        firmware_version: str | None,
        detection_point: str | None,
        result: str,
        reason: str,
        timestamp: str,
    ) -> None:
        """Persist one simulated attack record."""
        self.conn.execute(
            """
            INSERT INTO attack_logs (attack, target, firmware_version, detection_point, result, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (attack, target, firmware_version, detection_point, result, reason, timestamp),
        )
        self.conn.commit()

    def list_attack_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM attack_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["timestamp"] = item.pop("created_at")
            result.append(item)
        return result

    def count_boot_logs_by_status(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT status, COUNT(*) AS n FROM boot_logs GROUP BY status").fetchall()
        return {row["status"]: int(row["n"]) for row in rows}

    def count_attack_logs_by_result(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT result, COUNT(*) AS n FROM attack_logs GROUP BY result").fetchall()
        return {row["result"]: int(row["n"]) for row in rows}
