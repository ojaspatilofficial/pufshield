"""REST API routes for PUFShield."""

from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from ..auth import AuthenticationError
from ..firmware import VersionError
from ..pki import PKIError
from ..puf import DEFAULT_CAPTURES
from ..services import (
    DeviceAlreadyExists,
    DeviceNotFound,
    NoEnrollmentError,
    NoFirmwareError,
    Service,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

_DEVICE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
_DEVICE_ID_FIELD = dict(min_length=1, max_length=64, pattern=_DEVICE_ID_PATTERN, examples=["dev-0001"])


def _check_payload_b64(cls, value: str | None) -> str | None:
    """Reject malformed base64 firmware payloads with a clean validation error."""
    if value is None:
        return value
    try:
        base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001 - invalid base64 is a 422, not a crash
        raise ValueError("payload_b64 must be valid base64") from exc
    return value


def get_service() -> Service:
    return Service()


class ProvisionRequest(BaseModel):
    device_id: str = Field(**_DEVICE_ID_FIELD)
    bit_size: int = Field(default=256, ge=8, le=4096, multiple_of=8)
    num_captures: int = Field(default=DEFAULT_CAPTURES, ge=1, le=200)


class PUFTestRequest(BaseModel):
    device_id: str = Field(**_DEVICE_ID_FIELD)
    num_captures: int = Field(default=DEFAULT_CAPTURES, ge=1, le=200)


class FirmwareRequest(BaseModel):
    version: str = Field(min_length=1, max_length=32, examples=["1.0.0"])
    device_id: str = Field(**_DEVICE_ID_FIELD)
    payload_b64: str | None = Field(default=None, description="Optional base64 firmware payload")

    _validate_payload = field_validator("payload_b64")(_check_payload_b64)


class FirmwareSignRequest(BaseModel):
    version: str = Field(min_length=1, max_length=32, examples=["1.0.0"])
    device_id: str = Field(**_DEVICE_ID_FIELD)
    payload_b64: str | None = Field(default=None, description="Optional base64 firmware payload")
    store: bool = Field(default=False, description="Persist the signed bundle in the firmware registry")

    _validate_payload = field_validator("payload_b64")(_check_payload_b64)


class FirmwareVerifyRequest(BaseModel):
    device_id: str = Field(**_DEVICE_ID_FIELD)
    firmware_version: str = Field(min_length=1, examples=["1.0.0"])


class MinimumVersionRequest(BaseModel):
    version: str = Field(
        min_length=0,
        max_length=32,
        examples=["2.0.0"],
        description="Minimum allowed firmware version (dotted numeric); empty string clears the policy",
    )


class BootRequest(BaseModel):
    device_id: str = Field(**_DEVICE_ID_FIELD)
    firmware_version: str | None = Field(default=None)
    challenge_b64: str | None = Field(
        default=None,
        description="Optional one-time challenge for the challenge-response stage (signed with the device key)",
    )
    signature_b64: str | None = Field(
        default=None,
        description="Optional ECDSA signature over the challenge message",
    )


class AuthChallengeRequest(BaseModel):
    device_id: str = Field(**_DEVICE_ID_FIELD)


class AuthenticateRequest(BaseModel):
    device_id: str = Field(**_DEVICE_ID_FIELD)
    challenge_b64: str = Field(min_length=1, description="Base64 one-time challenge nonce")
    signature_b64: str = Field(min_length=1, description="Base64 ECDSA signature over the challenge")


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "PUFShield"}


@router.post("/devices", status_code=201)
def provision_device(req: ProvisionRequest, service: Service = Depends(get_service)) -> dict:
    try:
        return service.provision_device(req.device_id, req.bit_size, req.num_captures)
    except DeviceAlreadyExists as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get("/devices")
def list_devices(service: Service = Depends(get_service)) -> list[dict]:
    return service.list_devices()


@router.get("/devices/{device_id}")
def get_device(device_id: str, service: Service = Depends(get_service)) -> dict:
    try:
        return service.get_device(device_id)
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.delete("/devices/{device_id}")
def delete_device(device_id: str, service: Service = Depends(get_service)) -> dict:
    """Remove a device so it can be re-provisioned (audit logs are kept)."""
    try:
        return service.delete_device(device_id)
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/devices/{device_id}/certificate")
def device_certificate(device_id: str, service: Service = Depends(get_service)) -> dict:
    """Device certificate details (PEM, subject, issuer, validity, chain status)."""
    try:
        return service.get_device_certificate_info(device_id)
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PKIError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/devices/{device_id}/minimum-version")
def get_minimum_version(device_id: str, service: Service = Depends(get_service)) -> dict:
    try:
        return {
            "device_id": device_id,
            "min_firmware_version": service.get_minimum_firmware_version(device_id),
        }
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.put("/devices/{device_id}/minimum-version")
def set_minimum_version(
    device_id: str,
    req: MinimumVersionRequest,
    service: Service = Depends(get_service),
) -> dict:
    """Set the anti-rollback floor for a device (rejects malformed versions)."""
    try:
        return service.set_minimum_firmware_version(device_id, req.version)
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except VersionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/puf/test")
def test_puf(req: PUFTestRequest, service: Service = Depends(get_service)) -> dict:
    try:
        return service.test_puf(req.device_id, req.num_captures)
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except NoEnrollmentError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (PKIError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/puf/analysis")
def puf_analysis(service: Service = Depends(get_service)) -> dict:
    return service.puf_analysis()


@router.post("/firmware", status_code=201)
def create_firmware(req: FirmwareRequest, service: Service = Depends(get_service)) -> dict:
    try:
        payload = None
        if req.payload_b64:
            payload = base64.b64decode(req.payload_b64)
        return service.create_firmware(req.version, req.device_id, payload)
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (NoFirmwareError, VersionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PKIError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/firmware/sign")
def sign_firmware(req: FirmwareSignRequest, service: Service = Depends(get_service)) -> dict:
    """Sign a client-supplied payload with the device + manufacturer keys.

    The signed bundle is returned without being stored unless ``store`` is
    true, in which case it is also registered for future boots.
    """
    try:
        payload = None
        if req.payload_b64:
            payload = base64.b64decode(req.payload_b64)
        image = service.sign_firmware(req.version, req.device_id, payload)
        if req.store:
            bundle = service.store_firmware_image(image)
            bundle["stored"] = True
            return bundle
        return image.to_bundle()
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (NoFirmwareError, VersionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PKIError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/firmware")
def list_firmware(
    device_id: str | None = Query(default=None),
    service: Service = Depends(get_service),
) -> list[dict]:
    return service.list_firmware(device_id)


@router.post("/firmware/verify")
def verify_firmware(req: FirmwareVerifyRequest, service: Service = Depends(get_service)) -> dict:
    try:
        return service.verify_firmware(req.device_id, req.firmware_version)
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except NoFirmwareError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PKIError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/manufacturer/key")
def manufacturer_public_key(service: Service = Depends(get_service)) -> dict:
    """Trusted manufacturer public key (private key is never exposed)."""
    return service.get_manufacturer_public_key()


@router.post("/boot")
def run_boot(req: BootRequest, service: Service = Depends(get_service)) -> dict:
    try:
        return service.run_boot(
            req.device_id,
            req.firmware_version,
            req.challenge_b64,
            req.signature_b64,
        )
    except (DeviceNotFound, NoEnrollmentError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except NoFirmwareError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (PKIError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/boot/logs")
def list_boot_logs(limit: int = Query(default=100, ge=1, le=1000), service: Service = Depends(get_service)) -> list[dict]:
    return service.list_boot_logs(limit)


@router.post("/auth/challenge")
def issue_auth_challenge(req: AuthChallengeRequest, service: Service = Depends(get_service)) -> dict:
    try:
        return service.issue_auth_challenge(req.device_id)
    except DeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/auth/authenticate")
def authenticate_device(req: AuthenticateRequest, service: Service = Depends(get_service)) -> dict:
    try:
        return service.authenticate_device(req.device_id, req.challenge_b64, req.signature_b64)
    except (DeviceNotFound, NoEnrollmentError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail=exc.message,
            headers={"X-Auth-Reason": exc.reason},
        )


@router.get("/auth/logs")
def list_auth_logs(
    limit: int = Query(default=100, ge=1, le=1000),
    device_id: str | None = Query(default=None, pattern=_DEVICE_ID_PATTERN),
    service: Service = Depends(get_service),
) -> list[dict]:
    return service.list_authentication_logs(limit, device_id)


@router.get("/attacks")
def list_attacks(service: Service = Depends(get_service)) -> list[dict]:
    return service.list_attack_scenarios()


@router.get("/attacks/logs")
def list_attack_logs(
    limit: int = Query(default=100, ge=1, le=1000),
    service: Service = Depends(get_service),
) -> list[dict]:
    return service.list_attack_logs(limit)


@router.post("/attacks/{attack_name}")
def run_attack(
    attack_name: str,
    req: BootRequest,
    service: Service = Depends(get_service),
) -> dict:
    try:
        return service.run_attack(
            attack_name,
            req.device_id,
            req.firmware_version,
            req.challenge_b64,
            req.signature_b64,
        )
    except (DeviceNotFound, NoEnrollmentError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except NoFirmwareError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (PKIError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/security/events")
def list_security_events(
    limit: int = Query(default=100, ge=1, le=1000),
    event_type: str | None = Query(default=None, pattern="^(boot|attack|auth)$"),
    device_id: str | None = Query(default=None, pattern=_DEVICE_ID_PATTERN),
    service: Service = Depends(get_service),
) -> list[dict]:
    return service.list_security_events(limit, event_type, device_id)


@router.get("/dashboard/stats")
def dashboard_stats(service: Service = Depends(get_service)) -> dict:
    return service.dashboard_stats()
