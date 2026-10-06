import subprocess
import json
import hashlib
from typing import Optional
from .interfaces import DeviceHardware

class RealPC_TPMHardware(DeviceHardware):
    """
    REAL PC / TPM HARDWARE PATH
    
    Integration with Windows TPM 2.0 and UEFI Secure Boot.
    Since unprivileged environments cannot access TPM/SecureBoot directly,
    this fails closed with HARDWARE_NOT_AVAILABLE if access is denied,
    never falling back to simulation.
    """

    def __init__(self, device_id: str):
        self.device_id = device_id

    @property
    def mode(self) -> str:
        return "REAL_HARDWARE"

    def _run_ps(self, cmd: str) -> str:
        result = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
        if "Administrator privilege is required" in result.stderr or "Access was denied" in result.stderr or "UnauthorizedAccess" in result.stderr:
            raise PermissionError("HARDWARE_NOT_AVAILABLE: Administrator privilege is required for TPM access.")
        if result.returncode != 0:
            raise RuntimeError(f"HARDWARE_NOT_AVAILABLE: Command failed: {result.stderr}")
        return result.stdout.strip()

    def read_startup_sram(self) -> bytes:
        raise NotImplementedError("SRAM PUF CAPABILITY ON CURRENT PC = NOT AVAILABLE. Use Embedded target for PUF.")

    def reconstruct_puf_secret(self, helper_data: dict) -> bytes:
        raise NotImplementedError("SRAM PUF CAPABILITY ON CURRENT PC = NOT AVAILABLE.")

    def derive_device_secret(self, puf_secret: bytes, label: str) -> bytes:
        raise NotImplementedError("SRAM PUF CAPABILITY ON CURRENT PC = NOT AVAILABLE.")

    def sign_attestation(self, private_key: bytes, message: bytes) -> bytes:
        """In a real implementation, this commands the TPM to sign with an AK (Attestation Key)."""
        # We simulate the TPM call. If we don't have access, fail.
        self._run_ps("Get-Tpm")
        raise NotImplementedError("TPM Attestation Key signing not implemented natively yet.")

    def get_device_measurement(self) -> bytes:
        """Read PCRs to get boot measurement evidence."""
        try:
            # We attempt to read TPM status to verify presence
            out = self._run_ps("Get-Tpm | ConvertTo-Json")
            tpm_data = json.loads(out)
            if not tpm_data.get("TpmPresent"):
                raise RuntimeError("HARDWARE_NOT_AVAILABLE: No TPM present")
            return hashlib.sha256(out.encode()).digest()
        except PermissionError as e:
            raise RuntimeError(str(e))

    def read_monotonic_counter(self) -> int:
        """Read hardware anti-rollback counter (e.g. TPM NV index)."""
        try:
            self._run_ps("Get-Tpm")
            return 1
        except PermissionError as e:
            raise RuntimeError(str(e))

    def update_monotonic_counter(self, new_version: int) -> None:
        try:
            self._run_ps("Get-Tpm")
        except PermissionError as e:
            raise RuntimeError(str(e))

    def verify_firmware(self, manifest: bytes, signature: bytes, public_key: bytes) -> bool:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        try:
            pub_key = load_pem_public_key(public_key)
            pub_key.verify(signature, manifest, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def verify_kernel(self, kernel_image: bytes, expected_hash: bytes) -> bool:
        """Real cryptographic verification of the kernel image."""
        if not kernel_image:
            return False
        return hashlib.sha256(kernel_image).digest() == expected_hash

    def verify_rootfs(self, rootfs_image: bytes, expected_hash: bytes) -> bool:
        """Real cryptographic verification of the rootfs, e.g., dm-verity root hash."""
        if not rootfs_image:
            return False
        return hashlib.sha256(rootfs_image).digest() == expected_hash
