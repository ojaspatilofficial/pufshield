from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class DeviceHardware(ABC):
    """Abstract interface representing the physical device hardware capabilities.
    
    This separates the backend simulation from the on-device secure boot flow.
    """
    
    @property
    @abstractmethod
    def mode(self) -> str:
        """Returns 'REAL_HARDWARE' or 'SIMULATION'."""
        pass

    @abstractmethod
    def read_startup_sram(self) -> bytes:
        """Read the uninitialized SRAM state at power-up."""
        pass

    @abstractmethod
    def reconstruct_puf_secret(self, helper_data: dict) -> bytes:
        """Reconstruct the PUF root secret using SRAM and helper data."""
        pass

    @abstractmethod
    def derive_device_secret(self, puf_secret: bytes, label: str) -> bytes:
        """Derive a specific key from the PUF root secret."""
        pass

    @abstractmethod
    def sign_attestation(self, private_key: bytes, message: bytes) -> bytes:
        """Sign a message using the derived private key."""
        pass

    @abstractmethod
    def get_device_measurement(self) -> bytes:
        """Get the current measurement of the boot state."""
        pass

    @abstractmethod
    def read_monotonic_counter(self) -> int:
        """Read the hardware-backed monotonic counter for anti-rollback."""
        pass

    @abstractmethod
    def update_monotonic_counter(self, new_version: int) -> None:
        """Update the hardware-backed monotonic counter."""
        pass

    @abstractmethod
    def verify_firmware(self, manifest: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify the firmware manifest against the manufacturer public key."""
        pass

    @abstractmethod
    def verify_kernel(self, kernel_image: bytes, expected_hash: bytes) -> bool:
        """Verify the kernel image against the expected hash in the manifest."""
        pass

    @abstractmethod
    def verify_rootfs(self, rootfs_image: bytes, expected_hash: bytes) -> bool:
        """Verify the rootfs image against the expected hash in the manifest."""
        pass

class BootloaderInterface(ABC):
    """Interface for the first-stage bootloader."""
    
    @abstractmethod
    def boot(self) -> Dict[str, Any]:
        """Execute the secure boot sequence and return the result."""
        pass
