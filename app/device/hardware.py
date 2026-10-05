from .interfaces import DeviceHardware

class RealHardware(DeviceHardware):
    """Reference implementation for physical hardware.
    
    This class documents the exact integration boundary for the physical device.
    In the hackathon demonstration, this environment does not have access to
    physical SRAM, so calling these methods will raise NotImplementedError.
    
    CRITICAL: This implementation NEVER accesses the backend database to retrieve
    a puf_seed. It strictly reads the physical SRAM via a hardware driver.
    """

    def __init__(self, device_id: str):
        self.device_id = device_id

    @property
    def mode(self) -> str:
        return "REAL_HARDWARE"

    def read_startup_sram(self) -> bytes:
        # Expected C-FFI or hardware interface call here
        raise NotImplementedError("Physical hardware integration required: Cannot read SRAM in this environment.")

    def reconstruct_puf_secret(self, helper_data: dict) -> bytes:
        raise NotImplementedError("Physical hardware integration required.")

    def derive_device_secret(self, puf_secret: bytes, label: str) -> bytes:
        raise NotImplementedError("Physical hardware integration required.")

    def sign_attestation(self, private_key: bytes, message: bytes) -> bytes:
        raise NotImplementedError("Physical hardware integration required.")

    def get_device_measurement(self) -> bytes:
        raise NotImplementedError("Physical hardware integration required.")

    def read_monotonic_counter(self) -> int:
        raise NotImplementedError("Physical hardware integration required: Cannot read hardware fuse/NVRAM.")

    def update_monotonic_counter(self, new_version: int) -> None:
        raise NotImplementedError("Physical hardware integration required.")

    def verify_firmware(self, manifest: bytes, signature: bytes, public_key: bytes) -> bool:
        raise NotImplementedError("Physical hardware integration required.")

    def verify_kernel(self, kernel_image: bytes, expected_hash: bytes) -> bool:
        raise NotImplementedError("Physical hardware integration required.")

    def verify_rootfs(self, rootfs_image: bytes, expected_hash: bytes) -> bool:
        raise NotImplementedError("Physical hardware integration required.")
