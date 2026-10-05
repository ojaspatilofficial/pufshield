import json
import logging
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .interfaces import DeviceHardware
from ..puf.sram_puf import SRAMPUF
from ..puf.enrollment import PUFEnrollment
from ..fuzzy import FuzzyExtractor, FuzzyHelper
from ..fuzzy.kdf import derive_device_keys
from ..crypto.utils import sha256
from ..firmware import FirmwareImage, parse_version

logger = logging.getLogger(__name__)

class SimulatorHardware(DeviceHardware):
    """Software-simulated hardware device for development and CI.
    
    This uses the database purely as simulated NVRAM for the PUF seed
    and monotonic counter. It explicitly labels itself as SIMULATION.
    """

    def __init__(self, device_id: str, db):
        self.device_id = device_id
        self._db = db
        
        # Load simulated NVRAM
        device_record = self._db.get_device(device_id)
        if not device_record:
            raise RuntimeError(f"Device {device_id} not found in simulated NVRAM.")
            
        self.bit_size = device_record["bit_size"]
        self.seed = bytes.fromhex(device_record["puf_seed"])
        
        self.puf = SRAMPUF(device_id, bit_size=self.bit_size, seed=self.seed)

    @property
    def mode(self) -> str:
        return "SIMULATION"

    def read_startup_sram(self) -> bytes:
        """Simulate reading the uninitialized SRAM state at power-up."""
        return self.puf.regenerate()

    def reconstruct_puf_secret(self, helper_data: dict) -> bytes:
        sram_response = self.read_startup_sram()
        
        # Reconstruct fuzzy helper object
        try:
            helper = FuzzyHelper.from_dict(helper_data["fuzzy_helper"])
        except KeyError:
            raise RuntimeError("Invalid helper data format")
            
        # The mask is part of enrollment data
        mask = bytes.fromhex(helper_data["stability_mask"])
        masked_candidate = bytes(a & b for a, b in zip(sram_response, mask))
        
        # Use the code-offset fuzzy commitment reconstruct (which uses codes.py BCH)
        recovered = FuzzyExtractor().reconstruct(masked_candidate, helper)
        if recovered is None:
            raise RuntimeError("PUF reconstruction failed (excessive noise or wrong device)")
        return recovered

    def derive_device_secret(self, puf_secret: bytes, label: str) -> bytes:
        keys = derive_device_keys(puf_secret, self.device_id)
        if label not in keys:
            raise ValueError(f"Unknown key label: {label}")
        return keys[label]

    def sign_attestation(self, private_key_bytes: bytes, message: bytes) -> bytes:
        private_key = ec.derive_private_key(
            int.from_bytes(private_key_bytes, "big"),
            ec.SECP256R1()
        )
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def get_device_measurement(self) -> bytes:
        # Simulate measuring the bootloader/hardware state
        return sha256(b"bootloader_measurement_v1")

    def read_monotonic_counter(self) -> int:
        # Use DB as simulated secure NVRAM
        device = self._db.get_device(self.device_id)
        if not device or not device.get("min_firmware_version"):
            return 0
        version_str = device["min_firmware_version"]
        try:
            return sum(int(x) * (100 ** i) for i, x in enumerate(reversed(version_str.split('.'))))
        except Exception:
            return 0

    def update_monotonic_counter(self, new_version: int) -> None:
        # Not fully mapped to string version format in this simplified sim
        pass

    def verify_firmware(self, manifest: bytes, signature: bytes, public_key: bytes) -> bool:
        # To be implemented by FirmwareImage logic, but we do basic check
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        try:
            pub_key = load_pem_public_key(public_key)
            pub_key.verify(signature, manifest, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def verify_kernel(self, kernel_image: bytes, expected_hash: bytes) -> bool:
        return sha256(kernel_image) == expected_hash

    def verify_rootfs(self, rootfs_image: bytes, expected_hash: bytes) -> bool:
        return sha256(rootfs_image) == expected_hash
