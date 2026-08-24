"""Append Parts 19-35 to PUFShield PPT content."""
import os

OUT = os.path.join(os.path.dirname(__file__), "ppt-content.md")

parts = []

def add(text):
    parts.append(text)

# === PART 19 ===
add("""---

# PART 19 - NOVELTY (Ranked)

## 1. PUF-PKI Binding (Strongest)
- binding_hash = HKDF(PUF_secret || DER_SPKI_public_key)
- Makes stolen certificates useless on different hardware

## 2. Unified 11-Stage Boot Pipeline
- 8 blocking + 3 informational stages
- Single decision engine, first failure recorded

## 3. Attacks Through Real Pipeline
- 6 attacks through actual verification, not simulated independently

## 4. Multi-Mechanism Authentication
- PUF (physical) + PKI (cryptographic) + Challenge-Response (temporal)

## 5. Comprehensive Security Monitoring
- AI anomaly detection, risk engine, Merkle transparency log

## 6. Future-Proofing
- ML-DSA-65 PQC, Schnorr ZKP, Environmental PUF simulation
""")

# === PART 20 ===
add("""
---

# PART 20 - SECURITY MODEL

## Threat Response Table

| Threat | Mechanism | Stage | Response |
|--------|-----------|-------|----------|
| Cloned Device | PUF-PKI binding | 2 | Boot blocked |
| Stolen Certificate | PUF binding invalid | 2 | Boot blocked |
| Modified Firmware | SHA-256 hash | 5 | Boot blocked |
| Replay Attack | Atomic nonce | 4 | Auth blocked |
| Fake Certificate | RFC 5280 chain | 3 | Auth blocked |
| Firmware Rollback | Version policy | 7 | Boot blocked |
| Unauthorized Device | No enrollment | 1 | Boot blocked |
| Wrong Signer | Manufacturer sig | 6 | Boot blocked |
""")

# === PART 21 ===
add("""
---

# PART 21 - DATABASE (SQLite, 12 Tables)

| Table | Purpose |
|-------|---------|
| devices | Registered devices with binding_hash |
| puf_enrollments | Helper data, reference, stability metrics |
| certificates | X.509 PEM, issuer, serial, validity |
| firmware_images | Version, SHA-256, dual signatures |
| boot_logs | Per-stage results, timing, posture |
| authentication_events | Challenge-response audit trail |
| security_events | Severity-tagged audit log |
| auth_challenges | Nonce management (atomic consumption) |
| attack_logs | Attack type, detection result |
| transparency_entries | Merkle tree records |
| pqc_keys | ML-DSA-65 key registration |
| risk_assessments | 7-layer risk score history |
""")

# === PART 22 ===
add("""
---

# PART 22 - API ARCHITECTURE (39 Endpoints)

## Key API Groups

| Group | Count | Endpoints |
|-------|-------|-----------|
| Devices | 7 | CRUD, certificate, version policy |
| PUF | 2 | Test, analysis |
| Firmware | 4 | Create, sign, list, verify |
| Boot | 4 | Run, logs, report, metrics |
| Auth | 3 | Challenge, authenticate, logs |
| Attacks | 3 | List, run, logs |
| Security | 2 | Events, timeline |
| PQC | 1 | ML-DSA-65 keygen |
| ZKP | 2 | Schnorr prove/verify |
| Environmental | 1 | PUF environmental data |
| Anomaly | 1 | AI anomaly analysis |
| Risk | 2 | Assess, history |
| Transparency | 3 | Record, verify, history |
| Twin | 1 | Digital twin grid |
| Dashboard | 1 | System stats |
| Health | 1 | Health check |
| Manufacturer | 1 | Public key |
""")

# === PART 23 ===
add("""
---

# PART 23 - TESTING

## Summary
- **336 tests passed, 1 skipped**
- **24 test files** covering all subsystems

## Test Matrix

| Scenario | Expected | Actual | Status |
|----------|----------|--------|--------|
| Genuine device boot | BOOT_ALLOWED | BOOT_ALLOWED | PASS |
| Tampered firmware | BOOT_BLOCKED (Stage 5) | BOOT_BLOCKED | PASS |
| Cloned device | BOOT_BLOCKED (Stage 2) | BOOT_BLOCKED | PASS |
| Replay attack | AUTH_BLOCKED (Stage 4) | AUTH_BLOCKED | PASS |
| Fake certificate | AUTH_BLOCKED (Stage 3) | AUTH_BLOCKED | PASS |
| Firmware rollback | BOOT_BLOCKED (Stage 7) | BOOT_BLOCKED | PASS |
| Wrong PUF | BOOT_BLOCKED (Stage 1) | BOOT_BLOCKED | PASS |
| Invalid signature | BOOT_BLOCKED (Stage 6) | BOOT_BLOCKED | PASS |
""")

# === PART 24 ===
add("""
---

# PART 24 - DEMO FLOW

## Live Demo Script (10-12 minutes)

### Phase 1: Setup (1 min)
1. Start server, open dashboard
2. "This is PUFShield - SRAM PUF plus PKI for secure boot."

### Phase 2: Legitimate Boot (2 min)
3. Register device, show PUF metrics
4. Show PKI certificate and chain
5. Run secure boot -> BOOT ALLOWED
6. "All 11 stages passed. Device authenticated."

### Phase 3: Firmware Tampering (2 min)
7. Upload tampered firmware
8. Run boot -> BOOT BLOCKED (Stage 5)
9. "SHA-256 hash mismatch - one byte changed the entire hash."

### Phase 4: Device Cloning (2 min)
10. Run clone_device attack
11. Boot -> BOOT BLOCKED (Stage 2)
12. "Different physical device, different PUF, binding mismatch."

### Phase 5: Replay Attack (1 min)
13. Run replay_challenge attack
14. Auth -> BLOCKED
15. "Nonce was already consumed. Cannot reuse."

### Phase 6: Rollback (1 min)
16. Set minimum version to v3, boot v2 firmware
17. BOOT BLOCKED (Stage 7)
18. "Older firmware blocked even though signatures are valid."

### Phase 7: Review (1 min)
19. Show security logs with all events
20. Show dashboard statistics
21. "Every attack detected, every event logged."
""")

# === PART 25 ===
add("""
---

# PART 25 - PERFORMANCE / METRICS

## Measurable Metrics (from codebase)

| Metric | Value | Source |
|--------|-------|--------|
| PUF BER | ~0.01 (1%) | sram_puf.py default noise_rate |
| PUF bit_size | 256 bits | sram_puf.py default |
| Enrollment captures | 10 | enrollment.py DEFAULT_CAPTURES |
| BCH correction | Up to 3 errors per 31-bit block | codes.py BCH(31,16,7) |
| Fuzzy secret size | 16 bytes (128 bits) | fuzzy.py auto-selection |
| Nonce size | 32 bytes (256 bits) | auth/auth.py |
| Nonce TTL | 60 seconds | auth/auth.py |
| Key size (HKDF) | 32 bytes (256 bits) | kdf.py |
| Boot stages | 11 (8 blocking + 3 info) | verify.py |
| Attack types | 6 implemented | attacks.py |
| Database tables | 12 | db.py |
| API endpoints | 39 | routes.py |
| Test count | 336 passed, 1 skipped | pytest |
| PKI chain depth | Max 8 levels | pki.py |
| Risk layers | 7 weighted components | engine.py |

## Recommended Future Measurements
- Actual API response time under load
- Boot pipeline total execution time per stage
- PUF uniqueness Hamming distance across multiple devices
- Database query performance at scale
""")

# === PART 26 ===
add("""
---

# PART 26 - LIMITATIONS

## Honest Assessment

1. **SRAM PUF is software-simulated**
   - SHA-256 hash-chain produces deterministic per-device patterns
   - Does not replicate actual physical manufacturing variations
   - Designed for future hardware integration

2. **No physical hardware demonstration**
   - Running on standard PC, not embedded MCU
   - No actual SRAM startup measurement
   - No physical secure boot ROM

3. **Prototype PKI environment**
   - Self-signed root CA (not external CA)
   - Keys stored in filesystem (not HSM/TPM)
   - No certificate revocation list (CRL)

4. **Local SQLite database**
   - Not suitable for production fleet management
   - Single-server deployment

5. **Informational boot stages (8-11) always pass**
   - PQC, transparency, anomaly, risk stages are logged but do not block
   - Full integration of these stages is future work

6. **ML-DSA-65 is demo-grade**
   - Keygen only, sign/verify simplified
   - Not production-ready PQC

## These Do Not Invalidate the Proof-of-Concept
- All security mechanisms are functionally implemented
- Attack detection through real pipeline is validated
- 336 tests confirm correctness
- Architecture is designed for hardware porting
""")

# === PART 27 ===
add("""
---

# PART 27 - FUTURE SCOPE

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Software prototype (current) | COMPLETED |
| Phase 2 | Physical SRAM PUF on ESP32/STM32 | Future |
| Phase 3 | Hardware secure boot ROM integration | Future |
| Phase 4 | TPM / Secure Element for key storage | Future |
| Phase 5 | Remote device attestation protocol | Future |
| Phase 6 | Fleet management for 1000+ devices | Future |
| Phase 7 | Production CRL / certificate revocation | Future |
| Phase 8 | ML-DSA-65 full sign/verify integration | Future |

## Key Transition Points
- Software PUF simulation -> Physical SRAM measurement
- SQLite -> PostgreSQL/device database
- Self-signed CA -> External CA integration
- Single device -> Fleet management
- Informational stages -> Active blocking stages
""")

with open(OUT, "a", encoding="utf-8") as f:
    f.write("\n".join(parts))

print(f"Appended parts 19-27. Total: {os.path.getsize(OUT)} bytes")
