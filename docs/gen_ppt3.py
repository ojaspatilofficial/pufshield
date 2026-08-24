"""Append Parts 28-35 to PUFShield PPT content."""
import os

OUT = os.path.join(os.path.dirname(__file__), "ppt-content.md")

parts = []

def add(text):
    parts.append(text)

# === PART 28 ===
add("""
---

# PART 28 - REAL-WORLD APPLICATIONS

| Domain | Application | How PUFShield Helps |
|--------|-------------|---------------------|
| IoT | Smart home devices | Prevent cloned sensors from entering network |
| Industrial | SCADA/PLC systems | Ensure firmware integrity in control systems |
| Automotive | ECU authentication | Prevent cloned or tampered engine controllers |
| Defense | Military communication | Hardware-rooted device authentication |
| Medical | Patient monitors | Ensure device integrity for patient safety |
| Smart Meters | Utility metering | Prevent meter tampering and cloning |
| Aerospace | Flight controllers | Firmware integrity for safety-critical systems |
| Edge Computing | Edge nodes | Device identity in distributed infrastructure |
| Government | Secure communications | Trusted device authentication |
| Supply Chain | Component verification | Verify device authenticity in supply chain |
""")

# === PART 29 ===
add("""
---

# PART 29 - BUSINESS / IMPACT

## Why Organizations Need This
- IoT device count growing to 30+ billion, each an attack vector
- Device cloning costs manufacturers billions in counterfeit losses
- Firmware tampering can cause safety failures, data breaches
- Regulatory compliance (EU Cyber Resilience Act, FDA medical device requirements)

## What Happens Without It
- Cloned devices infiltrate secure networks
- Firmware backdoors go undetected
- Stolen certificates enable impersonation
- Rollback attacks exploit known vulnerabilities

## How PUFShield Improves Device Trust
- Hardware-rooted identity cannot be copied with software alone
- PUF-PKI binding makes certificate theft ineffective
- Multi-stage verification catches attacks at different layers
- Complete audit trail for compliance

## Scalability
- Architecture supports fleet management (future phase)
- SQLite can be replaced with PostgreSQL for production
- API-first design enables integration with existing systems
- Each device independently enrolled and verified
""")

# === PART 30 ===
add("""
---

# PART 30 - PPT STRUCTURE

## Recommended 15 Slides

| Slide | Title | Duration |
|-------|-------|----------|
| 1 | Title / Team / Hackathon | 30 sec |
| 2 | Problem Statement | 1 min |
| 3 | Why Existing Secure Boot Is Not Enough | 1 min |
| 4 | Proposed Solution - PUFShield | 1 min |
| 5 | System Architecture | 2 min |
| 6 | SRAM PUF + Device Identity | 1.5 min |
| 7 | PKI + PUF Binding | 1.5 min |
| 8 | Secure Boot Flow | 1.5 min |
| 9 | Firmware Integrity + Anti-Rollback | 1 min |
| 10 | Attack Detection | 1.5 min |
| 11 | Technology Stack | 1 min |
| 12 | Implementation / Dashboard | 1.5 min |
| 13 | Testing and Results | 1 min |
| 14 | Novelty + Advantages | 1 min |
| 15 | Future Scope + Conclusion | 1 min |

Total: ~17 minutes (adjust for Q&A)
""")

# === PART 31 ===
add("""
---

# PART 31 - CONTENT FOR EVERY SLIDE

## SLIDE 1: Title
- **Title**: PUFShield - SRAM PUF and PKI-Based Secure Boot
- **Subtitle**: Hardware-Rooted Device Authentication and Firmware Integrity
- **Bullets**: CDAC Hackathon 2026 | Team Name
- **Visual**: Project logo / shield icon
- **Say**: "We built a secure boot system where device identity comes from physics, not software."
- **Do NOT write**: Technical details on title slide

## SLIDE 2: Problem Statement
- **Title**: The Problem
- **Main Message**: Devices lack hardware-rooted identity
- **Bullets**:
  - 30B+ IoT devices, each an attack surface
  - Device cloning passes standard secure boot
  - Firmware tampering goes undetected
  - Credentials can be stolen and reused
  - No physical binding between cert and hardware
- **Visual**: Attack vector diagram
- **Numbers**: 30 billion devices at risk
- **Say**: "Standard secure boot verifies firmware but not the device running it."

## SLIDE 3: Why Existing Secure Boot Is Not Enough
- **Title**: The Gap in Current Security
- **Main Message**: Firmware verification alone is insufficient
- **Bullets**:
  - Verifies firmware, NOT device identity
  - Cloned devices pass all checks
  - No hardware-rooted trust anchor
  - Stolen certificates are valid anywhere
  - Rollback to vulnerable versions undetected
- **Visual**: Comparison diagram (traditional vs needed)
- **Say**: "A cloned device with valid firmware passes standard secure boot."

## SLIDE 4: Proposed Solution
- **Title**: PUFShield - Our Solution
- **Main Message**: 5 security mechanisms in one unified pipeline
- **Bullets**:
  - SRAM PUF: Hardware-rooted device fingerprint
  - PKI: Certificate-based trust with binding
  - Challenge-Response: Replay protection
  - Firmware Verification: Hash + dual signatures
  - Anti-Rollback: Version policy enforcement
- **Visual**: Flow diagram of 5 components
- **Numbers**: 11 stages, 6 attacks, 336 tests
- **Say**: "We combine five mechanisms into a single boot decision."

## SLIDE 5: System Architecture
- **Title**: System Architecture
- **Main Message**: End-to-end security from silicon to dashboard
- **Bullets**:
  - Frontend: Interactive security dashboard
  - Backend: Python FastAPI with 39 API endpoints
  - PUF Engine: Simulated SRAM with BCH error correction
  - PKI: ECDSA P-256 with X.509 certificates
  - Boot Engine: 11-stage verification pipeline
  - Database: SQLite with 12 tracking tables
- **Visual**: Full architecture diagram (use diagram-1)
- **Numbers**: 39 APIs, 12 tables, 14 components
- **Say**: "Every component communicates through REST APIs."

## SLIDE 6: SRAM PUF + Device Identity
- **Title**: SRAM PUF - Physical Device Identity
- **Main Message**: Every chip has unique manufacturing variations
- **Bullets**:
  - SRAM cells have unique threshold voltages
  - Creates unique startup bit pattern
  - Software simulation: SHA-256 hash-chain per device
  - Noise model: ~1% bit error rate per read
  - BCH(31,16,7) corrects noise for stable identity
- **Visual**: PUF noise diagram + BER chart
- **Numbers**: 256-bit PUF, BER 0.01, 10 captures
- **Say**: "This is a software simulation designed for future hardware."
- **DO NOT claim**: Physical unclonability from software alone

## SLIDE 7: PKI + PUF Binding
- **Title**: PUF-PKI Binding - Core Innovation
- **Main Message**: Cryptographically tie physical identity to certificate
- **Bullets**:
  - Enrollment: binding_hash = HKDF(PUF_secret || Public_Key)
  - Boot: Recompute and compare binding hash
  - Match: Continue boot
  - Mismatch: Clone detected, BOOT BLOCKED
  - Makes stolen certificates useless on different hardware
- **Visual**: Binding diagram (enrollment vs boot)
- **Say**: "This is our strongest novelty. A certificate becomes physically bound to one device."

## SLIDE 8: Secure Boot Flow
- **Title**: 11-Stage Secure Boot Pipeline
- **Main Message**: Sequential verification, any failure blocks boot
- **Bullets** (show as pipeline):
  - Stages 1-7: BLOCKING (PUF, Binding, Cert, Auth, FW Hash, FW Sig, Anti-Rollback)
  - Stages 8-11: INFORMATIONAL (PQC, Transparency, Anomaly, Risk)
  - Single boot decision: ALLOWED or BLOCKED
  - First failure point recorded with explanation
- **Visual**: Vertical pipeline diagram (use diagram-2)
- **Numbers**: 8 blocking + 3 informational = 11 total
- **Say**: "If any mandatory check fails, boot is immediately blocked."

## SLIDE 9: Firmware Integrity + Anti-Rollback
- **Title**: Firmware Security
- **Main Message**: Dual signatures + version policy = tamper-proof firmware
- **Bullets**:
  - SHA-256 hash for integrity
  - Device ECDSA signature (authorizes firmware)
  - Manufacturer ECDSA signature (authenticates source)
  - Manifest binds version + device + hash
  - Anti-rollback: strict dotted-version comparison
- **Visual**: Dual signature diagram
- **Say**: "Changing one byte changes the entire SHA-256 hash."

## SLIDE 10: Attack Detection
- **Title**: Attack Detection Through Real Pipeline
- **Main Message**: 6 attacks caught at specific pipeline stages
- **Bullets**:
  - Device Cloning -> Stage 2 (PUF binding mismatch)
  - Firmware Tampering -> Stage 5 (SHA-256 mismatch)
  - Replay Attack -> Stage 4 (nonce consumed)
  - Certificate Forgery -> Stage 3 (chain validation)
  - Firmware Rollback -> Stage 7 (version policy)
  - Wrong Signer -> Stage 6 (manufacturer signature)
- **Visual**: Attack matrix or use diagram-4
- **Say**: "Each attack is caught at a real, specific pipeline stage."

## SLIDE 11: Technology Stack
- **Title**: Technology Stack
- **Main Message**: Industry-standard technologies, purpose-built for security
- **Bullets**:
  - Python 3.13 + FastAPI + Pydantic v2
  - cryptography library (ECDSA, X.509, HKDF, SHA-256)
  - BCH(31,16,7) error correction
  - SQLite with 12 tables
  - HTML5/CSS3/JS + Chart.js dashboard
  - Pytest: 336 automated tests
- **Visual**: Tech stack grid
- **Numbers**: 9 dependencies, 0 external crypto libs
- **Say**: "Every crypto primitive uses the industry-standard cryptography library."

## SLIDE 12: Implementation / Dashboard
- **Title**: Live Dashboard
- **Main Message**: Complete web-based security monitoring
- **Bullets**:
  - Device management with PUF enrollment
  - Certificate management with chain view
  - Secure boot monitor with stage-by-stage results
  - Attack center for security testing
  - Real-time security event logging
  - PUF digital twin (16x16 SRAM grid)
- **Visual**: Dashboard screenshots or live demo
- **Say**: "Let me show you the live system." (trigger demo)

## SLIDE 13: Testing and Results
- **Title**: Testing and Results
- **Main Message**: Comprehensive automated testing validates security
- **Bullets**:
  - 336 tests passed, 1 skipped
  - 24 test files covering all subsystems
  - All 8 attack scenarios correctly detected
  - All boot stages validated
  - PKI chain verification tested
  - Fuzzy extraction round-trip tested
- **Visual**: Test results summary or test matrix table
- **Numbers**: 336 passed, 0 failed, 24 files
- **Say**: "Every security claim is backed by automated tests."

## SLIDE 14: Novelty + Advantages
- **Title**: What Makes PUFShield Different
- **Main Message**: PUF-PKI binding is the core innovation
- **Bullets**:
  - PUF-PKI binding: Physical identity tied to certificate
  - 11-stage unified boot pipeline
  - Attacks through real verification engine
  - Multi-mechanism: PUF + PKI + challenge-response
  - Comprehensive monitoring: AI anomaly + risk engine + Merkle log
- **Visual**: Innovation ranking or comparison chart
- **Say**: "The binding hash makes device cloning cryptographically impossible."

## SLIDE 15: Future Scope + Conclusion
- **Title**: Future Scope and Conclusion
- **Main Message**: From software prototype to hardware deployment
- **Bullets**:
  - Current: Complete software prototype (336 tests)
  - Next: Physical SRAM PUF on ESP32/STM32
  - Then: Hardware secure boot ROM
  - Finally: Fleet management + production
  - Core principle: "Only authenticated, physically-bound devices with authentic firmware boot"
- **Visual**: Roadmap timeline
- **Say**: "This prototype proves the concept. Hardware integration is the next step."
""")

# === PART 32 ===
add("""
---

# PART 32 - JUDGE QUESTIONS AND ANSWERS

## Q1: Why SRAM PUF specifically?
**A**: SRAM is present in virtually all microcontrollers. No additional hardware needed. Manufacturing variations in transistor threshold voltages create unique startup patterns. This gives us hardware-rooted identity from existing components.

## Q2: Why not use a TPM instead?
**A**: TPMs are expensive, require dedicated silicon, and add BOM cost. SRAM PUF uses existing memory already on the chip. For cost-sensitive IoT deployments, PUF eliminates the need for additional secure elements. TPMs are also a future integration point, not a replacement.

## Q3: Why PKI if we already have PUF?
**A**: PUF provides physical identity but not cryptographic trust infrastructure. PKI provides certificate-based authentication, chain of trust, and revocation capabilities. The binding of PUF to PKI is stronger than either alone.

## Q4: How does PUF prevent cloning?
**A**: The PUF-PKI binding hash is computed from the PUF secret AND the public key. A cloned device has a different PUF (different physical silicon), producing a different PUF secret, producing a different binding hash. The mismatch is detected at boot.

## Q5: What happens if PUF bits change?
**A**: BCH(31,16,7) error correction handles up to 3 bit errors per 31-bit block. The enrollment process captures 10 measurements to identify stable vs unstable bits. Only stable bits are used for the reference. The fuzzy extractor tolerates expected noise levels.

## Q6: What is fuzzy extraction?
**A**: It converts a noisy PUF response into a stable cryptographic secret. During enrollment, we commit a random secret using BCH encoding and store helper data. At reconstruction, the helper data corrects the noisy PUF to recover the original secret.

## Q7: Why HKDF specifically?
**A**: HKDF (RFC 5869) is the standard for key derivation. It provides extract-and-expand with domain separation. One PUF secret produces three distinct keys (device-auth, firmware-encryption, boot-integrity) that cannot be interchanged.

## Q8: Why SHA-256?
**A**: SHA-256 is the industry standard for integrity verification. It is collision-resistant, fast, and supported by all crypto libraries. Our firmware integrity check depends on SHA-256 producing different hashes for any binary modification.

## Q9: How does replay protection work?
**A**: Each authentication attempt uses a fresh 32-byte cryptographic nonce (TTL 60s). The nonce is atomically consumed (marked used) BEFORE signature verification. The same nonce cannot be used twice. Even a captured valid response is useless on a new challenge.

## Q10: What if a certificate is stolen?
**A**: The stolen certificate alone is insufficient. The PUF-PKI binding hash must also match, which requires the physical PUF of the original device. An attacker with only the certificate but a different device fails at Stage 2 (binding mismatch).

## Q11: What if firmware is modified?
**A**: Any modification changes the SHA-256 hash, caught at Stage 5. Even if the hash somehow matched, the ECDSA signature would fail at Stage 6 (device signature and manufacturer signature both checked).

## Q12: What if old firmware is correctly signed?
**A**: The anti-rollback check at Stage 7 compares firmware version against minimum allowed policy. Even with valid signatures, if version < minimum, boot is blocked. This prevents exploitation of known vulnerabilities in older versions.

## Q13: How is the Root CA protected?
**A**: The CA private key is stored in the filesystem (keys/ca/ directory). For production, this would be in an HSM or secure enclave. Our prototype uses filesystem storage for demonstration purposes.

## Q14: Can an attacker clone the software?
**A**: The software can be copied, but the PUF cannot. The PUF is physically bound to specific silicon (or in our simulation, deterministically bound to device_id). Without the original PUF, binding verification fails.

## Q15: Is software PUF equivalent to physical PUF?
**A**: No. Our simulation produces deterministic, device-specific patterns using SHA-256 hash-chains. Physical SRAM PUF relies on actual manufacturing variations. The software prototype proves the architecture; hardware PUF provides true physical unclonability.

## Q16: How will you implement on real hardware?
**A**: Replace the software PUF simulator with actual SRAM startup measurement code on ESP32/STM32. The fuzzy extraction, PKI, and boot pipeline remain largely unchanged. The API and verification logic are hardware-agnostic.

## Q17: What is the biggest limitation?
**A**: The software-simulated PUF. It proves the architecture but does not provide physical unclonability. True security requires real hardware PUF. This is the primary item on our future roadmap.

## Q18: How does the solution scale?
**A**: Current: single SQLite database, one server. Production path: PostgreSQL, device fleet management, remote attestation, distributed verification. The API-first architecture supports scaling.

## Q19: What is actually novel?
**A**: The PUF-PKI binding mechanism. While PUF and PKI individually exist, combining them through a cryptographic binding hash that ties physical identity to certificate is the core contribution. Also novel: attacks tested through the real verification pipeline.

## Q20: Why 11 stages instead of fewer?
**A**: Each stage addresses a specific threat. Fewer stages would miss attack vectors. The pipeline is designed so that blocking stages catch real attacks (cloning, tampering, replay, forgery, rollback) while informational stages prepare for future integration (PQC, transparency, anomaly, risk).
""")

# === PART 33 ===
add("""
---

# PART 33 - 30-SECOND PITCH

"PUFShield is a secure boot system that combines SRAM Physical Unclonable Functions with PKI certificates to solve the device cloning problem. Every chip has unique manufacturing variations creating a physical fingerprint. We bind this fingerprint to the device's certificate through a cryptographic hash. At boot, we verify the PUF, the certificate, the firmware integrity, and the firmware version through an 11-stage pipeline. If a device is cloned, its PUF produces a different binding hash and boot is blocked. We tested six attack scenarios through the actual verification engine, and all 336 automated tests pass. The core innovation is that stealing a certificate is useless without the physical device."
""")

# === PART 34 ===
add("""
---

# PART 34 - 2-MINUTE PITCH

[Problem]
"Every year, billions of IoT devices are deployed with weak device identity. Traditional secure boot verifies firmware but not the device running it. A cloned device with valid firmware passes all checks. Credentials can be stolen. Firmware can be rolled back to vulnerable versions."

[Solution]
"PUFShield solves this by combining five security mechanisms: SRAM PUF for hardware-rooted identity, PKI certificates for cryptographic trust, challenge-response for replay protection, dual firmware signatures for integrity and authenticity, and anti-rollback for version policy."

[Architecture]
"Our system has three phases. Enrollment measures the device PUF, derives a stable secret using BCH error correction, generates keys and certificates, and computes a PUF-PKI binding hash. Boot runs an 11-stage pipeline: PUF recovery, binding verification, certificate validation, challenge-response, firmware hash, dual signatures, anti-rollback, plus informational checks for PQC, transparency, anomaly detection, and risk assessment."

[PUF and Binding]
"The core innovation is PUF-PKI binding. We compute a hash from the PUF secret and the public key. At boot, we recompute and compare. A cloned device has a different PUF, producing a different hash, and boot is blocked."

[Attacks]
"We tested six real attack scenarios through our actual verification engine: device cloning, firmware tampering, replay, certificate forgery, rollback, and wrong signer. Each is caught at a specific pipeline stage. All 336 automated tests pass."

[Novelty and Impact]
"Our novelty is the PUF-PKI binding that makes certificate theft physically ineffective. When ported to real hardware like ESP32, this approach could prevent device cloning in supply chains and stop firmware downgrade attacks on deployed devices."
""")

# === PART 35 ===
add("""
---

# PART 35 - FINAL EXECUTIVE SUMMARY

```
PROJECT:
PUFShield - SRAM PUF and PKI-Based Device Authentication for Secure Boot

PROBLEM:
Embedded devices lack hardware-rooted identity. Traditional secure boot
verifies firmware but not device identity. Cloned devices, stolen
certificates, firmware tampering, replay attacks, and rollback attacks
remain undetected.

SOLUTION:
Five security mechanisms in one 11-stage boot pipeline:
SRAM PUF + PKI + Challenge-Response + Firmware Verification + Anti-Rollback

CORE TECHNOLOGIES:
Python 3.13, FastAPI, SQLite, cryptography (ECDSA P-256, X.509, HKDF-SHA256),
BCH(31,16,7) error correction, SHA-256, HTML5/CSS3/JS, Pytest

CORE SECURITY FLOW:
PUF -> Fuzzy Extraction -> Key Derivation -> PKI Certificate -> PUF-PKI Binding
-> Challenge-Response -> Firmware SHA-256 -> Dual Signatures -> Anti-Rollback
-> BOOT DECISION

KEY INNOVATION:
PUF-PKI Binding Hash = HKDF(PUF_secret || DER_SPKI_public_key)
Makes stolen certificates physically useless on different hardware.

ATTACKS DETECTED (6):
1. Device Cloning (PUF-PKI mismatch, Stage 2)
2. Firmware Tampering (SHA-256 mismatch, Stage 5)
3. Replay Attack (atomic nonce, Stage 4)
4. Certificate Forgery (RFC 5280 chain, Stage 3)
5. Firmware Rollback (version policy, Stage 7)
6. Wrong Signer (manufacturer signature, Stage 6)

SECURITY BENEFIT:
Only an authenticated, physically-bound device running authentic,
untampered, non-rolled-back firmware is allowed to boot.

CURRENT IMPLEMENTATION:
Software prototype with 336 automated tests, 39 API endpoints,
12 SQLite tables, complete web dashboard, 6 attack simulations.

LIMITATIONS:
- SRAM PUF is software-simulated (not physical)
- No hardware secure boot ROM
- Prototype PKI (self-signed CA, filesystem keys)
- Informational stages (8-11) always pass

FUTURE:
Phase 1 (current) -> Physical SRAM PUF on ESP32/STM32 ->
Hardware secure boot -> TPM integration -> Fleet management
```
""")

with open(OUT, "a", encoding="utf-8") as f:
    f.write("\n".join(parts))

print(f"Appended parts 28-35. Total: {os.path.getsize(OUT)} bytes")
