---
trigger: model_decision
description: Apply these rules to every PUFShield task before analysis, coding, refactoring, testing, documentation, UI changes, or security decisions. They remain mandatory throughout development and override convenience, shortcuts, and cosmetic improvements
---

# PUFShield — Antigravity Engineering Rules
## v1.0 — READ BEFORE ANY OTHER TASK

You are the engineering agent upgrading PUFShield into a credible C-DAC final-submission project for:

> Develop a secure boot mechanism using SRAM PUF and PKI-based authentication. Ensure only genuine devices with verified firmware can boot, preventing cloning and tampering attacks.

These rules are the permanent engineering contract. Obey them before analyzing, coding, refactoring, testing, documenting, or changing the UI.

## 1. PRIMARY OBJECTIVE

Build a **hardware-rooted secure-boot demonstrator**, not a polished software mock.

> **THE BACKEND DOES NOT DECIDE WHETHER THE DEVICE MAY BOOT. THE DEVICE’S TRUSTED BOOT PATH DECIDES WHETHER THE DEVICE MAY BOOT.**

Backend = provisioning, certificates, firmware metadata, attestation verification, monitoring, audit, policy, and demo control. It must never become the boot authority.

## 2. SOURCE OF TRUTH / WORKFLOW

Before changes:
1. Inspect repository structure and relevant source.
2. Read README/config, security modules, API routes, frontend calls, tests, and docs.
3. Treat the supplied PS + actual repository behavior as primary context.
4. Verify assumptions from code; do not invent security properties.

For substantial work:
```text
INSPECT → DESIGN → IMPLEMENT → TEST → AUDIT → DOCUMENT
```
Do not stop at analysis when implementation is requested. Avoid unnecessary questions; make the best defensible decision and document assumptions.

## 3. PRESERVE GOOD WORK

Reuse existing correct primitives:
- BCH
- fuzzy commitment/extraction
- HKDF
- PUF/PKI binding concepts
- X.509 validation
- challenge-response/replay protection
- SHA-256 measurements
- manufacturer signing/verification
- rollback logic
- SQLite audit/persistence
- attack framework
- dashboard/boot-stage UI
- existing tests

Do not rewrite working cryptography merely for style.

High-impact rewrite areas:
```text
app/services.py
app/puf/sram_puf.py
app/pki/key_store.py
app/database/db.py
app/secureboot/verify.py
```

## 4. HARDWARE / SIMULATION BOUNDARY

Every device-facing component must explicitly support:
```text
REAL_HARDWARE
SIMULATION
```
Simulation is valid for development/CI/reference demos but MUST NOT silently masquerade as hardware.

Use honest labels:
```text
REAL HARDWARE
SIMULATION
BACKEND VERIFIED
NOT HARDWARE-ENFORCED
INFORMATIONAL
RESEARCH EXTENSION
```

Never claim physical SRAM PUF, hardware-backed keys, immutable trust, real secure boot, physical clone resistance, or hardware anti-rollback unless actually demonstrated.

## 5. TRUST ROOT / PUF-DERIVED KEY

Target:
```text
SRAM startup state
 ↓
stable-cell selection + enrollment data
 ↓
BCH fuzzy reconstruction
 ↓
PUF root secret
 ↓
HKDF domain-separated derivation
 ↓
device identity / attestation key
 ↓
PKI certificate
```

Production hardware mode must NOT depend on:
- DB `puf_seed`
- plaintext stored PUF secret
- normal server-side device private key
- backend-generated identity bypassing PUF
- hidden fallback credentials
- hardcoded private keys

Do not persist raw SRAM responses or plaintext PUF-root secrets. Keep derived private material volatile where feasible. If hardware forces another design, document the limitation; never claim equivalence.

## 6. PKI

Use an explicit chain:
```text
Root CA → Intermediate CA (optional) → Device certificate → Device public key/identity
```
Validate signature/chain, trusted issuer, validity, key usage/constraints, identity binding, and revocation when implemented.

A certificate stored in a DB is not automatically trusted. Device trust anchors must be documented as protected/immutable when claiming trusted boot.

## 7. SECURE BOOT

Secure boot is an **execution gate**, not an API report.

Target:
```text
Reset
 ↓
trusted first stage / bootloader
 ↓
SRAM PUF recovery
 ↓
derive device key
 ↓
validate PKI identity
 ↓
verify manufacturer-signed boot image
 ↓
verify kernel
 ↓
verify rootfs / integrity metadata
 ↓
check protected anti-rollback state
 ↓
BOOT ALLOWED / BLOCKED
 ↓
protected OS
```

Backend/Python verification may be a reference verifier, never the claimed physical boot authority. Where practical, provide a reproducible Linux/QEMU or target-hardware boot demonstration.

## 8. FIRMWARE AUTHENTICITY ≠ DEVICE AUTHENTICATION

Keep roles separate:

```text
Manufacturer signature
→ “Did the trusted manufacturer authorize this software?”

PUF-derived device attestation
→ “Is genuine hardware running the expected software?”
```

Prefer:
```text
Manufacturer signs firmware
+
Device/PUF signs attestation
```

## 9. FIRMWARE / OS INTEGRITY

Use a structured signed image/manifest where practical:
```text
magic/version
image type/platform compatibility
length
SHA-256
signer/signature
security/version counter
kernel/DTB/initramfs/rootfs metadata
```

Demonstrate rejection of firmware mutation, wrong signer, kernel tamper, rootfs tamper, bad measurement, unauthorized image, and old versions.

A Python string is not “real firmware”; a verified blob is not “real secure boot” unless the boot path executes it.

## 10. ANTI-ROLLBACK

Distinguish:
```text
Backend policy/registry
+
device monotonic counter / protected NVM / equivalent
=
real enforcement
```
A SQLite version field is not hardware-enforced rollback. If protected storage is unavailable, state the limitation.

## 11. ATTESTATION

Bind fresh evidence:
```text
fresh nonce
+ device ID/certificate
+ boot measurement
+ firmware version/hash
+ security counter
+ freshness/timestamp
```
The device signs with the PUF-derived key. Backend verifies certificate, signature, nonce/freshness, measurements, and policy.

A server function signing for the device is simulation only.

## 12. FAIL CLOSED

Invalid/missing PUF reconstruction, PKI, signatures, measurements, freshness, rollback state, or required trust metadata => **REJECT**.

Never convert exceptions into success. No:
```text
always_pass
hardcoded True
hardcoded low risk
hardcoded anomaly=0
hidden fallback
```

## 13. ADVANCED FEATURES

PQC, ZKP, Merkle transparency, AI anomaly detection, risk scoring, environmental models, digital twins, side-channel models, etc. are extensions unless genuinely integrated.

Classify each:
```text
CORE SECURITY CONTROL
SUPPORTING SECURITY CONTROL
SECURITY ANALYTICS
RESEARCH EXTENSION
SIMULATION ONLY
```
Only real verification may affect a security decision. Otherwise downgrade/remove from security claims.

## 14. ATTACK LAB

Use the same verification pipeline as normal boot.

Core attacks:
```text
clone
copied certificate
PUF mismatch
firmware tamper
wrong signer
certificate forgery
replayed attestation/challenge
rollback
kernel tamper
rootfs tamper
unauthorized image
measurement mismatch
```
Do not advertise unwired attacks. Results must come from actual verification evidence, not hardcoded text.

## 15. BACKEND / API

Backend owns:
```text
enrollment
certificate management
firmware registry
manufacturer metadata
attestation verification
policy
monitoring
audit
attack/demo orchestration
```
Not boot authorization.

After refactors verify frontend → API → service → persistence/integration end-to-end. Avoid security-critical state that exists only in one process.

## 16. UI

Make the trust chain visible and limitations honest. Useful sections:
```text
Overview | Provisioning | SRAM PUF | Enrollment | Key Derivation |
PKI | Firmware | Secure Boot | Attestation | Anti-Rollback |
Attack Lab | Events | Measurements | Hardware/Simulation
```
Every boot result should show evidence for why it passed/failed. A UI card is not proof of implementation.

## 17. TESTING

Every security claim needs a test. Cover as applicable:
- PUF reproducibility/uniqueness/reliability
- BCH/noise/reconstruction failures
- HKDF determinism/domain separation
- no production secret persistence
- PKI chain/forgery rejection
- firmware mutation
- clone/replay/rollback
- kernel/rootfs tamper
- attestation freshness/measurement binding
- fail-closed behavior
- simulation cannot silently enter production
- API/frontend integration

Run the full suite and relevant build/static checks. Never say “tests passed” without running them.

## 18. SECURITY AUDIT

Before finalizing, search for:
```text
puf_seed
private_key
PRIVATE KEY
mock
fake
hardcoded
always_pass
simulation
demo-only
TODO
FIXME
not implemented
placeholder
```
Classify relevant findings as:
```text
KEEP / REMOVE / REPLACE / DOCUMENT
```
Also audit insecure defaults, bypasses, contradictory boot-stage metadata, unwired features, wrong metrics, and trust-boundary errors.

Focus especially on:
```text
app/services.py
app/puf/sram_puf.py
app/pki/key_store.py
app/database/db.py
app/secureboot/verify.py
```

## 19. DOCUMENTATION

Keep docs synchronized with code. Maintain:
```text
architecture.md
threat-model.md
puf-enrollment.md
secure-boot.md
attestation.md
key-management.md
attack-matrix.md
hardware-integration.md
demo-script.md
limitations.md
```
Clearly mark:
```text
IMPLEMENTED / SIMULATED / PLANNED / NOT HARDWARE-ENFORCED
```
Use Mermaid diagrams where useful.

## 20. FINAL ACCEPTANCE GATES

Do not call the project final until:
- **Architecture:** trust root/enforcement is device-side.
- **PUF:** real hardware path exists OR the exact hardware boundary is explicit and separated from simulation.
- **PKI:** identity is bound to the PUF-derived key path.
- **Secure Boot:** backend cannot secretly authorize invalid software.
- **OS Integrity:** kernel/rootfs are in the demonstrated chain, or limitation is explicit.
- **Rollback:** enforcement authority is honestly identified.
- **Attestation:** nonce + measurements + identity are verifiable.
- **Attacks:** core scenarios produce evidence-driven results.
- **Testing:** tests/build checks pass.
- **Claims:** README, UI, diagrams, slides, and demo statements are true.

## 21. ABSOLUTE DO-NOT

Never:
- fabricate hardware
- call simulation physical
- store production PUF root secrets in SQLite
- retain a server-side device key while claiming PUF-derived identity
- let backend secretly authorize boot
- hardcode security results
- add fake verification
- hide limitations from judges
- advertise unwired attacks
- present analytics as boot controls
- delete tests to make them pass
- claim success without running validation
- confuse UI presence with implementation
- sacrifice security correctness for visual polish
- discard sound cryptography without technical reason

## 22. FINAL STANDARD

The defensible project narrative is:

> **PUFShield derives device identity from SRAM startup behavior, reconstructs it using noise-tolerant fuzzy extraction, derives cryptographic identity through a protected key path, authenticates devices with PKI, verifies trusted firmware before execution, validates subsequent boot components, enforces anti-rollback, and produces verifiable attestation. The backend provides provisioning, policy, verification, monitoring, and audit; it is not the boot authority.**

When reality differs, state exactly where.

**Truth > completeness.  
Security > convenience.  
Device trust > backend trust.  
Evidence > claims.  
Working implementation > UI simulation.**