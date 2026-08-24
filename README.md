# PUFShield

**SRAM PUF (Physical Unclonable Function) + PKI device authentication for secure boot.**

PUFShield demonstrates a hardware-rooted-of-trust boot and device-authentication
flow: an SRAM PUF power-up fingerprint is combined with X.509 certificates and a
11-stage secure-boot pipeline (8 blocking + 3 informational) so that only genuine, provisioned devices can
boot cryptographically verified firmware.

> **IMPORTANT — proof-of-concept notice.**
>
> - **SRAM PUF behavior is software-simulated** (`app/puf/sram_puf.py`). There
>   is no physical SRAM hardware, no on-chip startup read, and no measured
>   entropy. The simulator models the *statistical properties* of a real SRAM
>   PUF (uniqueness, stability, reliability, noise) so the rest of the stack can
>   be developed and tested end-to-end.
> - This project is a **proof-of-concept for an eventual embedded
>   implementation** (see [Future Hardware Implementation](#future-hardware-implementation)).
> - **Physical hardware security has not been demonstrated.** This repository
>   makes **no claim** of silicon-level unclonability, tamper resistance, or
>   side-channel resistance. "Hardware root of trust" here refers to the *design*
>   that a real PUF would fill.

---

## Problem Statement

Internet-of-Things and embedded devices routinely boot from external flash that
an attacker can **read, copy, and modify**. This creates a family of
exploitable weaknesses:

1. **Credential cloning** — device identities and signing keys stored in flash
   or EEPROM can be extracted and cloned onto counterfeit hardware. A cloned
   identity is indistinguishable from the genuine device.
2. **Firmware tampering** — an attacker who can modify flash can alter the
   bootloader or application image. Software-only integrity checks fail when
   the attacker can also rewrite the code that performs the check.
3. **Key escrow in firmware** — if the verification key is shipped inside the
   attacker-readable firmware, the attacker simply replaces the key along with
   the firmware, defeating the signature check.
4. **Replay and downgrade** — captured authentication traffic and older,
   vulnerable firmware can be replayed unless one-time nonces and a
   per-device anti-rollback policy are enforced.
5. **Per-device isolation** — a single extracted identity compromises the
   entire fleet unless each device has its own hardware-anchored identity and
   certificate.

The core problem: **a secret that is *stored* can be *stolen*; a genuine
identity must be *intrinsic* to the hardware, not stored on it.**

## Proposed Solution

PUFShield anchors device identity in an **SRAM Physical Unclonable Function** —
a power-up fingerprint derived from manufacturing variation that:

- is **unique** to each device (process variation differs between chips),
- is **not stored** anywhere (it exists only while the SRAM is powered and is
  regenerated from the same silicon at every power-up),
- **cannot be copied** — a cloned or emulated device does not have the same
  silicon and cannot reproduce the fingerprint.

Around that anchor, PUFShield builds a complete, testable security stack:

| Layer | Role |
|-------|------|
| **SRAM PUF** (simulated) | Hardware root of trust: unique, unclonable device fingerprint |
| **Fuzzy extraction** | BCH error correction + HKDF turn the *noisy* fingerprint into an *exact, repeatable* secret |
| **PKI** | Local root CA + one X.509 certificate per device binding the EC public key to the device identity |
| **PUF-to-key binding** | The PUF-derived secret is cryptographically bound to the device's certified public key |
| **Challenge-response auth** | Device proves possession of its key with a one-time signed nonce (replay-proof) |
| **Firmware verification** | Dual device + manufacturer signatures over a SHA-256 manifest |
| **Secure boot engine** | Seven mandatory stages; any failure blocks boot (`BOOT_BLOCKED`) |
| **Anti-rollback** | Per-device minimum firmware version, checked after the image is authenticated |
| **Attack Center** | Real attack simulations that mutate the *actual* verified data |
| **Audit trail** | SQLite event feed for every boot, auth, and attack attempt |

Because a PUF is inherently noise-tolerant, a real SRAM PUF would be embedded in
the device and read at boot time; the rest of this pipeline (fuzzy extraction,
PKI, boot logic, anti-rollback) is implemented in full.

## System Architecture

```
                           ┌──────────────────────────────────────────┐
                           │              Web Dashboard              │
                           │        (devices · PUF viz · boots ·     │
                           │          attacks · auth · events)       │
                           └───────────────────▲──────────────────────┘
                                               │ static + JSON
┌──────────────────────────────────────────────┴───────────────────────────┐
│                          FastAPI (REST + TestClient)                     │
│  /api/devices · /api/puf · /api/firmware · /api/boot · /api/auth ·      │
│  /api/attacks · /api/security · /api/dashboard                            │
└──────┬────────────────┬──────────────────┬───────────────────┬──────────┘
       │                │                  │                   │
       ▼                ▼                  ▼                   ▼
┌─────────────┐  ┌──────────────┐   ┌────────────────┐   ┌───────────────┐
│  Service    │  │ SecureBoot   │   │  AuthManager   │   │ AttackSimulator│
│ (services)  │  │  (7 stages)  │   │ (challenge-resp)│  │ (real attacks) │
└──────┬──────┘  └──────┬───────┘   └───────┬────────┘   └───────┬───────┘
       │                │                   │                   │
       ▼                ▼                   ▼                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  PUF module        PKI module         Firmware module      Crypto utils  │
│  sram_puf ·        key_store ·        image (dual sigs) ·  sha256 ·      │
│  enrollment ·      pki · root CA      manufacturer ·        hmac · rng   │
│  fuzzy extractor   + intermediates     version policy                    │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
                                   ▼
                    ┌────────────────────────────┐
                    │  SQLite persistence + key  │
                    │  store (data/, env-set)    │
                    └────────────────────────────┘
```

**Module layout**

```
app/
├── main.py            FastAPI application entry point
├── config.py          Environment / .env settings
├── services.py        Orchestration layer (provision, boot, auth, attacks)
├── api/               REST API routes
├── puf/               SRAM PUF simulation (enroll / regenerate / verify)
├── fuzzy/             Fuzzy extraction (BCH error correction + HKDF device keys)
├── auth/              Challenge-response device authentication
├── crypto/            Cryptographic helpers (SHA-256, HMAC, secure RNG)
├── pki/               Root CA + device certificates (KeyStore, PKIManager)
├── firmware/          Signed firmware image format
├── secureboot/        PUF + PKI boot verification pipeline
├── attacks/           Simulated attack scenarios
├── database/          SQLite persistence (devices, enrollments, certificates, firmware, boot/auth/security/attack events)
└── frontend/          Static dashboard (HTML / CSS / JavaScript)
tests/                 pytest suite (unit + integration + security)
data/                  Runtime SQLite database (gitignored)
```

## SRAM PUF Architecture

### Background: what a real SRAM PUF is

An SRAM cell is a pair of cross-coupled inverters that, at power-up, toggles
toward one of two stable states. Slight manufacturing variation decides which
value each cell prefers. At power-on the SRAM therefore presents a per-cell
bit pattern that is:

- **unique** to the specific chip (variation differs between chips),
- **stable** across power cycles for the large majority of cells,
- **noisy** for a small fraction of "metastable" cells that start at either
  value on each cycle,
- **impossible to clone** without the physical silicon.

### The simulation model (`app/puf/sram_puf.py`)

Since no physical SRAM exists in this repository, the simulator reproduces the
properties above with a deterministic per-device model:

- **Persistence** — a per-device `seed` (stored at provisioning time) is fed
  through a stretched SHA-256 construction to derive a stable baseline value
  for every cell. The same device always powers up to the same baseline.
- **Stability** — most cells always hold their baseline value.
- **Noise / reliability** — a deterministic metastable-cell mask marks roughly
  `2 × noise_rate` of the cells (default `noise_rate = 0.01`, i.e. a 1 %
  observable bit-error rate). Each power cycle, every metastable cell toggles
  with probability 0.5; stable cells never change. This mirrors real SRAM
  where the measured bit-error rate equals the fraction of metastable cells.
- **Uniqueness** — different devices (different identities/seeds) produce
  substantially different baselines; the fleet's mean pairwise inter-device
  Hamming distance is reported as `uniqueness`.

Each simulated "power cycle" returns a noisy response; the noise-free baseline
is used only as enrollment helper data. **No raw startup response is ever used
directly as a credential.**

> **Honesty note.** The simulator is a *statistical stand-in*. It does **not**
> claim to reproduce silicon-level entropy, correlated bit flips, temperature
> dependence, or anti-tamper behavior, and it does **not** claim physical
> unclonability against an attacker who could read the seed. In an embedded
> implementation the real SRAM startup read would replace this module; the
> rest of the pipeline is unchanged.

## PUF Enrollment

Provisioning a device (`POST /api/devices`, `Service.provision_device`) performs:

1. **Key + certificate first** — the device's EC key pair is generated and a
   device certificate is issued by the PKI (see [PKI Architecture](#pki-architecture)).
2. **PUF capture** — the simulated PUF is read `num_captures` (default 10)
   times to characterise it.
3. **Stability analysis** — cells that produced the same value in every capture
   are marked **stable**; the rest are **unstable (metastable)**. The
   **stability mask** (1 = stable) and a **stable-only reference** (unstable
   cells zeroed) are computed.
4. **Fuzzy commitment** — a random secret is committed to the stable-only
   reference via the code-offset fuzzy extractor (see
   [Fuzzy Extraction](#fuzzy-extraction)).
5. **Credential tag** — HKDF-SHA256 derives a domain-separated `device-auth`
   key from the secret; an **HMAC-SHA256 tag** of that key, keyed by a
   server-side secret stored *outside* the database, is stored as the
   credential.
6. **PUF-to-key binding** — `binding = HKDF(secret, salt=device_id,
   info="puf-binding" + device public key)` is computed and stored.

**Recorded metrics** (available via `/api/puf/analysis` and device details):

| Metric | Meaning |
|--------|---------|
| `stable_bit_count` / `unstable_bit_count` | cells that always / sometimes toggle |
| `stability_mask` | bitmask of stable cells (helper data) |
| `intra_device_hd` | mean pairwise Hamming distance between captures (fraction) |
| `bit_error_rate` | mean fraction of bits differing from the reference |
| `reliability` | `1 − bit_error_rate` |
| `uniqueness` | mean pairwise inter-device Hamming distance across the fleet |

**What is *never* stored:** raw startup responses or any plaintext PUF
credential. The HMAC credential tag's key is server-side, so a database
leak alone never exposes the credential tag itself. **Simulation caveat:**
the PUF response is reproducible from the stored `puf_seed`, so the PUF
factor is not a secret against a full database dump — protect the seed;
on real hardware the response is never stored.

## Fuzzy Extraction

Real PUF responses are noisy — a handful of metastable cells flip between power
cycles. A **fuzzy extractor** converts the noisy-but-reproducible response into
an *exact, repeatable* secret (`app/fuzzy/`).

**Error correction (`app/fuzzy/codes.py`).** A real algebraic **BCH** codec:
syndrome computation, **Berlekamp–Massey** for error-locator polynomials, and
**Chien search** for roots. Presets:

- `BCH(15, 7, 5)` — corrects up to **t = 2** bit errors per block,
- `BCH(31, 16, 7)` — corrects up to **t = 3** bit errors per block.

The code is selected automatically for the device's PUF size.

**Code-offset fuzzy commitment (`app/fuzzy/fuzzy.py`).**

```
enroll:      helper = codeword(secret) XOR response        (block by block)
reconstruct: codeword ≈ helper XOR (fresh noisy response) → decode → secret
```

Reconstruction succeeds only if every block differs from the enrolled response
within the code's error tolerance `t`. Excess noise — or a *foreign* PUF — does
not decode, and the whole check fails.

**Key derivation (`app/fuzzy/kdf.py`).** The recovered secret is stretched and
domain-separated with **HKDF-SHA256** (salt = device id, info = application
prefix + label) into independent keys:

```
device-auth        → challenge-response authentication
firmware-encryption → (reserved) encrypted firmware payloads
boot-integrity      → (reserved) boot state integrity
puf-binding         → the PUF-to-key binding hash
```

Hashing is **never** used to correct errors — it only derives keys from the
already-corrected secret.

## PKI Architecture

A filesystem-backed trust chain (`app/pki/`):

- **Root CA** — self-signed, 10-year validity, CA basic constraint and
  `key_cert_sign` key usage; created once and reused.
- **Intermediate CAs** — optional subordinate CAs signed by the root.
- **Device certificates** — one leaf per provisioned device (2-year validity),
  signed by the root (or an intermediate), binding the device's EC public key
  to its identity.
- **Validation** — signature checks, issuer/subject matching, expiry /
  not-yet-valid detection, CA basic constraints, key-usage enforcement, and
  full chain-of-trust verification with RFC 5280 path-length limits
  (`verify_chain`).
- **Key security** — CA and device private keys are stored with restrictive
  file permissions and are **never exposed** through the REST API or the
  frontend; only the public key is served (`GET /api/manufacturer/key`,
  certificate info endpoints).
- **Key store** — `app/pki/key_store.py` organises keys and certificates by
  scope (`device/<id>`, `root`, intermediates); removing a device removes its
  key/cert files.

## Device Authentication

Devices prove possession of their private key with a **fresh one-time
challenge** (`app/auth/`):

1. `POST /api/auth/challenge` — issues a random 256-bit nonce generated with
   Python's `secrets` module, stored in `auth_challenges` with a 60-second
   TTL.
2. The device signs the canonical message
   `"pufshield-auth:v1:" + device_id + ":" + challenge` with its private key
   (ECDSA-SHA256) and returns the signature. Binding `device_id` into the
   message prevents cross-device answer attacks.
3. `POST /api/auth/authenticate` succeeds **only if all** of the following
   hold:
   - the challenge exists, belongs to the device, is unexpired, and **has not
     been used** — challenges are consumed *atomically* before the signature
     is verified, so **replays and even failed attempts are rejected**,
   - the device certificate chains to the root CA,
   - the ECDSA-SHA256 signature verifies against the registered certificate
     public key,
   - the **PUF-to-key binding** is reproduced — the PUF re-read must recover
     the secret that recomputes the binding for that public key, so a
     certificate or private key copied onto different hardware still fails.

Failures return `401` with a machine-readable `X-Auth-Reason` header
(`challenge_invalid` | `signature_invalid` | `puf_mismatch` |
`certificate_invalid`). Every attempt is written to the audit trail.

## Firmware Verification

Firmware images (`app/firmware/image.py`) are JSON envelopes
(magic `PUFB\x01`) containing the base64 payload, its SHA-256 digest, and
**two ECDSA-SHA256 signature layers**:

1. **Device signature** — the device's private key signs the whole unsigned
   body, proving the image came from / is bound to this provisioned device.
2. **Manufacturer manifest signature** — the trusted manufacturer key signs a
   canonical manifest (magic `PUFM\x01`, version, device id, payload SHA-256).
   Because the manifest commits the *payload hash*, any bit flip in the binary
   invalidates the signature even if the attacker re-ships the original bytes.

`POST /api/firmware` builds, signs, and stores an image.
`POST /api/firmware/verify` reports `verified = hash_valid AND
device_signature_valid AND manufacturer_signature_valid AND version_allowed`.

The manufacturer key pair is generated on first use and persisted in the key
store; only the public key is ever served. `POST /api/firmware/sign` can sign a
client-supplied payload without storing it (`store: true` persists it).

## Secure Boot Flow

The complete boot engine (`app/secureboot/verify.py`) runs **11 stages in order**
— 8 mandatory (blocking) and 3 informational — and reports each in the result.
A failure in any blocking stage stops boot (`BOOT_BLOCKED`):

| # | Stage | Type | What is verified | Threat caught |
|---|-------|------|------------------|---------------|
| 1 | `puf_recovery` | Blocking | SRAM PUF re-read + fuzzy error-correction reproduces the enrolled credential | Cloned hardware, wrong PUF |
| 2 | `puf_pki_binding` | Blocking | Recovered secret recomputes the registered PUF-to-key binding | Certificate/key copied onto different hardware |
| 3 | `certificate_verification` | Blocking | Device certificate chains to the root CA (RFC 5280) | Forged / rogue certificates |
| 4 | `challenge_response` | Blocking | One-time nonce signed by the device's private key (consumed atomically) | Replay, stolen-key possession proof |
| 5 | `firmware_hash` | Blocking | Loaded payload reproduces the registered SHA-256 digest | Tampered binary |
| 6 | `firmware_signature` | Blocking | Device signature vs certified key **and** manifest vs manufacturer key | Wrong / unauthorized signer |
| 7 | `anti_rollback` | Blocking | Image version satisfies the device minimum version | Downgrade to old firmware |
| 8 | `pqc_readiness` | Informational | Post-quantum cryptography key registration status | Future PQC preparedness |
| 9 | `transparency_log` | Informational | Merkle tree inclusion proof for boot record | Audit trail integrity |
| 10 | `anomaly_detection` | Informational | Z-score + EWMA composite anomaly scoring | Behavioral anomalies |
| 11 | `risk_assessment` | Informational | 7-layer weighted risk score against thresholds | Cumulative risk |

Each boot returns:

```
decision   → "BOOT_ALLOWED" | "BOOT_BLOCKED"
status     → success | puf_mismatch | certificate_invalid | auth_failed |
             hash_invalid | signature_invalid | image_mismatch | rollback_rejected
stages     → per-stage {passed, blocking, details}
checks     → flat aggregate (stage → passed + detail fields)
message    → human-readable reason
```

Every decision is written to the boot audit log and the unified security-event
feed. The certificate is loaded up front because its public key is needed by
the binding and challenge stages; whether it *chains* is decided by its own
stage.

## Anti-Rollback

Each device stores a **minimum allowed firmware version** (empty = unrestricted,
set via `PUT /api/devices/{device_id}/minimum-version`). The rollback check
runs as the **last** stage, after the signature checks, so it only ever
evaluates a version authenticated by a valid manufacturer signature:

1. **Secure version comparison** (`app/firmware/version.py`) — versions are
   strict dotted sequences of non-negative integers (no whitespace, empty
   components, or leading zeros), compared numerically with missing trailing
   components treated as zero (`"1.10.0" > "1.9.0"` — string ordering would
   wrongly reject the newer build). Malformed versions are never compared;
   they **fail closed**.
2. **Correctly signed rollback is still rejected** — an older image whose
   device and manufacturer signatures are fully valid is rejected with status
   `rollback_rejected` as soon as its version is below the device minimum.
3. **Honest reporting** — with no policy set, an old image boots
   (`BOOT_ALLOWED`); the engine never hardcodes a "blocked" outcome.
4. **Logging** — every rejection/success records image version, minimum, and
   `version_allowed` in the audit log and `/api/firmware/verify`.

## Advanced Security Features

Beyond the core boot pipeline, PUFShield includes several advanced security
mechanisms (currently informational / demo-grade):

- **Post-Quantum Cryptography** (`app/pqcrypto/mldsa.py`) — ML-DSA-65
  (FIPS 204) key generation for future-proofing against quantum attacks.
  Key generation works; full sign/verify integration is deferred.
- **Zero-Knowledge Proof** (`app/zkp/schnorr.py`) — Schnorr ZKP with both
  interactive and Fiat-Shamir (non-interactive) modes. Demonstrates that a
  device can prove knowledge of a secret without revealing it.
- **Anomaly Detection** (`app/ai/anomaly.py`) — Z-score + EWMA composite
  scoring on boot timing, authentication patterns, and device behavior.
- **Risk Engine** (`app/risk/engine.py`) — 7-layer weighted scoring that
  aggregates device age, firmware freshness, authentication history, anomaly
  signals, boot success rate, environment, and update compliance into a single
  risk score with LOW/MEDIUM/HIGH/CRITICAL classification.
- **Merkle Transparency Log** (`app/transparency/merkle.py`) — append-only
  Merkle tree recording boot decisions with inclusion proofs for auditability.
- **Environmental PUF Simulation** (`app/ai/environment.py`) — Arrhenius model
  simulating temperature/voltage effects on SRAM PUF stability.
- **PUF Digital Twin** (`app/frontend/static/js/app.js`) — interactive 16x16
  SRAM cell grid visualization showing real-time PUF state.

## Threat Model

**Trust assumptions**

- The backend, its root CA, and the manufacturer signing key are trusted.
- The attacker controls a field device and can read, copy, and modify its
  external flash/storage.
- The attacker does **not** possess the physical silicon of the genuine device
  (in the simulation, this maps to not possessing the true device seed/PUF).
- (Simulation caveat) the PUF model is assumed to behave like a real SRAM PUF;
  this is a design assumption, not a demonstrated hardware property.

**Assets protected**

| Asset | Protected by |
|-------|--------------|
| Device identity | PUF-derived secret + per-device certificate + PUF-to-key binding |
| Firmware authenticity & integrity | SHA-256 registration + device + manufacturer signatures |
| Boot state | Seven-stage pipeline, any failure blocks boot |
| Authentication sessions | One-time challenges, atomic consumption, replay rejection |
| Rollback resistance | Per-device minimum firmware version |

**Out of scope (not claimed)**

- Side-channel attacks (power, EM, timing) on real silicon.
- Invasive/physical attacks on real SRAM.
- Server compromise, DB exfiltration combined with the server secret file.
- Transport security in the demo (no TLS on the local FastAPI server).
- Certificate revocation during runtime (see [Limitations](#limitations)).

## Attack Scenarios

The **Attack Center** (`app/attacks/`) runs **real simulations**: every attack
mutates the *actual* data the boot engine verifies and is then evaluated by the
genuine `verify_boot` pipeline. The recorded outcome is never hardcoded — the
detection point, result, and reason are read from the pipeline's `BootResult`,
and every run is persisted to `attack_logs`.

| Attack | What the attacker does | Detection point | Status |
|--------|------------------------|-----------------|--------|
| `clone_device` | A different SRAM PUF claims the same device identity (certificate copied over) | `puf_recovery` | `puf_mismatch` |
| `tamper_firmware` | Payload bytes modified after signing | `firmware_hash` (SHA-256 mismatch) | `hash_invalid` |
| `replay_challenge` | A captured genuine signed challenge is replayed after the nonce was consumed | `challenge_response` | `auth_failed` |
| `certificate_forgery` | Device key re-issued under a rogue CA and swapped in | `certificate_verification` | `certificate_invalid` |
| `firmware_rollback` | An older but legitimately-signed image booted against the minimum-version policy | `anti_rollback` | `rollback_rejected` |
| `wrong_signer` | Firmware signed by an unauthorized key | `firmware_signature` | `signature_invalid` |

Every blocked attack writes a full record (attack, target, detection point,
result, reason, timestamp) plus a `critical` security event; the dashboard
aggregates the blocking rate.

## Database Design

SQLite persistence (`app/database/db.py`) with the following tables:

| Table | Contents |
|-------|----------|
| `devices` | Provisioned devices: identity, simulated SRAM seed, anti-rollback minimum version |
| `puf_enrollments` | Stability mask, stable-only reference, metrics, HMAC credential tag, fuzzy helper data, PUF-to-key binding — **raw responses are never stored** |
| `certificates` | Device X.509 certificates (subject, issuer, serial, PEM), persisted at provisioning and refreshed on read |
| `firmware_images` | Signed firmware bundles available for boot |
| `boot_logs` | Audit trail of every secure boot attempt (status, message, per-stage checks) |
| `authentication_events` | Audit trail of every challenge-response attempt (success, reason, checks) |
| `auth_challenges` | One-time nonces (issued, consumed, expired) |
| `attack_logs` | Every simulated attack (type, target, detection point, result, reason, timestamp) |
| `security_events` | **Unified, timestamped feed**: every boot, auth, and attack attempt writes exactly one row with a `severity` |

**Security design**

- The credential is an **HMAC tag keyed by a server-side secret** stored in
  `data/puf_secret.bin` (override with `PUF_CREDENTIAL_SECRET_PATH`) — a
  database leak alone never exposes the credential tag. (Simulation caveat:
  the stored `puf_seed` reproduces the PUF response, so protect the seed;
  on real hardware the response is never stored.)
- The database path is configurable (`DATABASE_PATH`); tests run against an
  isolated temporary database.
- `DELETE /api/devices/{device_id}` cascades operational state (enrollment,
  certificate, firmware, challenges) so a device can be re-provisioned, while
  **audit logs are preserved** for forensics.
- A device's `puf_seed` is stored because the PUF is *simulated* and must be
  reproducible across restarts; a real implementation never stores the
  fingerprint — it lives in the silicon.

## API Documentation

Interactive docs are available at `http://127.0.0.1:8000/docs` (OpenAPI).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Service health check |
| POST | `/api/devices` | Register a device (PUF enrollment + certificate) — `201`; `409` if it exists |
| GET | `/api/devices` | List registered devices (with enrollment stats) |
| GET | `/api/devices/{device_id}` | Device details incl. enrollment metadata |
| DELETE | `/api/devices/{device_id}` | Remove a device so it can be re-provisioned (audit logs kept) |
| GET | `/api/devices/{device_id}/certificate` | Device certificate + RFC 5280 chain verification |
| GET | `/api/devices/{device_id}/minimum-version` | Device anti-rollback floor |
| PUT | `/api/devices/{device_id}/minimum-version` | Set anti-rollback floor (malformed versions → `400`) |
| POST | `/api/puf/test` | Re-read a PUF and verify its enrollment + binding |
| GET | `/api/puf/analysis` | Fleet-wide PUF statistics (reliability, BER, uniqueness, per-device mask/reference) |
| POST | `/api/firmware` | Create signed firmware for a device — `201` |
| GET | `/api/firmware` | List firmware images (optionally by `device_id`) |
| POST | `/api/firmware/sign` | Sign firmware without storing (or persist with `store: true`) |
| POST | `/api/firmware/verify` | Verify hash + device + manufacturer signatures + version policy |
| GET | `/api/manufacturer/key` | Trusted manufacturer public key (private key is never exposed) |
| POST | `/api/boot` | Simulate a secure boot (optional `challenge_b64`/`signature_b64`) |
| GET | `/api/boot/logs` | Boot audit log |
| POST | `/api/auth/challenge` | Issue a one-time challenge for a device |
| POST | `/api/auth/authenticate` | Authenticate by signed challenge — `200`; `401` + `X-Auth-Reason` on failure |
| GET | `/api/auth/logs` | Authentication audit log (success, reason, checks) |
| GET | `/api/attacks` | List attack scenarios |
| POST | `/api/attacks/{attack_name}` | Run an attack simulation (`400` for unknown attacks) |
| GET | `/api/attacks/logs` | Attack audit log |
| GET | `/api/security/events` | Unified security event feed (filter by `event_type`/`device_id`) |
| GET | `/api/dashboard/stats` | Dashboard statistics (devices, firmware, boots, auth, attacks, events, PUF) |

## Web Dashboard

The project includes a full web interface served by the FastAPI backend:

- **Public pages** (`/`, `/about`, `/features`, `/how-it-works`, `/architecture`,
  `/demo`) — white/blue/green themed marketing site describing the project
- **Login** (`/login`) and **Register** (`/register`) — demo authentication
  (credentials: `admin` / `pufshield`)
- **Dashboard** (`/dashboard`) — protected security console with:
  - Device management with PUF enrollment
  - Certificate management with chain view
  - Secure boot monitor with stage-by-stage results
  - Attack center for security testing
  - Real-time security event logging
  - PUF digital twin (16x16 SRAM cell grid)
- **Architecture diagrams** (`docs/`) — 4 interactive HTML diagrams for
  presentation:
  - Full system architecture (10-layer)
  - 11-stage boot pipeline timeline
  - Enrollment + authentication flow
  - 6 attack class detection matrix

## Installation

**Requirements**

- Python 3.13
- FastAPI, uvicorn, cryptography, pydantic(-settings), pytest, httpx
  (see `requirements.txt`)

**Setup**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env   # then edit if needed
```

Configuration lives in `.env` (see `app/config.py`). The SQLite database and
key store are created automatically on first run.

Key settings:

| Setting | Default | Purpose |
|---------|---------|---------|
| `DATABASE_PATH` | `data/pufshield.db` | SQLite database location |
| `PUF_CREDENTIAL_SECRET_PATH` | `data/puf_secret.bin` | Server-side secret keying PUF credential tags |
| `APP_HOST` / `APP_PORT` | `127.0.0.1` / `8000` | Server binding |
| `APP_DEBUG` | `true` | FastAPI debug mode |

## Running Instructions

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- **Dashboard:** http://127.0.0.1:8000 — device management, SRAM PUF
  visualization, firmware, boots, Attack Center, authentication, and the
  unified event feed.
- **API docs:** http://127.0.0.1:8000/docs

**Typical flow**

1. `POST /api/devices` → provision a device (PUF enrollment + certificate).
2. `POST /api/firmware` → create and sign firmware for it.
3. `POST /api/boot` → run a secure boot (should be `BOOT_ALLOWED`).
4. `POST /api/attacks/{attack_name}` → run attacks (each should be
   `BOOT_BLOCKED` at its detection point).
5. `POST /api/auth/challenge` + `POST /api/auth/authenticate` → authenticate;
   replaying the same nonce returns `401`.

**Tests**

```powershell
pytest -q
```

Tests run against an isolated temporary database and key store (see
`tests/conftest.py`).

## Testing Results

Run with `pytest -q`:

```
336 passed, 1 skipped  (337 collected)
```

The suite includes an RFC 5869 HKDF test vector (`test_fuzzy.py`), a
mixed-size fleet regression test, a dedicated 11-test security suite
(`test_security_suite.py`), and a thread-safety test that exercises the
shared SQLite connection from a worker thread. There are **24 test files**
covering all subsystems including PQC, ZKP, anomaly detection, risk engine,
Merkle tree, and environmental PUF.

| Area | Files | Coverage |
|------|-------|----------|
| Unit — PUF | `test_puf.py` | PUF generation, uniqueness, noise simulation |
| Unit — Enrollment | `test_enrollment.py` | Enrollment process, metrics, credential derivation |
| Unit — Fuzzy extraction & KDF | `test_fuzzy.py` | BCH encode/decode, noise tolerance, key derivation, binding |
| Unit — PUF binding | `test_binding.py` | Reproducibility, foreign-key rejection, clone detection |
| Unit — PKI | `test_pki.py` | Chain verification, forgery, expiry, key usage |
| Unit — Firmware & rollback | `test_firmware.py`, `test_rollback.py` | Dual signatures, version parsing, anti-rollback policy |
| Unit — Auth | `test_auth.py` | Challenge lifecycle, replay rejection, binding |
| Unit — Crypto | `test_crypto.py` | Cryptographic primitives |
| Unit — PQC | — | ML-DSA-65 key generation |
| Unit — ZKP | `test_zkp.py` | Schnorr proof generation and verification |
| Unit — Anomaly | `test_anomaly.py` | Z-score + EWMA composite scoring |
| Unit — Risk engine | `test_risk_engine.py` | 7-layer weighted risk scoring |
| Unit — Merkle | `test_merkle.py` | Merkle tree operations and proofs |
| Unit — Environmental | `test_environment.py` | Arrhenius environmental PUF simulation |
| Integration — boot engine | `test_boot_engine.py` | all 11 stages, per-stage checks, decisions |
| Integration — secure boot | `test_secureboot.py` | End-to-end secure boot flow |
| Integration — API | `test_api.py`, `test_api_endpoints.py`, `test_new_endpoints.py` | Every REST endpoint, status codes, error paths |
| Persistence | `test_database_persistence.py` | Cascade deletes, audit retention, re-provision |
| Security suite | `test_security_suite.py` | The eight threat scenarios below |
| Attack Center | `test_attack_center.py` | Real simulations + detection points + records |

**Security scenario results** (`tests/test_security_suite.py`)

| # | Scenario | Result | Detection point |
|---|----------|--------|-----------------|
| 1 | Genuine device + genuine firmware | **BOOT ALLOWED** | — (all 7 stages pass) |
| 2 | Genuine device + tampered firmware | **BLOCKED** | `firmware_hash` |
| 3 | Clone device + copied certificate | **BLOCKED** | `puf_recovery` |
| 4 | Replay authentication | **BLOCKED** | `challenge_response` (+ API `401`) |
| 5 | Fake certificate | **BLOCKED** | `certificate_verification` |
| 6 | Signed old firmware | **BLOCKED** | `anti_rollback` |
| 7 | Wrong device PUF | **BLOCKED** | `puf_recovery` |
| 8 | Invalid firmware signature | **BLOCKED** | `firmware_signature` |

## Limitations

- **Simulated PUF, not hardware.** The PUF is a deterministic software model.
  It does not provide physical entropy, tamper response, or silicon-level
  unclonability, and the `puf_seed` must be stored in the database to
  reconstruct it across restarts (a real device would never store it). This is
  the central proof-of-concept caveat.
- **No transport security in the demo.** The demo server binds to localhost
  without TLS; in production, device traffic would use TLS/DTLS with the
  challenge-response handshake over the wire.
- **No certificate revocation.** Chain-of-trust verification is implemented,
  but certificate revocation lists and runtime revocation are deferred.
- **On-device policy enforcement is not implemented.** The anti-rollback
  minimum version lives in the backend database; a real deployment requires an
  on-device trusted anchor (e.g. fuse-committed monotonic counter) that the
  bootloader itself enforces.
- **No secure update protocol.** Firmware is signed and verified, but there is
  no over-the-air update handshake, rollback-recovery mechanism, or code
  signing PKI for the update channel.
- **Single-user demo auth.** The web dashboard uses a simple in-memory session
  store with a hardcoded demo user (`admin`/`pufshield`). This is for
  hackathon demonstration only; production would use proper user management.
- **Side-channel / physical attacks not modelled.** No power, EM, timing, or
  fault-injection models are included.
- **No persistent device-side key storage model.** In the simulation the
  "device" is a service-side object; real device-side secure storage (or a
  secure element) is future work.

## Future Hardware Implementation

Path from this proof-of-concept to a physical system:

1. **Real SRAM PUF driver** — on an MCU with internal SRAM, read the startup
   content immediately after power-on (before any data is written), evaluate
   cell stability across a burn-in of power cycles, and select the stable
   cells. This replaces `app/puf/sram_puf.py`.
2. **On-chip helper data** — store the stability mask, reference, and fuzzy
   helper data in on-chip protected flash; never store the PUF secret. The BCH
   codec (`app/fuzzy/`) ports directly to the device to error-correct the
   fresh response at boot.
3. **Device-side key derivation** — run the HKDF derivation
   (`app/fuzzy/kdf.py`) inside the bootloader/secure enclave so the derived
   keys never appear in plaintext in the application.
4. **Trusted boot anchor** — commit the root CA public key to the chip
   (OTP fuses / secure element) and enforce certificate chain verification and
   the anti-rollback minimum version in the bootloader itself, backed by a
   hardware monotonic counter.
5. **Secure transport** — carry the existing challenge-response protocol over
   TLS/DTLS so authentication happens over the network without exposing
   signatures to capture-and-replay.
6. **Deployment hardening** — CRL/OCSP revocation, secure OTA update protocol
   with the existing dual-signature scheme, encrypted firmware payloads using
   the reserved `firmware-encryption` key, and hardware acceleration for ECDSA.
7. **Evaluation** — entropy assessment (NIST SP 800-90B style), temperature /
   voltage reliability trials, and attack evaluation (modelling, side channels,
   fault injection) on the real silicon.

The PUF-to-key binding, fuzzy extraction, PKI, firmware verification, and boot
stages are already production-real; the embedded work is confined to the
hardware interface and on-device enforcement.
