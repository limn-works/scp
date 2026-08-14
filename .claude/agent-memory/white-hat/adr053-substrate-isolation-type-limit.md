---
name: adr053-substrate-isolation-type-limit
description: ADR-053 pre-rotation custody — why substrate isolation cannot be type-enforced across the FFI callback boundary, and the migration-reveal process-memory transit residual
metadata:
  type: project
---

# ADR-053 Pre-Rotation Custody: Substrate Isolation Is Not Type-Enforceable

**Status of ADR: Proposed** (implementation not landed as of HEAD ae3a4238f, 2026-07-15). Consequences/Risk describe the TARGET design, not current code. Current code still routes pre-rotation seed into `scp_platform::testing::InMemoryPreRotationCustody` (UniFFI bridge.rs `generate_ephemeral_ed25519_seed` ~676-712) and fail-closes migration import (`import_ed25519_signing_key` 714-740 returns `PlatformError::Unsupported`). Both carry honest in-code comments.

**Core defensive insight (Round 26, ae3a4238f correction — APPROVED):**
- Spec §9.7.4.1 §3 mandates the pre-rotation key live in a *substrate* separate from operational custody. This is a **substrate property**, not a type property.
- A separate `PreRotationCustodyProvider` FFI trait object enforces only that the *same Rust object* cannot serve both roles. It CANNOT verify two distinct foreign callback objects aren't backed by the same Keychain access group / biometric prompt / secure enclave key. **Type distinctness ≠ substrate distinctness.**
- Correct framing: substrate/auth-flow isolation is a **foreign-implementation obligation**, "structurally encouraged" by the type split, verified by conformance test ("pre-rotation key NOT recoverable from the operational provider") only *where observable*. The test observes the recoverability property, NOT the substrate property. This is the strongest available check, not a proof.
- The prior ADR text "enforced by the type system" was an overclaim; the in-code comment (bridge.rs ~686-692) was already honest ("Type-level isolation satisfied... Substrate isolation NOT satisfied"). Correction aligned ADR to code.

**Migration-reveal transit residual (architecturally inherent):**
- Canonical migration (ADR line 51): `consume(handle) -> Zeroizing<[u8;32]>` then `KeyCustody::import_ed25519_signing_key(seed)`. The `consume`/`import` primitive design forces the 32-byte pre-rotation seed to materialize as raw bytes in shared bridge process memory between the two calls.
- `Zeroizing` narrows the window (wipes after import) but does not eliminate it. Substrate isolation holds AT REST; during migration the seed is transiently observable to a process-memory attacker. This is unavoidable for offline/Shamir/BIP39 backends that inherently hold raw bytes.
- P2 hardening for ADR authors before Proposed→Accepted (non-blocking): (1) Risk section could add explicit implementer obligation — keep consume→import the tightest possible sequence, no intervening IO/logging/persistence, never copy the seed. (2) "necessarily transits" is true for the chosen consume/import primitive; a same-substrate internal-rewrap alternative could avoid transit for HSM-to-HSM but not for byte-holding backends.

**Verdict on the correction: posture moved in the SAFE direction on both counts** (downgraded an overclaim; added a residual-risk disclosure). No new defensive gaps. Disclosure adequately informs (what/where/via-which-step/mitigation/limit/at-rest-vs-migration boundary all present).
