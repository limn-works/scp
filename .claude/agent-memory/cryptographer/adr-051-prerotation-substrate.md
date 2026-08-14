---
name: adr-051-prerotation-substrate
description: ADR-051 pre-rotation custody substrate isolation — separate PreRotationCustodyProvider; sound per spec §9.7.4.1
metadata:
  type: project
---

`.docs/adrs/ADR-051-pre-rotation-custody-substrate-isolation.md` (Proposed, 2026-06-14).

**Gap:** callback-custody path (mobile App-Attest/Keychain/Keystore) mints the pre-rotation key into `InMemoryPreRotationCustody` — same process memory as operational key handles. Violates spec §9.7.4.1 §3 (storage isolation: pre-rotation key MUST NOT be accessible via same custody provider/auth flow as daily ops). Also blocks migration reveal (`KeyCustodyProvider` has no import-seed method → UniFFI `import_ed25519_signing_key` fail-closes).

**Decision soundness (cryptographer view): SOUND.**
- Separate `PreRotationCustodyProvider` (not new methods on `KeyCustodyProvider`) is the correct mechanism — enforces §3 substrate split STRUCTURALLY at the type/trait boundary, not by documentation. Combining would re-introduce the coupling §3 forbids.
- `generate()`-inside-substrate (not bridge-side OsRng marshalled out) is correct for HSM/Secure-Enclave (§9.7.4.1 §1 on-device CSPRNG; key never leaves substrate). Bridge-side OsRng acceptable ONLY for software/offline backends that inherently hold raw bytes.
- `import_seed_bytes(Zeroizing<[u8;32]>)` as reveal-time inverse of `consume` is the right model for ADR-003 §4b migration (revealed pre-rotation bytes become new operational #0).
- Zeroizing on all seed bytes at FFI boundary; conformance test that created identity's pre-rotation key is NOT recoverable from operational provider — both correct mitigations.

**Open Qs flagged in ADR (legit, for reviewers):** WASM scope (WebAuthn/passkey-PRF), v1 mandatory backend floor, whether §9.7.4.1 needs explicit callback-custody sub-clause (spec change must land before code per artifact flow).

This is a design ADR only — no code in this diff. Implementation is a future workstream.
