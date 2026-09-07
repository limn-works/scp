---
name: surfaces-pr127-ucan-bridges
description: PR #127 second-pass attack surfaces — UCAN validation gaps across bridges, context_close auth bypass, zero-signature token minting, nonce replay, cover traffic distinguishability — plus what that pass confirmed sound
metadata:
  type: project
---

# PR #127 second pass (post-fix)

Caveat: some paths named here predate later refactors. The WASM bridge under
`crates/scp-ffi/wasm/` was cut; see [[constraint_wasm_cut]] before acting on a
WASM row. Verify each path before recommending from this file.

- **CRITICAL — WASM bridge UCAN validation missing 6 of 11 steps.** `crates/scp-ffi/wasm/src/ucan.rs`. Ed25519 verification was added; steps 3-5 and 7-9 stayed absent. Self-signed DIDs pass, because an attacker encodes an own public key in a DID and signs with an own key. No root issuer check, no audience check, no delegation chain, no nonce tracking.
- **HIGH — `context_close` authorization bypass on napi-rs, WASM, UniFFI.** PyO3 checks a `ContextClose` capability; the others discard an identity argument: `crates/scp-ffi/napi/src/context.rs:430`, `crates/scp-ffi/wasm/src/context.rs:579`, `crates/scp-ffi/uniffi/src/bridge.rs:1704`.
- **HIGH — broadcast UCAN validation skips every cryptographic check.** `crates/scp-core/src/context/broadcast.rs:423-442`. Wildcard rejection landed (RED-012); signature, expiry, issuer, and chain checks did not. A forged `UcanToken` struct carrying a correct `aud` plus `att` string passes.
- **HIGH — napi-rs and UniFFI mint zero-signature tokens with no unsigned indicator.** `crates/scp-ffi/napi/src/ucan.rs:432` and `crates/scp-ffi/uniffi/src/bridge.rs:2181` both write `[0u8; 64]`. No `is_signed` field, so a token looks production-ready.
- **MEDIUM — nonce replay TOCTOU, substantially improved.** `crates/scp-core/src/store/ucan.rs:236-267`. Post-write re-verification added; an in-memory path is serialized by DashMap entry locks. Residual risk sits in a crash-recovery window.
- **MEDIUM — cover traffic size and timing are distinguishable.** `crates/scp-transport/src/cover_traffic.rs`. A fixed 30-second interval plus a fixed 1024-byte size makes a recognizable pattern.
- **MEDIUM — attestation renewal re-verifies internal fields only.** `crates/scp-core/src/trust/renewal.rs:93-125`. A `verify_attestation` call was added; external evidence is not re-fetched.

# Confirmed sound in that pass

Broadcast key isolation per author (AES-256-GCM, random nonces); epoch overflow
protection at `u64::MAX`; key-material `Debug` redaction across every bridge;
scp-core's 11-step UCAN pipeline where it is actually invoked (napi-rs, UniFFI,
PyO3); napi-rs TLS enforcement rejecting `ws://`; nonce replay serialization on
an in-memory path; heartbeat suppression detection; broadcast wildcard rejection
(RED-012); PyO3 `context_close` authorization; Merkle checkpoint equivocation
detection.
