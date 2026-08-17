---
name: surfaces-pr76-spec22
description: Attack surfaces found in PR #76 (shadow claiming, PyO3 skeleton, spending UCAN, standing TOCTOU) and in spec 22, human-readable addressing (trust-level gaming, namespace hijack, squatting, petname deception)
metadata:
  type: project
---

# PR #76 attack surfaces

- **CRITICAL — `claim_shadow()` does not verify signatures.** `crates/scp-core/src/bridge/claiming.rs:206-218`. Function documents that a caller must verify Ed25519 signatures, and enforces nothing. Tests pass with `vec![0u8; 64]`.
- **CRITICAL — PyO3 bridge is a skeleton with no crypto enforcement.** `crates/scp-ffi/src/context.rs`. Join, leave, send, and close are stubs over string-based state.
- **HIGH — spending UCAN 24h max expiry unenforced.** `crates/scp-core/src/crypto/ucan/spending.rs`. `MAX_EXPIRY_SECS` and an error type exist; no validation function reads either.
- **HIGH — standing channel TOCTOU.** `crates/scp-core/src/context/standing.rs:166`. Lock dropped between an existence check and async creation.
- **HIGH — `SenderVelocityTracker` accepts arbitrary timestamps.** `crates/scp-core/src/economy/antispam.rs:153`.
- **HIGH — `SingleAdmin` `TransferAdmin` performs no DID validation.** `crates/scp-core/src/context/governance/mod.rs:503`.
- **HIGH — `TestAdapter` has no production exclusion.** `crates/scp-testing/src/test_adapter.rs`.

# Spec 22 (human-readable addressing) attack surfaces

- **CRITICAL — `MultiLayerCorroborated` trust level is trivially gameable.** `.docs/specs/22-human-readable-addressing.md` §22.7, §22.8.2, §22.10.2. One attacker controlling a domain plus a context plus an attestation reaches a highest trust level, because no independence verification runs between corroborating layers.
- **CRITICAL — context governance capture yields total namespace hijack.** §22.3.4.
- **HIGH — handle squatting carries zero economic cost for bulk registration.** §22.3.1.
- **HIGH — petname auto-creation is permanent after one successful deception.** §22.8.3, §22.8.4.
- **HIGH — every lookup is DID-authenticated, so a resolver learns who asks for whom.** §22.10.4.
- **HIGH — cache poisoning through stale-while-revalidate.** §22.8.4.
