---
name: adr057-pseudonym-derivation-scp-crypto
description: ADR-057 Option A — move §9.10.4.A pseudonym DERIVATION from scp-platform to wasm-safe scp-crypto; CLEAN byte-preserving review
metadata:
  type: project
---

# ADR-057 Option A pseudonym-derivation extract (branch refactor/adr057-pseudonym-derivation-scp-crypto, 3 commits, HEAD 64bf5d306)

**CLEAN — 0 defects. Byte-preserving move, verified by compile+test on native+wasm32.**

- `pseudonym.rs` git-renamed scp-platform→scp-crypto (similarity 89%). Only changes are doc-comment additions + `#[must_use]` on `derive_pseudonym_secret` (behavior-neutral lint). Algorithm body (HKDF salt `scp-pseudonym-secret-v1`, v1 domain `scp-pseudonym`, v2 domain `scp-pseudonym-v2`, HMAC-SHA256 keying, epoch BE64, Ed25519 from_bytes seed) UNCHANGED — not in diff hunks.
- Delegation sites (file.rs, sqlite/key_custody.rs, testing/key_custody.rs, traits.rs doc) are pure path swaps `crate::pseudonym::` → `scp_crypto::pseudonym::`, IDENTICAL args (signing_key, &context_id, None / Some(epoch)).
- Deps: `hkdf` removed from scp-platform (0 remaining refs, confirmed grep). `hmac`+`sha2` KEPT — used only by testing/key_custody.rs `mod tests` cross-check (`derive_pseudonym_cross_platform_golden_vector`, passes). scp-crypto adds hkdf/hmac/sha2/zeroize non-optional; wasm-safe (builds wasm32-unknown-unknown).
- Cross-target KAT `crates/scp-client-wasm/tests/pseudonym_derivation_cross_target_kat.rs` is REAL (not vacuous): calls real `derive_pseudonym_secret`/`derive_pseudonym_keypair`, asserts secret+v1_pub+v2_pub against §25.19 Vectors 30/31 golden bytes on both `#[test]` (native) and `#[wasm_bindgen_test]`. scp-crypto added as dev-dependency of scp-client-wasm. Native run passes.
- Cross-SDK (Python/TS/Swift/Kotlin recipe files + kotlin lesson + §25.19 spec) changes are ONLY file-location reference edits in comments/docstrings — no algorithm/recipe change. Spec §25.19 additionally cites the new cross-target KAT.
- No missed consumer: old module was `pub(crate)`; grep for `scp_platform::pseudonym`/`platform::pseudonym` across crates/+bindings/ = 0; old file deleted; no `pub use scp_crypto` shim.

ENV: used CARGO_TARGET_DIR=iso to avoid shared-target contention.
