---
name: adr057-optionA-pseudonym-derivation-scp-crypto
description: ADR-057 Option A — §9.10.4.A pseudonym DERIVATION (HKDF/HMAC/Ed25519-keygen) moved scp-platform→wasm-safe scp-crypto::pseudonym; byte-identical, cross-target KAT SOUND
metadata:
  type: project
---

Branch `refactor/adr057-pseudonym-derivation-scp-crypto`, HEAD 64bf5d306. VERDICT SOUND.

Distinct from the earlier T-1 extraction ([[adr057-pseudonym-extract]]) which moved the §9.10.4 CLASSIFIER into scp-protocol. THIS move is the §9.10.4.A software-custody DERIVATION (HKDF-SHA256 pseudonym_secret → HMAC-SHA256 per-context seed → Ed25519 keygen), out of `scp-platform/src/pseudonym.rs` into wasm-safe `scp-crypto/src/pseudonym.rs`, so the in-browser client derives its pseudonym in Rust over the wasm-held key without forking the native copy.

**Byte-identity proof:** `git diff -M origin/main...HEAD` over the rename, filtered to non-comment lines, yields EXACTLY ONE change: `+#[must_use]` on `derive_pseudonym_secret` (lint attr, no behavior). Everything else = doc additions. So HKDF salt `scp-pseudonym-secret-v1`, HMAC ordering (context_id → BE64(epoch) → domain), domains `scp-pseudonym`/`scp-pseudonym-v2`, `from_bytes(seed[0..32])` RFC-8032-seed interpretation, and Zeroizing all preserved verbatim.

**Cross-target KAT** `crates/scp-client-wasm/tests/pseudonym_derivation_cross_target_kat.rs`: fixed `const` VECTOR_30/31 goldens (== §25.19 spec bytes == scp-crypto unit-test bytes); ONE fn gated `#[cfg_attr(wasm32, wasm_bindgen_test)]`/`#[cfg_attr(not, test)]` runs same asserts both targets ⇒ native==golden ∧ wasm==golden ⇒ native==wasm. scp-crypto is a DEV-dependency of scp-client-wasm (parity edge does not enter prod wasm bundle).

**Zeroize preserved:** pseudonym_secret + context_seed both `Zeroizing<[u8;32]>`; intermediate HMAC output explicit `.zeroize()` (robust to generic-array/zeroize feature absence). scp-crypto gains only hkdf/hmac/sha2/zeroize (pure RustCrypto, no tokio) → stays wasm-safe fence-intact. No forked copy: platform pseudonym.rs GONE, mod decl removed, all 6 callers route to scp_crypto::pseudonym.

**Spec §25.19** golden hex UNCHANGED — only enforcing-test location pointer updated (scp-platform→scp-crypto) + cross-target KAT mention. Vectors 30/31. No blocker, no findings.
