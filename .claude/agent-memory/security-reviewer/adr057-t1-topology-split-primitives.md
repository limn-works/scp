# ADR-057 T1 — dissolve scp-primitives / extract scp-did (2026-07-02) — ZERO FINDINGS

Branch refactor/dissolve-primitives-split-identity, range 86519aa6f..8d6819674 (3 commits).
Behavior-preserving crate-topology refactor. Reviewed 6 security-relevant moved surfaces vs origin:

- (a) scp-crypto/src/lib.rs verify_ed25519_signature + parse_key_and_signature = BYTE-IDENTICAL to
  old scp-primitives/src/crypto.rs (only crate header `#![forbid(unsafe_code)]`+docs added). verify_strict
  strictness preserved; 32/64-byte length checks preserved.
- (b) scp-did extract_public_key_from_did BODY byte-identical (z-base-32 decode, 32-byte enforcement,
  did:key:hex still `#[cfg(any(test, feature="testing"))]`-gated). CRITICAL CHECK PASSED: scp-did/testing
  reachable ONLY via non-default `testing` features (scp-protocol/scp-event-log/scp-mls/scp-client/
  scp-client-wasm all default=[]) or dev-dependencies; the 4 direct `features=["testing"]` scp-did edges
  are ALL [dev-dependencies]. No production/default edge. scp-platform (which carries testing in prod edges,
  pre-existing) does NOT depend on scp-did so can't cascade. Browser build scp-client-wasm prod edge has no
  features → did:key rejected in release.
- (c) scp-did document.rs + attestation.rs = pure rename DidDocumentError→DidError + module-path repoints +
  doc-text. NO serde attribute drift, NO validation logic change. decode_multibase_key 'z'-prefix+base58btc
  +32-byte, relay-URL validation, agent-key uniqueness all verbatim. scp-identity From<DidError> maps all
  7 variants identically.
- (d) scp-event-log old crypto.rs was a PURE re-export shim (pub use scp_primitives::crypto::verify_...).
  tree.rs now calls byte-identical scp_crypto::verify_ed25519_signature + scp_did::extract_public_key_from_did.
  No validation wrapper lost.
- (e) scp-clock/src/lib.rs = byte-identical to old scp-primitives/src/time.rs (header only). cache.rs dropped
  the `pub use ...Clock` re-export → now private `use scp_clock::{Clock,SystemClock}`. All consumers
  (scp-node, templates/personal-relay, scp-ffi/common+napi) repoint to scp_clock::SystemClock — identical type.
- (f) New crates minimal deps: scp-crypto=ed25519-dalek only; scp-clock=none; scp-did adds no NEW external
  crate (all moved from scp-primitives). fuzz/Cargo.toml: scp-primitives→scp-clock+scp-did+scp-mls (scp-mls
  new direct fuzz dep b/c ScpCredential moved scp-runtime→scp-mls). fuzz non-production. release.yml: new
  leaf crates published in dep order, same CRATES_IO_TOKEN secret, no hardcoded secret.

scp-primitives crate DELETED; zero stale scp_primitives/DidDocumentError refs in any source/manifest.
scp-protocol/src/identity/attestation.rs remaining = distinct trust-attestation file (0 ScpKeyCustody refs),
not a duplicate of the moved DID custody attestation.
