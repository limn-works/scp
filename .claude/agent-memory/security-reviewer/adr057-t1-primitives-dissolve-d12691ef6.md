# ADR-057 T1 — dissolve scp-primitives, extract scp-did (d12691ef6) — 2026-07-02 — ZERO FINDINGS

Behavior-preserving crate-topology refactor. Range 86519aa6f..d12691ef6, branch refactor/dissolve-primitives-split-identity.
- scp-primitives dissolved: crypto.rs→scp-crypto/src/lib.rs, identity.rs→scp-did/src/lib.rs, time.rs→scp-clock.
- DID document/attestation model moved scp-protocol/src/identity/{document,did_attestation}.rs → scp-did/src/{document,attestation}.rs. Rename DidDocumentError→DidError (single mechanical rename). did_attestation→attestation module rename.

VERIFIED CLEAN on all security surfaces:
- verify_ed25519_signature + parse_key_and_signature: diff = +4 header lines ONLY. 32/64-byte try_into, VerifyingKey::from_bytes, verify_strict all intact.
- extract_public_key_from_did (scp-did/src/lib.rs:120): identical. did:key:<hex> STILL gated `#[cfg(any(test, feature = "testing"))]` (line 134). z-base-32 decode + 32-byte enforce + unsupported-format Err all preserved.
- decode_multibase_key: 'z' prefix + base58btc + 32-byte + VerifyingKey::from_bytes curve-point validation preserved.
- serde attrs on MigrationProof/PreRotationProof (array64/array32), serde_proof_bytes, rename/rename_all enums — all verbatim. No deny_unknown_fields added/removed (none at base). Rename-normalized full-body diff shows only doc-comments + import paths + rustfmt reflow.
- Deleted shims (scp-protocol/src/crypto/ed25519.rs, time.rs, scp-primitives/src/lib.rs) were PURE `pub use` re-exports — no wrapped validation lost.

FEATURE-GATE GOTCHA (checked, CLEAN): scp-did/scp-crypto/scp-clock all `default = []`. `testing` feature (enables did:key hex) NOT default. All `scp-did = {features=["testing"]}` are [dev-dependencies] (scp-protocol:57, scp-client:55, scp-mls:55, scp-client-wasm:66) + explicit `testing`-feature forwards — NEVER a normal-dependency activation. Production consumers (scp-node/scp-ffi/scp-runtime/scp-identity/scp-core) depend on scp-did with NO features. Release builds keep did:key-hex rejection. Mirrors base pattern (scp-protocol forwarded scp-primitives/testing identically).
