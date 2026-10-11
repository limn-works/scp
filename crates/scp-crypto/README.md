# scp-crypto

The low-level **cryptographic anchor** for SCP (Shared Context Protocol):
strict Ed25519 signature verification (`verify_ed25519_signature`), the P-256
primitives (§9.5), the software-custody pseudonym derivation (§9.10.4), the
typed custody failure, and the curve-neutral `ScpSigner` trait.

This is a wasm-safe capability leaf. It depends on no other SCP crate, and its
external dependencies are `RustCrypto` and `ed25519-dalek` crates that compile to
`wasm32-unknown-unknown` for the in-browser SCP client (ADR-057). Ed25519
verification paths across the workspace delegate to `verify_ed25519_signature`
rather than re-inlining `VerifyingKey::from_bytes` + `Signature::from_bytes` +
`verify_strict`.

Verification uses `verify_strict` (cofactorless, rejects small-order points) —
the strongest mode ed25519-dalek provides.

Part of the `scp-clock` / `scp-crypto` / `scp-did` split that dissolved the old
`scp-primitives` junk-drawer crate (ADR-057 Amendment, 2026-06-30).
