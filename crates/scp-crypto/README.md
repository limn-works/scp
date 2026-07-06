# scp-crypto

The low-level **cryptographic anchor** for SCP (Shared Context Protocol):
centralized, strict Ed25519 signature verification via
`verify_ed25519_signature`.

This is a wasm-safe capability leaf — its only dependency beyond `std` is
`ed25519-dalek`, and it depends on no other SCP crate — so it compiles to
`wasm32-unknown-unknown` for the in-browser SCP client (ADR-057). Module-specific
verification paths across the workspace delegate here rather than re-inlining
`VerifyingKey::from_bytes` + `Signature::from_bytes` + `verify_strict`, so there
is a single verification entry point and no silent drift.

Verification uses `verify_strict` (cofactorless, rejects small-order points) —
the strongest mode ed25519-dalek provides.

Part of the `scp-clock` / `scp-crypto` / `scp-did` split that dissolved the old
`scp-primitives` junk-drawer crate (ADR-057 Amendment, 2026-06-30).
