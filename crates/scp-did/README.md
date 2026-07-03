# scp-did

The **DID data model** for SCP (Shared Context Protocol) — the single wasm-safe
home for identity value types.

This crate owns:

- `DID` — the newtype over a `did:dht:...` string, with `Deref`/`Borrow`/serde.
- `SigningKeyId` — the `#active` / `#agent` verification-method selector.
- `extract_public_key_from_did` — Ed25519 public-key extraction from a DID.
- `DidDocument`, `VerificationMethod`, `Service`, and the rotation/migration
  proofs (`DidRotationEvent`, `MigrationProof`, `PreRotationProof`) — the W3C
  DID Document model for `did:dht` identities (ADR-039).
- `decode_multibase_key` — multibase → 32-byte Ed25519 key, with curve-point
  validation.
- `DidError` — the synchronous errors those types construct.
- the [`attestation`] module — key-custody and identity-link attestation types.

Every type here is a pure synchronous value type with no async, no `tokio`, and
no `scp-platform` coupling, so the crate compiles to
`wasm32-unknown-unknown` for the in-browser SCP client (ADR-057).

The **native** identity subsystem — DHT resolution/publication, the async
`DidMethod` trait, `DidDht`, `ScpIdentity`, `IdentityError`, and lifecycle
management — lives in `scp-identity`, which imports this data model. The DHT is
not separable from that subsystem (its type graph rejects the seam), so it stays
one native crate; see ADR-057's Amendment (2026-06-30, rejected alternative 5).

Part of the `scp-clock` / `scp-crypto` / `scp-did` split that dissolved the old
`scp-primitives` junk-drawer crate and moved the DID model out of `scp-protocol`.

## Feature flags

- `testing` — enables the non-standard `did:key:{hex}` DID format for
  integration tests that run outside `#[cfg(test)]`. **Never enable in
  production builds.**
