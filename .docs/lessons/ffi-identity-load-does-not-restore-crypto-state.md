# FFI Identity Load Does Not Restore Crypto State

**Date:** 2026-03-01
**Source:** SCP-214 review of `crates/scp-ffi/src/identity.rs`

## The Bug

`py_identity_load` reads (DID, custody_label) from `InMemoryStorage` and returns a `PyIdentity`.
It does NOT call `register_identity`, so the DID is absent from `IDENTITY_REGISTRY`. Any
subsequent crypto operation — `py_ucan_mint`, `py_context_send`, `py_context_create` pseudonym
derivation, `py_identity_rotate_key` — calls `with_identity()` and fails with:

```
IdentityError: identity '{did}' not found in registry -- was it created with py_identity_create?
```

The returned `PyIdentity` looks valid but is cryptographically inert.

## Why This Cannot Be Fixed Transparently

`InMemoryKeyCustody` is an in-memory `HashMap<u64, SigningKey>`. It does not persist across
process restarts. Loading a DID from storage recreates the *metadata* (DID string, custody label)
but not the *key handles* — the `u64` IDs that map to actual Ed25519 key material. There is no
way to restore a `KeyHandle` that points to a live key without also restoring the custody's
internal map.

This is a fundamental constraint of the in-memory testing adapter, not a code omission. Fixing it
requires one of:

1. **Encrypted key material persistence** — serialize InMemoryKeyCustody's key map to storage,
   restore on load. This is the right long-term path (spec §17 ProtocolRepository) but requires
   encrypted blob storage, not plain `InMemoryStorage`.
2. **Session-scoped identity** — document that `py_identity_load` only restores metadata for
   display purposes (DID display, custody label inspection). Crypto operations require a fresh
   `py_identity_create` each session, which is consistent with how hardware-backed custody
   (Secure Enclave, Android Keystore) works: keys are always in the hardware, handles are
   ephemeral session references.
3. **Re-create with deterministic seed** — if the custody was created from a seed (test harness
   scenario), `py_identity_load` could recreate the custody from the stored seed. Only valid
   for `InMemoryKeyCustody` with deterministic seeding.

## The Invariant

Any function that populates `IDENTITY_REGISTRY` (i.e., any path through which an identity
enters the system) must supply a live `KeyCustody` instance that owns the actual key material.
There are exactly two such paths:

1. `py_identity_create` — creates keys, registers entry. (Works.)
2. `py_identity_load` — restores from storage. (Broken: no crypto state.)

A future `py_identity_load` that fully restores crypto state must restore both the DID document
and the custody's key material. The custody type field in storage (`"in_memory"`) is insufficient
to reconstruct a live custody instance.

## How to Catch This

When reviewing a bridge function that reads from storage and returns an opaque handle:
- Check whether the opaque handle is subsequently used to look up state in a global registry.
- Confirm that the load path populates the same registries as the create path.
- A test that calls `py_identity_load` then `py_ucan_mint` will expose this immediately.

## Resolution Path

Two-step fix tracked in subsequent stories:
1. Document `py_identity_load` as metadata-only (raises explicit error if caller attempts any
   crypto operation, rather than confusingly failing at the point of use).
2. Design encrypted identity persistence (spec §17 ProtocolRepository) with key material export/import
   so that a fully functional `py_identity_load` is possible.

## Related

- `py_identity_create` correctly populates both IDENTITY_REGISTRY and storage. Bug is isolated
  to the load path.
- `InMemoryStorage` stores `identity/{did}/state` as `"{did}\n{custody_label}"`. This is
  sufficient to reconstruct `PyIdentity` for display but not for crypto.
- See `.docs/lessons/ffi-registry-must-be-populated-from-production-paths.md` for the related
  pattern where a registry write path was missing entirely from `py_context_create`.
