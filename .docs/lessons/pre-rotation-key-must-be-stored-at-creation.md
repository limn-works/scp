# Pre-Rotation Key Handle Must Be Stored at Identity Creation

**Source:** SCP-214 review of `crates/scp-ffi/src/identity.rs:py_identity_migrate`

## The Bug

`py_identity_migrate` performs a root-key rotation. It calls
`migrate_identity(identity, old_doc, pre_rotation_key, custody, rotated_at)`.

The `pre_rotation_key` parameter must be the **KeyHandle of the keypair whose public key was
committed to at identity creation time**. The published record stores that commitment as the
SHA-256 digest of the pre-rotation public key.

`build_pre_rotation_proof` (dht.rs:690) reads that commitment from the old record and compares
it to the public key of the supplied `pre_rotation_key`. If they do not match, the proof is
cryptographically invalid and verifiers reject the rotation.

The implementation generates a **fresh keypair at migration time** (identity.rs:587-590), and a
freshly generated key never matches the commitment stored at creation time. Every migration
attempt produces an invalid proof.

## Why It Happens

`IdentityEntry` stores `ScpIdentity` (which contains `identity_key` and `active_signing_key`
handles) but not the pre-rotation key handle. `create` allocates three keys in
sequence:

| Allocation order | KeyHandle id | Purpose |
|------------------|-------------|---------|
| 0 | identity_key | Identity key |
| 1 | active_signing_key | Active signing key |
| 2 | (unnamed) | Pre-rotation key (the commitment's preimage) |

The pre-rotation key handle is computed during `create` but not surfaced in `ScpIdentity`. It
exists in `InMemoryKeyCustody`'s internal map under handle id 2. For the FFI bridge to use it
at migration time, the handle must be stored explicitly.

## The Fix

Add a `pre_rotation_key: KeyHandle` field to `IdentityEntry`. Populate it from the pre-rotation
key allocated during `create`. Pass it directly to `migrate_identity` instead of generating a
fresh key.

Two approaches:

1. **Surface the handle in `create`'s return value.** `ScpIdentity` could include
   `pre_rotation_key: KeyHandle` alongside `identity_key` and `active_signing_key`. The field is
   already conceptually part of the identity — it changes on every operational-key rotation
   (`rotate_active_key` allocates a new pre-rotation key and updates the commitment).

2. **Expose the handle from `IdentityEntry` without changing `ScpIdentity`.** Add
   `pre_rotation_key: KeyHandle` to `IdentityEntry` in `runtime.rs` and populate it from the
   handle returned by the key allocation inside `create`. This avoids changing the
   scp-core public API.

Option 1 is preferred — the pre-rotation key is intrinsic to the identity lifecycle, not an
FFI implementation detail.

## Operational-Key Rotation Interaction

`py_identity_rotate_key` calls `rotate_active_key`, which allocates a new pre-rotation key and
updates the published commitment. After that rotation, the stored pre-rotation handle in
`IdentityEntry` must also be updated. Otherwise a subsequent `py_identity_migrate` uses the
stale pre-rotation handle from before the rotation.

## The Invariant

The pre-rotation keypair and its commitment form a hash-then-reveal scheme. The commitment (hash)
is written at time T. The key (preimage) must be presented at time T+1 (migration). These two
values must be cryptographically linked. Any code path that writes the commitment must also
persist a reference to the preimage. They cannot be separated across time.

## Related

- `ScpIdentity.pre_rotation_commitment` stores the SHA-256 hash (32 bytes), not the handle. The
  commitment is verified but not used to reconstruct the handle.
- Root-Authority Recovery and Fork Precedence, §9.7.4.2 of `09-security-model.md`, states the
  key rotation scheme.
- `build_pre_rotation_proof` (dht.rs:690-716) performs the commitment check.
- After an operational-key rotation, `rotate_active_key` preserves `pre_rotation_commitment` (verified by
  test `rotate_active_key_preserves_pre_rotation_commitment`), so the pre-rotation key handle
  must be updated alongside it.
