# Assert a Cryptographic Invariant on Every Bridge That Emits the Artifact

**Rule**: when a wire artifact carries a spec-defined cryptographic invariant, every bridge
that emits the artifact asserts the invariant in its own tests, recomputed from the emitted
bytes. Registering the operation under one canonical name in `scripts/bridge-aliases.json`
and `ffi_conformance.rs` proves the surfaces are symmetric and says nothing about whether the
output satisfies the protocol.

**What happened**: `migrate_identity` was a registered parity operation on every bridge, the
symmetry checks were green, and each bridge's test asserted only
`event.pre_rotation_proof.is_some()`. The PyO3, NAPI, and UniFFI bridges generated a fresh
pre-rotation key at migrate time, so `SHA-256(revealed_key) == commitment` (§9.7.4.1 of
`09-security-model.md`) failed on every rotation event they emitted. Only the since-removed
WASM bridge asserted the equality, and porting its assertion turned the other three red.

## The test each bridge carries

1. Invoke the bridge end to end, with no internal mocks.
2. Deserialize the emitted bytes into the cross-bridge wire type.
3. Recompute the invariant from the deserialized fields.
4. Assert byte equality, never `is_some()` or non-empty.

```rust
let pre_rot = event.pre_rotation_proof.as_ref().expect("MUST be present");
let recomputed: [u8; 32] = Sha256::digest(pre_rot.revealed_key).into();
assert_eq!(recomputed, pre_rot.commitment);
```

When two implementations encode the same wire type, test parity in both directions: each
one's output must round-trip through the other's type.

See `.docs/lessons/hash-commitment-preimage-lifetime.md` for the storage half of the same
defect.
