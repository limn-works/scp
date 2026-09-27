# `#[serde(flatten)]` Buffers the Whole Message Before Any Field Check Runs

A struct with a `#[serde(flatten)]` field does not deserialize field by field: serde buffers
every map entry first and then hands fields to their deserializers, so a per-field bound such
as `serde_bounded_bytes` fires only after the whole input is in memory. MessagePack makes this
exploitable, because a five-byte `bin32` header (`\xc6\xff\xff\xff\xff`) claims 4 GiB and the
decoder trusts the length. `InnerEnvelope` and other wire types in `scp-protocol` flatten an
`extensions` map, so an unauthenticated peer could make a relay or SDK attempt a huge
allocation.

## Rule

Every entry point that calls `rmp_serde::from_slice` or `from_read` on untrusted bytes checks
`data.len()` against a protocol constant as its first operation, before any prefix or magic
reading. `rmp_serde` takes no size-limit parameter, so the explicit length check is the only
gate. `InnerEnvelope::from_bytes` (`crates/scp-protocol/src/envelope/inner/mod.rs`) checks
`MAX_ENVELOPE_SIZE` this way. The rule holds after MLS decryption too, because an
authenticated plaintext can still be malformed.

Unit tests with valid inputs never produce a maximal length prefix; a raw-byte fuzz target
such as `fuzz/fuzz_targets/fuzz_outer_envelope.rs`, or an explicit boundary test, does.
