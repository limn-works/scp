# `#[serde(flatten)]` + `rmpv::Value` buffers the whole message before rejection

**Source:** pre-deserialization size checks (security fix)

## What happened

`rmp-serde` with `#[serde(flatten)]` on a MessagePack struct does not stream field-by-field.
It first deserializes the entire input into an intermediate `rmpv::Value` tree, then extracts
named fields from that tree. This means a 4-byte MessagePack header claiming a 4 GiB blob
(`\xc6\xff\xff\xff\xff`) causes an allocation attempt before any application-level size check
runs.

In the SCP wire format, `OuterEnvelope`, `InnerEnvelope`, and several sender-key structs all
use `#[serde(flatten)]` for backward-compatible field layout. Without a size gate before
`rmp_serde::from_slice`, any unauthenticated TCP connection can send a 4-byte packet and
trigger an OOM-abort on the relay or SDK — a P0 denial-of-service.

## The fix

Always size-gate BEFORE calling any deserialization function:

```rust
use scp_protocol::constants::MAX_MESSAGE_SIZE; // from ADR-043

pub fn from_bytes(data: &[u8]) -> Result<Self, EnvelopeError> {
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(EnvelopeError::MessageTooLarge {
            size: data.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }
    rmp_serde::from_slice(data).map_err(EnvelopeError::Deserialize)
}
```

The check must be the very first operation — before any prefix reading, magic bytes, or
partial parsing. `rmp_serde::from_slice` does not accept a size limit parameter; the only safe
approach is an explicit length check at the call site.

## Why this is subtle

1. **`#[serde(flatten)]` looks harmless.** It is a field annotation, not a deserialization
   strategy annotation. Its effect on the internal buffering strategy is not obvious from
   the `serde` documentation without reading the `serde_rmpv` internals.

2. **MessagePack's length-prefixed encoding makes this exploitable.** JSON deserialization
   typically fails fast on obvious junk. MessagePack is a binary format; a 4-byte header
   `\xc6\xff\xff\xff\xff` is a valid `bin32` marker claiming 4 GiB follows. The deserializer
   trusts this length and tries to allocate before reading any data.

3. **Tests do not catch this.** Unit tests using valid or slightly malformed inputs will never
   produce a 4 GiB length prefix. The size-gate bug is only discovered by: (a) fuzz targets
   that mutate length bytes, or (b) explicit boundary tests with max-length prefixes.

## Rule

**For any type that calls `rmp_serde::from_slice` or `rmp_serde::from_read` with
`#[serde(flatten)]` fields, the size gate MUST precede deserialization.**

When reviewing a new `from_bytes` or deserialization entry point:
1. Check if the type or any field uses `#[serde(flatten)]`.
2. If yes, confirm there is a `data.len() > MAX_*` guard as the first line.
3. Check the constant comes from `scp-protocol::constants` (ADR-043), not a local magic number.

This applies to all trust boundaries — B1 (relay wire), B2 (post-MLS), B3 (discovery). Even
authenticated inputs (B2) can be malformed: MLS authentication success does not imply
well-formed plaintext.

## Related

- `crates/scp-protocol/src/envelope/outer.rs` — `OuterEnvelope::from_bytes` (size gate added)
- `crates/scp-protocol/src/envelope/inner.rs` — `InnerEnvelope::from_bytes` (size gate added)
- `crates/scp-protocol/src/constants.rs` — `MAX_MESSAGE_SIZE`, `MAX_SENDER_KEY_DIST_SIZE`, etc. (ADR-043)
- `.docs/adrs/phase-6.md` §ADR-043 — Protocol Constants Reclassification
- `.docs/adrs/phase-6.md` §ADR-045 — Fuzzing Infrastructure (the fuzz target that exposed this)
- `fuzz/fuzz_targets/fuzz_outer_envelope.rs` — T1 target that catches regressions
