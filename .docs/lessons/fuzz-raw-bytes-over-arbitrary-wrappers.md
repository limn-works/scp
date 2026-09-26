# Fuzz parser targets with raw bytes + dicts, not `Arbitrary` wrappers

**Source:** ADR-045 (Fuzzing Infrastructure) — design rationale; `fuzz/.claude/CLAUDE.md`

## The principle

For parser and deserializer fuzz targets (Tier 1–2 in ADR-045), always use raw byte slices as
the fuzzer input. Reserve `Arbitrary` for Tier 3–4 invariant and differential targets where
raw bytes cannot reach the code path.

```rust
// CORRECT — raw bytes for a parser target
fuzz_target!(|data: &[u8]| {
    let _ = OuterEnvelope::from_bytes(data);
});

// WRONG — Arbitrary wrapper for a parser target
fuzz_target!(|input: ArbOuterEnvelope| {
    let bytes = input.to_bytes();
    let _ = OuterEnvelope::from_bytes(&bytes);
});
```

## Why the distinction matters

libFuzzer works by mutating the input buffer and observing which new LLVM coverage edges are
discovered. When the input is a raw `&[u8]`:

1. The fuzzer mutates bytes directly in the parser's input space.
2. A single bit flip in a MessagePack field-name byte may expose a new branch in the parser.
3. libFuzzer's mutation strategies (bit flip, byte substitution, crossover, dictionary tokens)
   all operate directly on meaningful parser bytes.

When the input is an `Arbitrary`-wrapped type:

1. libFuzzer mutates bytes in the `Arbitrary` binary encoding (the serialized representation
   of the `Arbitrary` struct), not in the final parser input.
2. Many mutations of the `Arbitrary` encoding produce the same or structurally equivalent
   parser input — no new coverage edge, no learning.
3. The dictionary (`-dict=`) is useless: dictionary tokens are meaningful as MessagePack bytes,
   not as bytes inside an `Arbitrary` encoding.
4. Coverage plateaus quickly at a low value, and the fuzzer stops making progress.

This break in the feedback loop is the single most common cause of ineffective fuzz campaigns.

## When `Arbitrary` IS the right choice

`Arbitrary` is appropriate when:

1. **Raw bytes cannot reach the code path.** A merkle proof verifier requires a structurally
   consistent proof (sibling hashes must be consistent lengths, root must match). Random bytes
   are rejected before reaching the interesting code. `ArbMerkleProof` generates structurally
   valid proofs with adversarially chosen values.

2. **Differential invariants require two semantically distinct inputs.** `fuzz_aad_differential`
   checks that different `(context_id, sender_did)` pairs always produce different AAD values.
   This requires generating two structurally valid inputs, not two random byte arrays.

3. **Targets require real cryptographic material.** `fuzz_validate_ucan_deep` uses real Ed25519
   keypairs (generated once per run, seeded from the fuzzer input) to test signature
   verification bypass. Raw bytes cannot produce a valid Ed25519 signature — `Arbitrary` with
   real key generation is needed.

## Recognizing the wrong pattern

Red flags in a fuzz target:

- `fuzz_target!(|input: ArbFoo|` for a type that has a `from_bytes` entry point.
- A target that creates an `ArbFoo`, calls `to_bytes()` on it, then passes it to a parser.
- A target description says "parser target" but uses `Arbitrary`.

When reviewing a new target, ask: "Is the target testing a parser (Tier 1–2) or a security
invariant that requires structural validity (Tier 3–4)?" If the former, the input must be
`&[u8]`.

## Dictionaries amplify raw-byte coverage

For MessagePack parser targets, the `-dict=` flag is essential. Without a dictionary:
- The fuzzer spends most of its time on inputs that fail before the first field check.
- Coverage plateaus at the fixmap header byte (`\x81`–`\x8f`).

With a dictionary of field names and MessagePack structural bytes:
- The fuzzer can quickly construct inputs that reach deep field-parsing branches.
- New enum variants and field names are discovered much faster.

Add a dictionary for every new Tier 1–2 target. Update it whenever a new serde field or
variant is added. See `fuzz/.claude/CLAUDE.md` §Dictionary Files for the format.

## Related

- `.docs/adrs/phase-6.md` §ADR-045 — Fuzzing Infrastructure (decision §"Raw bytes + dicts for T1/T2")
- `fuzz/.claude/CLAUDE.md` — "Do NOT wrap raw bytes in Arbitrary types for parser targets"
- `fuzz/fuzz_targets/fuzz_outer_envelope.rs` — canonical Tier 1 example (raw bytes)
- `fuzz/fuzz_targets/fuzz_merkle_proof.rs` — canonical Tier 3 example (Arbitrary)
- `fuzz/src/lib.rs` — shared `Arbitrary` type definitions for Tier 3–4 targets
