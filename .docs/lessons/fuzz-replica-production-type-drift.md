# Fuzz targets that replicate private production functions drift silently

**Date:** 2026-04-15
**Source:** Round 1 review of fuzzing infrastructure — three HIGH bugs in `fuzz_validate_ucan_deep`

## What happened

`fuzz_validate_ucan_deep` (Tier 4, trust boundary B3) validates UCAN tokens by calling a
sequence of validation steps that mirror the production validation pipeline. Three of those
steps required access to private production functions — `build_sender_aad`, the CID format
logic, and the ceiling format string — that were not `pub` in the production crates.

The target re-implemented these functions locally:

```rust
// fuzz_targets/fuzz_validate_ucan_deep.rs
fn build_sender_aad_replica(context_id: &str, sender_did: &str) -> Vec<u8> {
    // Local replica of scp_runtime::encrypt::build_sender_aad
    let mut aad = Vec::new();
    aad.extend_from_slice(context_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(sender_did.as_bytes());
    aad
}
```

Round 1 review found three HIGH bugs:

1. The production `build_sender_aad` used a length-prefixed format (`[len][context_id][len][sender_did]`), not the colon-separated format in the replica. The replica produced a different byte sequence.
2. The CID format replica omitted a version prefix byte that was added to the production function in PR #1602.
3. The ceiling format replica used lowercase hex where the production function used uppercase.

All three discrepancies would cause the fuzz target to miss bugs in the real production code:
the target was testing the replica, not the production function.

## Why this is dangerous

A fuzz target that uses a stale replica of a production function provides false assurance:

1. **The target continues to pass** — it is internally consistent with itself.
2. **Production bugs are invisible** — the target never calls the production function, so
   it cannot discover bugs in it.
3. **Corpus is worthless** — inputs that find bugs in the replica would not exercise the
   production code path at all.

This is worse than having no fuzz target: a missing target is visible; a green fuzz target
with a stale replica hides the gap.

## The mitigation: prefer re-export over replica

**Option 1 (preferred): `pub` or `pub(crate)` with `#[doc(hidden)]`.**

Make the production function public with a `#[doc(hidden)]` attribute to signal it is
implementation-internal but accessible for testing and fuzzing:

```rust
// crates/scp-runtime/src/encrypt.rs
#[doc(hidden)]
pub fn build_sender_aad(context_id: &str, sender_did: &str) -> Vec<u8> { ... }
```

The fuzz target then calls the real function:

```rust
use scp_runtime::build_sender_aad;
fuzz_target!(|input: ArbAadInput| {
    let aad = build_sender_aad(&input.context_id, &input.sender_did);
    // ... invariant assertions on real output
});
```

**Option 2: byte-equality conformance test.**

Add a `#[test]` in the production crate that verifies the fuzz-target replica matches the
production function for a representative set of inputs. This does not eliminate drift but
detects it at CI time:

```rust
#[test]
fn build_sender_aad_matches_fuzz_replica() {
    let cases = [("ctx:abc", "did:dht:xyz"), ("", "did:dht:zzz")];
    for (ctx, did) in cases {
        assert_eq!(
            build_sender_aad(ctx, did),
            fuzz_replica::build_sender_aad(ctx, did),
            "replica drifted from production for ({ctx}, {did})"
        );
    }
}
```

**Option 3 (last resort): document the replica explicitly.**

If neither option is feasible (e.g., the function is truly sealed in a private module with no
way to expose it), document the replica with a comment linking to the production function and
add a CI check that verifies the replica is reviewed when the production function changes.

## How to catch replica drift during review

1. `grep -n "replica\|// mirrors\|// replicates\|// copy of" fuzz/fuzz_targets/*.rs` — any
   such comment is a candidate for a `#[doc(hidden)] pub` promotion.
2. When a production crate changes a function that is also used (or replicated) in a fuzz
   target, the `fuzz-build` CI check (`cargo +nightly-2026-05-03 check --manifest-path fuzz/Cargo.toml`)
   will catch compilation errors but NOT semantic drift.
3. When adding a new field to a struct used in fuzzing, audit all fuzz targets for local
   replicas of functions that use that struct.

## Related

- `fuzz/fuzz_targets/fuzz_validate_ucan_deep.rs` — Tier 4 target (fixed after Round 1 review)
- `crates/scp-runtime/src/encrypt.rs` — `build_sender_aad` (promoted to `#[doc(hidden)] pub`)
- `.docs/adrs/phase-6.md` §ADR-045 — Fuzzing Infrastructure, "Rejected Alternatives §Arbitrary-everywhere"
- `.docs/lessons/fuzz-raw-bytes-over-arbitrary-wrappers.md` — related target-quality lesson
