---
name: versioned-tail-proptest-pattern
description: Fix for the "never-panics" proptest that never passes the version/discriminant gate (~1/256 vacuity); scp-protocol did_record.rs
metadata:
  type: project
---

Frame decoders gated on a first-byte version/discriminant have a classic vacuous
"never panics on arbitrary input" proptest: a fully-random first byte equals the
expected version only ~1/256 of the time, so the len/slice/value-length paths are
almost never exercised. **Fix pattern (good, replicate):** add a *versioned-tail*
generator that prepends the real version byte then a random tail, plus a
*boundary-clustered length* generator centered on the fixed-prefix length (where
the `len - PREFIX` underflow risk lives). The versioned-tail test should also
assert *specific* outcomes per length band (Truncated below prefix, EmptyValue at
prefix, Ok above), not just `matches!(Ok|Err)` — that turns a non-panic smoke test
into a real behavior test.

Reference implementation: `crates/scp-protocol/src/envelope/did_record.rs`
(`DidRecordV1`, SCP-RELAYRES-001) — `prop_versioned_tail_never_panics` +
`prop_prefix_boundary_never_panics`, 256 cases each.

Companion misuse-resistance pattern in same file: private fields +
validating `try_new` (rejects empty/oversize `value`) + read accessors ⇒ a
malformed record is unrepresentable, so total `encode()` can never emit an
undecodable frame. Tests that need a malformed frame build **raw byte vectors**
(the invalid struct is unconstructable) — see `decode_value_length_boundaries`.

**Stale-base trap reminder:** this crate/spec state only exists on the feature
branch. `scp-relay-client` crate + `crates/scp-relay-client/src/protocol.rs`
(authoritative `MAX_BLOB_SIZE`) and spec §9.10.12 are ADDED on the branch — the
working tree / HEAD does NOT have them. Always `git show <branch>:<path>` when
verifying doc cross-refs, not the checked-out tree. See alignment-reviewer's
[[feedback_two_dot_diff_stale_base_trap]].
