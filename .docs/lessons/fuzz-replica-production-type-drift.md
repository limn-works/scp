# A Fuzz Target That Replicates a Private Production Function Drifts Silently

`fuzz_validate_ucan_deep` reimplemented three private production functions locally. Review
found all three wrong: the AAD replica used `context_id:sender_did` where production used
length-prefixed fields, the CID replica lacked a version prefix byte production had gained,
and the ceiling-format replica used lowercase hex where production used uppercase. The target
stayed green because it agreed with itself, and it could never find a bug in the production
code it never called. A green target over a stale replica is worse than no target, because a
missing target is visible.

## What to do

1. **Call the real function.** Make it `pub` with `#[doc(hidden)]` so the fuzz crate can
   import it.
2. **If it cannot be exposed, add a byte-equality test in the production crate** that compares
   the replica with the production function over representative inputs, so drift fails CI.
3. **As a last resort, document the replica** with a link to the production function. The
   `fuzz-build` job (`cargo check` of the fuzz crate) catches signature changes and never
   semantic drift.

Replicas still exist in `fuzz/fuzz_targets/` (`fuzz_aad_differential.rs`,
`fuzz_redb_blob.rs`, `fuzz_stored_value.rs`); search for `replica`, `mirrors`, and
`replicates` there when a production function or struct they copy changes.
