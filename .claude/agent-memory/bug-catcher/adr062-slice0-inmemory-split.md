---
name: adr062-slice0-inmemory-split
description: ADR-062 Slice 0 review (PR #2138) — scp-platform in_memory/ vs testing/ module split, feature-gate verification
metadata:
  type: project
---

# ADR-062 Slice 0 module restructure (PR #2138, commit 026420ed5)

Verdict: **CLEAN — 0 real bugs.** 91-file restructure. `InMemoryStorage`/`InMemoryPush`
moved `testing/` → new `in_memory/` behind durability-only features
`in-memory-storage`/`in-memory-push`. Nullifier doubles (`InMemoryKeyCustody`/
`InMemoryDeviceAttestation`/`InMemoryPreRotationCustody`) stay in `testing/` behind
`#[cfg(feature="testing")]`. `testing = ["software_platform","in-memory-storage","in-memory-push"]`
(testing implies both durability features). `BridgeInMemoryStorage` deleted;
`build_event_log_provider` now `EncryptingAdapter<in_memory::InMemoryStorage>`.

**Key finding I initially suspected then DISPROVED (empirically):** scp-ffi-common
`server.rs` uses BOTH `in_memory::InMemoryStorage` (durability) AND
`testing::InMemoryKeyCustody` (nullifier). The `server` feature was re-pointed
`scp-platform/testing` → `scp-platform/in-memory-storage` (dropping testing). I thought
`InMemoryKeyCustody` would be unresolved. It is NOT: `server` → `dep:scp-node`, and
scp-node's Cargo.toml enables `scp-platform` with `testing` **non-optionally**
(`features=["testing","sqlite","file","encrypting"]`). Feature unification pulls
scp-platform/testing into any build where `server` is on. `cargo check/clippy -D warnings
-p scp-ffi-common --features server` both PASS clean. **Lesson: always verify feature-gate
hypotheses with an actual isolated `cargo check`, don't reason from Cargo.toml alone —
transitive non-optional feature activation via sibling deps masks apparent gaps.**

Verified compiles (isolated, worktree): scp-platform `--no-default-features --features
in-memory-storage,encrypting` OK; `--features in-memory-push` OK; scp-runtime default (no
testing) OK — its only in_memory use is `#[cfg(any(test, feature="testing"))]` in
context/mod.rs:271; scp-ffi-common `--features server` OK + clippy -D warnings OK.

Other concerns checked & clean:
- build_event_log_provider replacement is behaviorally IDENTICAL — `in_memory/storage.rs`
  is the git-moved `testing/storage.rs` (HashMap + `keys.sort()` in list_keys), and old
  deleted `BridgeInMemoryStorage` was also HashMap+sort. No lost behavior.
- No mis-split imports: grep for `in_memory::InMemoryKeyCustody` (0), `testing::InMemoryStorage`
  (0). Nullifiers stayed testing::, storage moved to in_memory::.
- store/mod.rs 51-line diff = pure repointing + one formatting reflow, no logic change.
- consumers with non-test in_memory use all have testing/in-memory-storage guaranteed:
  scp-node (testing non-optional), scp-ffi (testing non-optional), scp-testing (testing
  non-optional), scp-ffi-common (dep table bakes in-memory-storage into every scp-platform activation).

LOW/latent (not a bug, noted): `server` feature's compile-correctness depends on scp-node
transitively forcing scp-platform/testing for `InMemoryKeyCustody`. Comment says "in-memory
testing backends" but only lists in-memory-storage. If scp-node ever drops testing, or
server.rs is decoupled from scp-node, `-p scp-ffi-common --features server` breaks. Hygiene:
server feature could declare its InMemoryKeyCustody dependency directly. Pre-existing property
of server.rs (used testing:: before this PR too).
