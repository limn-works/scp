---
name: adr062-slice0-module-split
description: ADR-062 Slice 0 durability-only in_memory/ split from testing/ nullifiers (PR #2138, 026420ed5) — boundary holds, no new nullifier leak; narrowing is cosmetic
metadata:
  type: project
---

# ADR-062 Slice 0 — honest in_memory/ module split (PR #2138, commits 76796c890 + 026420ed5) -- 2026-07-15 -- PASS, boundary holds; 0 CRIT/HIGH

Verified against merge-base 27c1849c9; Slice 0 proper = 76796c890 (refactor) + 026420ed5 (doc fix). Branch is stacked on many unrelated PRs — review the two commits only (`git diff 8b39f3526..026420ed5`).

## What the split does
- New `scp-platform/src/in_memory/` = ONLY InMemoryStorage + InMemoryPush (durability-only, spec §17.17.2). push.rs/storage.rs are BYTE-IDENTICAL git moves out of testing/. Gated `#[cfg(any(feature="in-memory-storage", feature="in-memory-push"))]`.
- The 3 NULLIFIERS (InMemoryKeyCustody plaintext keys, InMemoryDeviceAttestation always-pass, InMemoryPreRotationCustody) STAY in testing/ behind `#[cfg(feature="testing")]`. Confirmed: no key/attest/secret material in in_memory/storage.rs.
- Cargo: `testing = ["software_platform","in-memory-storage","in-memory-push"]` (one-way implication; enabling in-memory-storage ALONE does NOT pull testing/nullifiers). server feature re-pointed `scp-platform/testing`→`scp-platform/in-memory-storage`. Base scp-platform dep in scp-ffi/common/Cargo.toml gained `in-memory-storage`.

## KEY FINDING (observation, not a regression): narrowing is COSMETIC
- F1 re-point does NOT break compile: server.rs (scp-ffi-common) still `use scp_platform::testing::InMemoryKeyCustody` UNCONDITIONALLY (lines 23/323/436). It compiles because **scp-identity Cargo.toml:23 and scp-node Cargo.toml:31 enable `scp-platform/testing` via NORMAL PRODUCTION deps** (untouched by slice). Verified via `cargo tree -i scp-platform` + successful `cargo check -p scp-ffi-common --features server,custody`.
- Therefore the 3 nullifiers remain COMPILED into EVERY graph pulling scp-node/scp-identity (i.e. all bridges). The slice removes only a REDUNDANT direct edge; actual nullifier reachability in prod artifacts is UNCHANGED. Real reduction deferred to Slice 6 (custody/attestation phantoms). This is the known deferred leak, NOT newly introduced. Do NOT mistake Slice 0 for "nullifiers out of prod" — storage half only, and even that is masked by the transitive testing edge.

## POSITIVE
- Adding `in-memory-storage` to the base scp-ffi/common dep + pointing bridge_runtime at `scp_platform::in_memory::InMemoryStorage` (event-log store, #1447) makes the durability-only edge EXPLICIT instead of relying on the transitive testing leak. Right direction. in-memory-storage in a shipped graph is ALLOWED (durability-only, explicitly selected, not default/fallback).
- `pub use testing as software;` alias removed — grep confirms zero dangling `scp_platform::software::` refs.

## Pre-existing leak to watch (Slice 6 target)
scp-identity Cargo.toml:23 `scp-platform features=["testing"]` (prod dep) and scp-node Cargo.toml:31 `["testing","sqlite","file","encrypting"]` (prod dep) = the real nullifier leak into prod. software_platform alone does NOT pull nullifiers (that boundary from #88 holds).
