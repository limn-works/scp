---
name: adr062-e4-relay-publisher-sever
description: SCP-CAPINJECT-011 (ADR-062 E4) InMemoryRelayPublisher default-sever review — COMPLETE; pattern for E1/E2/E3/E4 default-type-param severs
metadata:
  type: project
---

SCP-CAPINJECT-011 (ADR-062 Slice 11, E4 WRITE-path default-selection hygiene) reviewed COMPLETE at commit 7f658c8fb. Single-file diff, `crates/scp-identity/src/republish.rs`.

**Why:** E-item class (E1 `DidDht<D=InMemoryDhtClient>`, E2 credentials, E3 blob, E4 relay-publisher) all do the same thing: remove a `= InMemoryX` default type param so no shipped construction can silently bind the dev double, and demote the in-memory double + its exclusive support types to `#[cfg(any(test, feature="testing"))]`.

**How to apply — what to verify for any E-class sever:**
- `grep '= InMemory' <file>` == 0; struct decl carries no default type param.
- The `impl<D> X<D>` DHT-only constructor block must become `impl<D, R> X<D, R>` (generic over the freed param) or every test construction breaks. Verify the constructor impl AND the Debug impl are re-parameterized.
- The in-memory double's `pub struct` + `impl X` + `impl Trait for X` EACH carry the cfg gate, AND any exclusive support type (e.g. `RecordedRelayPublish`, produced only by the double) — else it ships as a dead unused `pub` type.
- Every construction site must be inside `#[cfg(test)]` mod tests (grep line numbers > `mod tests` line). Confirm no production construction: `grep -rn 'X::' crates --include=*.rs` outside the defining file == 0.
- The READ-side sibling (here `NoOpRelayQuerier`, resolver.rs) is NOT a nullifier (fails CLOSED, returns `Ok(None)`, never fabricates) — stays SHIPPED and UNGATED. Do not gate it. ADR-062 §Decision 5 line 41/96 classifies it as a defense-in-depth completeness gap, not a nullifier; building the real querier is issue #482, out of ADR-062 scope.
- G1 gate `bash scripts/check-shipped-feature-graph.sh` must pass (feature-graph ⊆ durability-only allowlist; the double is absent from shipped graph because `testing` isn't in it).
- Provenance is exact: story + ADR-062 §Decision 5 WRITE row (line 42/100/166) agree with code. No divergence.

All 6 story ACs + task's expanded checks PASS: bare/testing builds exit 0, clippy -D warnings exit 0, 24 republish tests pass, validate-prd exit 0 (18 files/443 stories), G1 green.
