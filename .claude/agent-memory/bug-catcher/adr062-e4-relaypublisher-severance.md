---
name: adr062-e4-relaypublisher-severance
description: SCP-CAPINJECT-011 / ADR-062 E4 — RepublishManager InMemoryRelayPublisher default severance + test-double gating. Reviewed clean at 7f658c8fb.
metadata:
  type: project
---

# ADR-062 E4 — RepublishManager relay-publisher-double severance (commit 7f658c8fb)

Change: removed `R: RelayPublisher = InMemoryRelayPublisher` default type param on
`RepublishManager<D, R>`; gated `InMemoryRelayPublisher`, its inherent impl, its
`RelayPublisher` impl, and the exclusive `RecordedRelayPublish` support type behind
`#[cfg(any(test, feature = "testing"))]`. File: crates/scp-identity/src/republish.rs.

**Reviewed CLEAN — NO BUGS.** Verified:
- Prod (`cargo build -p scp-identity`), test (`cargo test --no-run`), and
  `--features testing` all compile.
- Zero production construction sites of `RepublishManager` anywhere (only lib.rs
  re-export + 2 doc-comment mentions in dht.rs / custody_migration.rs). In-crate
  `mod tests` sites all annotate `RepublishManager<InMemoryDhtClient, InMemoryRelayPublisher>`.
- cfg choice `any(test, feature="testing")` (not `testing`-only) is CORRECT: the
  in-crate test module uses `InMemoryRelayPublisher`, and `cargo test -p scp-identity`
  does NOT auto-enable the crate's own `testing` feature (a crate can't dev-dep itself),
  so bare `test` cfg is required. Contrast `InMemoryDhtClient` (from scp-dht) which the
  tests get via dev-dep `scp-dht = { features=["testing"] }` — different mechanism, why it
  needs no `test`. `testing` feature IS declared in Cargo.toml (no unexpected_cfgs).
- G1 (check-shipped-feature-graph.sh) unaffected: `test` is a rustc cfg, never a Cargo
  feature, so it can't enter the shipped feature graph.
- Only `[...]` intra-doc link to the gated type (line 143 on RecordedRelayPublish) is
  co-gated; trait/struct docs mention `InMemoryRelayPublisher` in backticks only. No
  broken-link introduced by the diff.

**Out-of-scope / pre-existing (NOT this diff):**
- There is NO production implementor of `RelayPublisher` in the whole workspace — only
  the now-gated test double. So `RepublishManager` and `DualLayerHealingPublisher`
  (resolver.rs) are, in prod, generic over a trait with zero implementors → practically
  unconstructable in prod. Intended: real relay backend is issue #482, out of ADR-062
  scope; honest fail-closed absence. Was already the case pre-diff (default was the same
  test double).
- `cargo doc` broken intra-doc link to `InMemoryPreRotationCustody` is in config.rs/dht.rs
  (SCP-IDENT-1059 fail-closed change), byte-identical to origin/main — strictly
  pre-existing, unrelated to republish.rs.
