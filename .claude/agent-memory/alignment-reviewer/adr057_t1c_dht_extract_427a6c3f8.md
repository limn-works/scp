---
name: adr057-t1c-dht-extract-427a6c3f8
description: ADR-057 T1c(-a) scp-dht transport extraction — review of batch-fix HEAD 427a6c3f8; ALIGNED, all prior-round findings resolved, 1 LOW peripheral guide stale path
metadata:
  type: project
---

# ADR-057 T1c(-a) extract scp-dht @ `427a6c3f8` (2026-07-03) — ALIGNED, 1 LOW

Successor to [[adr057_t1c_dht_extract_6932d2fbf]] (that pass = NEEDS DISCUSSION, 1 HIGH + 2 MOD + 1 LOW, all downstream-artifact staleness). HEAD range c102f8222..427a6c3f8; `427a6c3f8` = review-batch fix atop the `6932d2fbf` extraction commit. **ALL FOUR prior-round findings RESOLVED:**

- (was HIGH) release.yml: scp-dht now in TAGS array, has its own Publish step in TOPOLOGICAL order (line 388, after scp-did/before scp-identity — correct since scp-identity pins `scp-dht = "=0.1.0-beta.2"` and scp-dht has no scp-* deps), and summary line lists it (17 crates). Verified full publish ladder ordering sound.
- (was MOD) ADR-057: intro line now "T1 and T1c ... executed by this change set; T1c-b and T2 follow"; T1c bullet past-tense "landed"; NEW T1c-b bullet carries the parser-consolidation (the deferred half — the impl's "T1c-b" name is now IN the ADR, resolving my prior nuance); crate table has scp-dht row; ASCII graph shows `scp-identity ... → scp-dht`; rejected-alt-5 transport bullet past-tense "was extracted (landed in this change set)".
- (was MOD) architecture.md: crate map + Layer-1 ladder both list scp-dht; "Completed extractions" para line 712 rewritten (DID-**method** not separable, transport WAS separable/extracted); replaceable-subsystems DHT-client row now points `crates/scp-dht/src/dht_client/` (path exists).
- (was LOW) CLAUDE.md project map: scp-dht row added.

CODE re-verified 0-findings: scp-dht/Cargo.toml publishable (no publish=false, 0.1.0-beta.2 == sibling crates), DhtError=3 variants, lib.rs owns bep44_signable+verify_bep44_signature (local, pkarr_client calls `crate::verify_bep44_signature`), no scp-* deps. `From<scp_dht::DhtError> for IdentityError` @ scp-identity/lib.rs:295 message-preserving all 3 variants. `pub use dht::{...}` block @ lib.rs:45 has verify_bep44_signature REMOVED (not repointed — no shim); grep confirms zero `pub use scp_dht` re-exports. shim gate fully extended (closed-set array + owning_dir + header comments + success msg). production-dht feature forwards `scp-dht/production-dht`. Old crates/scp-identity/src/dht_client/ dir GONE. Standalone crates (scaffolds/rust-client, templates/personal-relay) repointed to scp_dht (personal-relay w/ production-dht feature). scpid.rs + all 6 named FFI/node sites import scp_dht:: direct. `cargo check -p scp-dht --features production-dht -p scp-identity` GREEN. shim gate run GREEN.

**ONLY NEW FINDING — LOW:** `.docs/guides/self-hosting-a-website-on-scp.md:100` cites `crates/scp-identity/src/dht_client/pkarr_client.rs:271 publish / :303 resolve` — the crate-path segment is now stale (file moved to `crates/scp-dht/src/dht_client/pkarr_client.rs`). Branch did NOT touch this guide; the move made the path unresolvable (line numbers 271/303 coincidentally still land in publish/resolve regions of the new file). Same downstream-doc-staleness class as the prior round's core-artifact findings, but this one is a peripheral guide outside the four named artifacts. Non-blocking; fix = repoint crate path (and ideally re-check line numbers: publish `fn publish` @233, resolve `fn resolve` @293 in new file).

Verdict ALIGNED (was NEEDS DISCUSSION last round). GOTCHA carried forward: this is a recurring pattern — a crate move/extraction leaves stale file-path citations in peripheral `.docs/guides/` that a diff-scoped review misses; corpus-wide grep for the moved path across ALL of .docs/ catches them.
