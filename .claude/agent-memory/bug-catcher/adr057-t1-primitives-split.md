# ADR-057 T1 topology refactor (dissolve scp-primitives, extract scp-did) — CLEAN

Branch `refactor/dissolve-primitives-split-identity`, range 86519aa6f..5b35cb9aa.

Verified clean (2026-07):
- Moves are byte-level mechanical: scp-primitives/{time,crypto,identity}.rs → scp-clock/scp-crypto/scp-did lib.rs (only 4-line crate headers added). document.rs + did_attestation.rs pulled OUT of scp-protocol into scp-did; the only edit is `DidDocumentError`→`DidError` rename + import-path repointing. No logic drift.
- All consumers repointed: zero dangling `DidDocumentError`, `scp_primitives`, `scp_protocol::time`, `crypto::ed25519`, `identity::document`, or un-shimmed `crate::crypto::mls::{group,credential,…}` refs. scp-runtime deleted its `pub use scp_mls::{…}` shim (ADR-057 Amendment) and all call sites import `scp_mls::` directly.
- MLS facade in scp-core merges scp_mls sync modules + scp_runtime async-storage-bridge with NO name overlap.
- `cargo check --workspace --all-targets` with CI custody feature set = exit 0. wasm32 check of scp-did/clock/mls/client/client-wasm = exit 0. `cargo metadata --locked` = exit 0 (root + fuzz locks consistent, no stale scp-primitives).
- release.yml: valid YAML, 16 crates in correct topological publish order each with trailing `sleep 60`, scp-client-wasm correctly excluded (publish=false).
- Gate scripts/check-no-shim-reexports.sh: `*/` comment-filter guard is FAIL-CLOSED (over-flags, never under-flags). Wired at ci.yml protocol-deps job. Passes.

Only non-clean item (PRE-EXISTING, NOT a regression, NOT CI-gated):
- templates/cross-context-bridge, templates/personal-relay, scaffolds/rust-client do NOT compile — but from core-API drift (deleted ContextManager, ApplicationNodeBuilder, append_event 5-vs-6 arity, RateLimit API), unrelated to this refactor. Base rust-client already referenced deleted `scp_core::context::manager::ContextManager`. The refactor's DID/clock import repointing + unused-dep drops in these crates are correct; the "standalone-crate sweep/repair" claim only covers dep hygiene, not API-drift repair. CI builds none of these standalone crates.
- Minor: scp-did makes `hex` non-optional (was `testing=["dep:hex"]` in scp-primitives). did:key path still `#[cfg(any(test,feature="testing"))]`-gated, so hex is dead-weight (compiled, unused) in pure production builds. Harmless.
