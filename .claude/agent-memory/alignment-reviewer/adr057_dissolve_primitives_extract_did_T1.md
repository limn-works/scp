---
name: adr057-dissolve-primitives-extract-did-t1
description: ADR-057 Amendment T1 (dissolve scp-primitives; extract scp-did) code↔ADR fidelity review @280983dd7 — CLEAN, zero findings
metadata:
  type: project
---

# ADR-057 Amendment T1: dissolve scp-primitives; extract scp-did @ `280983dd7` (2026-07-03) — ALIGNED, 0 findings

Branch `refactor/dissolve-primitives-split-identity`, range `86519aa6f..280983dd7` (371 files, +2743/-2432). ADR file `.docs/adrs/ADR-057-in-browser-client-over-shared-mls.md` (140 lines; Amendment §95-140 supersedes Prereq 3).

**Verified CLEAN across every dimension:**
- Crate table (ADR L107-110): scp-clock (Clock/SystemClock/TestClock/ClockError, zero-dep leaf), scp-crypto (verify_ed25519_signature, dep=ed25519-dalek), scp-did (DID/SigningKeyId/extract_public_key_from_did/DidDocument/proofs/attestation/DidError, deps=ed25519-dalek+serde crates, **no scp-crypto edge** confirmed — validates via VerifyingKey::from_bytes not verify_ed25519_signature). scp-primitives fully DELETED (6 files, status D).
- Dep graph (ADR L114-121): scp-did no scp-crypto edge ✓; wasm stack (scp-protocol→scp-mls→scp-client→scp-client-wasm, +scp-event-log, +scp-clock/crypto/did leaves) reaches NO native crate (fence holds); scp-identity→scp-clock+scp-did+scp-platform (native).
- Enforcement (ADR L125-128): `scripts/check-no-shim-reexports.sh` is a positive CLOSED-set gate over exactly {scp_clock,scp_crypto,scp_did,scp_mls}, scans all `crates/**/src/`, comment-filtered; PASSES. check-protocol-deps.sh PASSES. Both wired into ci.yml (:187). wasm32 fence job ci.yml:338 builds full browser stack. Registered in CLAUDE.md enforcement list.
- Shim deletion: `scp-runtime/src/crypto/mls/mod.rs` `pub use scp_mls::*` GONE; runtime imports `scp_mls::` directly (backend.rs).
- scp-protocol DID strays removed: identity/document.rs + did_attestation.rs gone; NO residual DidDocument def. `IdentityLinkAttestation` (attestation.rs:27 `use scp_did::DID`) correctly RETAINED as protocol wire type per ADR L101 flag.
- DidDocumentError→DidError rename COMPLETE (0 residual DidDocumentError refs).
- All layers retargeted: fuzz/ (Cargo+7 targets→scp_clock/scp_did), templates/ (cross-context-bridge→scp_did, personal-relay→scp_clock), scaffolds/rust-client→scp_did. release.yml publish order topologically sound (leaves→...→runtime→core). Docs: architecture.md:706, specs 16/20/21, white-paper ("eleven additional crates"=correct count), CLAUDE.md project map — all accurate.
- T1c/T2 forward-refs grounded in current code: scp_identity::dht::extract_public_key (canonicality parser, ADR L86 says port to scp_did FIRST in T1c — scp_did parser is currently WEAKER, correctly deferred), lib re-export verify_bep44_signature, dht_client/ dir all present.
- ADR internal anchor `#amendment-2026-06-30-...` resolves to §95 header. ADR-055 (phase-4.md) untouched, not contradicted (ADR-057 amends only browser-deployment conclusion, bridge-removal stands).
- Leaves compile (cargo check scp-clock/crypto/did OK).

**Non-findings checked & cleared:** ClockError is `pub(crate)` not pub — but ADR "Owns" = home-of, accurate (free now_secs/now_millis internal, replaced at call sites by Clock trait methods per spec-16 diff). scp-did weaker parser = explicit T1c deferral, not a T1 gap.

GOTCHA: review target = worktree `.claude/worktrees/split-primitives`, not main.
