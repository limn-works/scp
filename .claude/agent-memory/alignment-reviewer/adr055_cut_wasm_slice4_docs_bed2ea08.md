---
name: adr055-cut-wasm-slice4-docs-bed2ea08
description: ADR-055 Slice 4 (final) — scrub WASM-as-live-bridge from normative docs @ bed2ea08 — GO-WITH-CHANGES (1 missed file)
metadata:
  type: project
---

# ADR-055 Cut-WASM Slice 4 (docs) @ `bed2ea08` (chore/cut-wasm-docs, worktree cut-wasm-4) — GO-WITH-CHANGES

Doc-only, 19 files +108/-354. Final slice of ADR-055 (supersedes ADR-034): browser = remote thin client to server-side scp-node; 3 bridges (PyO3/UniFFI/NAPI). Builds on Slice 1 (`1a3b41a5e` #1934, deleted scp-ffi/wasm crate + marked ADR-034 AND ADR-022 Superseded-by-ADR-055) and ADR-056 ctxid commit (`191ae8fc8` #1935).

**Two critical guards BOTH HELD:**
- §9.9.3/§9.8.2/§7.3.1 GUARD: `git diff bed2ea08~1 bed2ea08 -- .docs/specs/09-security-model.md .docs/specs/07-trust-validation-and-capabilities.md` = EMPTY. Convergence/equivocation language untouched. (Note: those convergence paragraphs were already NATIVE↔NATIVE post-Slice-1, not native↔wasm.)
- §23 RE-POINT correct: export-digest "reference implementation" repointed from deleted WASM `manager.rs::wasm_export_snapshot_digest` → `ContextExport::canonical_snapshot_hash` in scp-runtime/src/context/export_import.rs:351 (used by create_export@847). Verified fn body = SHA-256(CONTEXT_EXPORT_DOMAIN_SEPARATOR || scope.tag_byte() || jcs::to_vec(snapshot)) then Ed25519. ALL normative reqs survive (domain-sep, JCS/RFC8785, scope-tag byte, Ed25519, creator_did signer, verify-before-restore, exporter==creator). §23 ALSO correctly dropped the now-moot cross-family/dual-version-counter/cross-implementation-import-out-of-scope paragraphs (single engine now, ADR-055) — that's correct simplification, no normative loss.

**Over-removal check CLEAN (coder left these deliberately, correct):** webtransport transport (scp-transport/src/webtransport/* stays; only the deleted scp-ffi/wasm/src/transport.rs file-list entry removed from transport-expansion PRD); scp-protocol wasm32-compile-safety (architecture.md:253/663 "compiles for wasm32" + 10-infra:877 cfg(target_arch=wasm32) PRESERVED); §05:192 "Statically deployed (WASM, container)" deployment-artifact hashing PRESERVED (generic, not the FFI bridge).

**Matrix:** 38 deletions (32 wasm-mentioning + 6 paired JSON-structure rewrites), NO boolean capability flips (only a `"swift": true,`→`"swift": true` trailing-comma artifact). validate-prd.py PASS (13 files/367 stories), check-sdk-coverage.py PASS. Deleted WASM stories SCP-079/SCP-218 have zero surviving refs (no dangling forward deps).

**Item 5 RESOLVED (task premise stale):** ADR-022 ("Dual-Target Architecture") was ALREADY marked "Superseded by ADR-055 (2026-06-29)" with a full historical-record note in Slice 1 (`1a3b41a5e`), NOT left unedited. Not in this commit's diff. No action.

**FINDING (GO-WITH-CHANGES, 1 item):** `.docs/specs/20-licensing.md:69` — the AGPL/Apache crate-license diagram still lists `scp-ffi (PyO3, UniFFI, napi, wasm)`. The `wasm` crate (scp-ffi-wasm) was DELETED in Slice 1 (crates/scp-ffi/wasm confirmed gone; not in workspace Cargo.toml). 20-licensing.md was NOT touched by this commit — a missed scrub site in the "clean WASM-as-live-bridge from normative specs" slice. Fix: `scp-ffi (PyO3, UniFFI, napi)`. Non-blocking (licensing-diagram cosmetic, doesn't affect copyleft boundary logic) but in-scope for this slice's stated goal.

**Two acceptable residuals (NOT this slice's scope, leave):** 11-prior-art.md:384 "runs in browsers via WASM" (prior-art prose about the broad WASM-in-browser concept, not the SCP FFI bridge — arguably now imprecise but it's comparative-prose, defensible); 25-test-vectors.md:363 "native↔WASM unification Amendment" (HISTORICAL NAME of the ADR-011 EventType-taxonomy amendment — a proper-noun provenance ref to a past amendment, must NOT be rewritten or it breaks the amendment's identity).

LESSON: a multi-slice "scrub X from all normative docs" job — the LAST slice must re-grep the WHOLE normative corpus for X, not just the files it edits; a license/crate-inventory table (20-licensing.md) is an easy miss because it's not "WASM-bridge language," it's a crate list that happens to name the deleted crate. Re-grep `wasm` across specs/standards/architecture/scaffold excluding {wasm32, target_arch, deployment-artifact hashing, webtransport, ADR-034/055 refs, historical-amendment proper nouns} to find genuine stragglers.
