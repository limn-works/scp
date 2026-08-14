# classs-finalize: ClassSCell state_mut deletion + text-scanner retirement (Jun 2026)

CLEAN review — no real bugs. Staged diff on branch `classs-finalize`.

## What changed
- Deleted `ClassSCell::state_mut()` escape hatch + `DerefMut`-less cell is now the sole mutation boundary.
- Removed dead view accessors: `context_id_mut`, `created_at_mut`, `creation_timestamp_secs_mut` (ClassCMut), `revoked_spending_ucan_cids_mut` (GovernanceClassCMut) + their struct fields + destructure bindings.
- Privatized `PerContextState.class_s`, `GovernanceState.class_s`, `GovernanceState.revoked_spending_ucan_cids` from `pub(crate)` → `pub(in crate::context)`.
- Retired `scripts/check-class-s-fail-closed.sh` (deleted, 4354 lines) + removed its `class-s-fail-closed` CI job.
- Added test-module source lexer + bounded-whitelist tripwire `class_s_no_persist_mutator_whitelist_is_bounded`.

## Verified non-issues
- **No dangling refs:** all writers of removed accessors were dead scaffolding; reads flow through `Deref`. Both destructures in `ClassCMut::new` have `..` rest absorbing removed fields. No bound-and-unused. clippy -D warnings clean.
- **Privatization safe:** `store/context.rs` (crate::store, NOT crate::context) has its OWN same-named `revoked_spending_ucan_cids` on a separate snapshot struct — privatization doesn't reach it.
- **Lexer (code_only):** char-based (multi-byte § × → safe), handles raw/byte strings, char-vs-lifetime, nested block comments, \\-escapes. No char-index OOB. Indentation preserved per line.
- **Tripwire test PASSES.** KNOWN_SAFE len 6, PERSIST_MARKERS len 2 — match the literals. Real no-persist set = exactly KNOWN_SAFE.
- **CI:** no dangling `needs:`, YAML parses (43 jobs), deleted script unreferenced anywhere.

## GOTCHA for future validation
A naive whitelist-test simulation that slices method bodies by "next 4-space fn line" absorbs the NEXT method's leading doc-comment → false persist-marker hits (`ClassSCommitToken::new` substring-matches `..::new_for_test`; `persist_state_fail_closed` appears in `/// 2. ...` docs). The real `brace_bounded_body` strips comments via `code_only` FIRST. Must replicate comment-stripping to validate correctly. Best ground truth: just run the test.

## Honest limitations (by design, not defects)
- Persist-marker scan is presence-only: `ClassSCommitToken::new` clears `begin_class_s` even though minting≠persisting — sound because token is `#[must_use]` + Drop-guarded.
- Block-comment guard scans RAW block for 4-space `/*`: a future `///` doc literally containing `/*` would trip it (LOW, documented intent).
