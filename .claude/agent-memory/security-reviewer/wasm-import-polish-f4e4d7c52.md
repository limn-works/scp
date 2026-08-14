---
name: wasm-import-polish-f4e4d7c52
description: PR-2b #1900 WASM import final security pass (f4e4d7c52) — GO; forged-quorum + cap-before-resolve verified
metadata:
  type: project
---

# WASM Import Final Pass — f4e4d7c52 (#1900 PR-2b) — 2026-06-28 — GO

Commit: single-file `crates/scp-ffi/wasm/src/manager.rs` (+372/-79). Builds on 7e5f6cfb6 (forged-quorum invalidation) and f4e4d7c52-prior (member caps). This commit FINALIZES three things: (FIX A) approve/reject/withdraw/get_proposal report ACTUAL stored status via new `proposal_status_label`; (FIX B) `role_state.members` capped+per-DID-validated on import (was uncapped, only live add_member capped); (gate-before-resolve) `validate_imported_governance_and_member_sets` moved to run BEFORE `resolve_governance_config`.

**Why GO:** A validly-signed malicious snapshot CANNOT obtain unearned governance execution, and CANNOT cause unbounded import work.

## Verified facts (file:line @ f4e4d7c52)
- **No forged-quorum exec.** `rederive_imported_proposal_statuses` (manager.rs ~7960) runs UNCONDITIONALLY before `contexts.insert` (~7910), sets every `resolved_proposals` entry with `ProposalStatus::Approved` → `Invalidated{reason}` for ALL governance models. No `ingest_*` replay loop on import path (engine built only in live approve/reject endpoints). Snapshot carries proposals ONLY via `resolved_proposals_json` (struct @8374, no pending carrier); `import_context` sets `pending_proposals: HashMap::new()` (~7860). So execute gate's pending fallback can't hit an imported Approved proposal.
- **Execute gate sound.** `require_proposal_approved` (3805) requires `matches!(status, Some(Approved))` from resolved-or-pending; post-rederive no imported proposal is Approved. Canonical replay guard: `execute_governance_action` (3915) keys `executed_proposals` on `canonical_replay_key_for_tracked` (SHA-256 over context_id,proposer,JCS(action),created_at) NOT caller hex id; insert-before-dispatch + rollback-on-err. Imported honest executed proposals already in `executed_proposals` → cannot re-run.
- **Caps before resolve, every set, fail-closed.** `validate_imported_governance_and_member_sets` (1434) caps `role_state.members`, `eligible_voters`, `threshold_signers` at WASM_MEMBER_CAP + per-DID-validates, returns Err (CTX_2032) on over-cap. Called at import (7634) BEFORE `resolve_governance_config` (7660) which clones the same `snap.*` fields. Sole production import entry = `import_context` (7609); no bypass path (other from_snapshot = BroadcastContext only).
- **Envelope intact.** `deserialize_and_verify_envelope` (7405): version >= WASM_EXPORT_VERSION (else CTX_2094); `exporter_did == snapshot.creator_did` (else CTX_2093); empty-sig reject; `verify_snapshot_signature` resolves key from creator_did (#active→#agent) + `verify_strict` over JCS digest; HMAC defense-in-depth for self-imports. `validate_governance_model` re-run via `resolve_governance_config` (item C collapse: threshold-no-signers → single_admin; threshold==0 reject).

## FIX A status-reporting — checked for new exec exposure: NONE
- approve quorum branch unchanged (sets post_status, executes only on quorum-cross). New code only MOVES already-terminal non-Pending proposal pending→resolved + reports label. Reject path NEVER executes even when engine reports Approved (rejecter not executor) — test `pr2b_reject_past_deadline_reports_resolved_approved_status` asserts 0 executed leaves. Label is coarse lifecycle only (terminal reasons stay on stored proposal).

## Non-blocking (pre-existing / filed — DO NOT re-raise)
- #1926 reject-execute divergence; #1927 other-collection import caps (broadcast author_block_lists/subscribers/key_epochs, role_state.assignments, read_exclusion_list — 16MiB-bounded only, no dedicated cap).
