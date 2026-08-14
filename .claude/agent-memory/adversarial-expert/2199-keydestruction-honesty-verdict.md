---
name: 2199-keydestruction-honesty-verdict
description: Audit verdict for SCP #2199 — KeyDestructionAttestation destroyed-flag honesty fix (DisposalOutcome gating)
metadata:
  type: project
---

# SCP #2199 — KeyDestructionAttestation honesty fix — SHIP WITH CONDITIONS

Audited working tree (uncommitted) in worktree adr049-2199-attestation-gating. PR = 8 code
files ONLY (verified via merge-base ed80eab404); the large spec "deletions" in
`git diff origin/main` (09-security-model -111, 25-test-vectors -69, ADR-057) are origin/main
advancing PAST the branch point, NOT the PR. Branch needs rebase.

**What the PR does (genuine, not theater):**
- Deletes fabricated pre-disposal attestation build in uniffi/bridge.rs (built KeyDestructionAttestation
  with hardcoded true off ContextParams::default() fake scope, then discarded in a log line). That block
  issued NO real relay deletion (relay_urls/blob_ids always empty), so deletion loses nothing observable.
- `ContextCryptoState::dispose_secrets` / `PerContextState::dispose_secrets` now return `#[must_use]
  DisposalOutcome{mls_group_destroyed, sender_keys_destroyed}` — flags gated on PRE-disposal PRESENCE
  (mls_group.is_some(); sender_key.is_some() || !sender_key_store.is_empty()).
- destroy_group (scp-mls group.rs:991) is TOTAL: Ok or idempotent Err(GroupDestroyed), drops can't fail —
  so presence-gated true is sound ("released"). Caveat #82: Ed25519 signer FREED not ZEROIZED (pre-existing, documented).
- SenderKeyStore::is_empty() added; honest because remove() prunes empty inner maps (verified mod.rs:559).
- Real PRODUCTION attestation now built inline in ttl_close_helpers.rs:923 (finalize_close) from the
  observed dispose_secrets() return, passed directly — HONEST. Still log-only (tracing::info); event-log
  recording deferred to #2215. Correct order: kill the lie BEFORE wiring consumption.
- ttl.rs apply_ttl_terminal_transition gates STEP bits on observed outcome; None-crypto anomaly warns +
  leaves bits unset (honest incomplete) instead of fabricating completion.

**Tests are REAL (not theater):** seeded-encrypted golden test disposes a live MLS group + sender key
over the E2E join path, asserts both true + idempotent repeat false; empty→false; per-flag independence;
Broadcast N/A. present→true / absent→false actually proven.

**No build break:** builder.rs/supervisor:13847 bare dispose_secrets() calls are on OwnedMlsCryptoState
(provider.rs:393, returns ()), a DIFFERENT type — unaffected by the new must_use on ContextCryptoState/PerContextState.
**No retry-spin:** ExecuteTtlClose reply gated on has_failures() not is_complete(); None branch records no
error; bitmask carry-forward protects retry-after-success.

**Findings:**
- MEDIUM: DisposalOutcome has PUBLIC fields — doc claims "structurally unrepresentable" / "compile-enforced"
  but `DisposalOutcome{true,true}` is freely constructible anywhere (tests do exactly this). Honesty is
  CONVENTION at the one prod call site, not a type guarantee. Fix: private fields + private constructor in
  dispose_secrets so the documented claim becomes real (aligns with "enforce mechanically not docs" tenet).
- MEDIUM/LOW: CloseOrchestrator / KeyDestructionOrchestrator now have ZERO production callers (bridge deletion
  removed the only one). The disposal-param threading there is exercised ONLY by tests — dead code giving
  false confidence. Wire it or mark test-scaffold.
- LOW (pre-existing): mls_group_destroyed=true means "freed" not "zeroized" (#82).
- LOW: cross-path double-close (TTL then finalize) yields honest-but-confusing {false,false} attestation
  (material gone from earlier pass). Theoretical — paths mutually exclusive.
- Note: ADR-018 file not present in worktree .docs/adrs (referenced but absent) — provenance gap.
