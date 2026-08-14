---
name: hollow-stub-audit-2026-08
description: Forensic audit of "hollow production implementations" (Phase-5 stub class) — method, the stale-checkout trap, and the confirmed hit-list on origin/main
metadata:
  type: project
---

# Hollow-production-stub audit (2026-08, origin/main 0cdeb635f)

Goal: current list of code that COMPILES + returns success but the claimed effect is a no-op on a production path (nullifier/dev-stand-in class CLAUDE.md forbids). NOT todo!()/unimplemented!() (grep ~0).

## CRITICAL PROCESS LESSON — verify against origin/main, not the local checkout
**Why:** The local working checkout was **164 commits STALE** vs origin/main (HEAD 1620de983 vs origin/main 0cdeb635f; `git rev-list --left-right --count origin/main...HEAD` = 164 3). EVERY finding-bearing file differed (supervisor.rs +23k/-9k, provider.rs, governance_helpers +2.5k/-1k). A first pass of 5 cluster agents read the stale tree and produced partially-wrong classifications (esp. AddMember). Additionally `governance_helpers.rs` had a large STAGED uncommitted WIP (+2500/-1053) that diverged from BOTH local HEAD and was ≈origin/main — reading the working tree silently mixed three states.
**How to apply:** For any "audit current origin/main" task: FIRST `git rev-list --left-right --count origin/main...HEAD`. If nonzero, `git worktree add --detach <scratch> origin/main` and point all agents at that path. The Read tool reads the working tree (local HEAD + staged), NOT origin/main. This mirrors CLAUDE.md's orchestrator rule "verify against the PUSHED REMOTE branch (git show origin/branch:file)."

## Method
5 clusters, each: locate symbol → read body + ALL callers → classify a) STILL-HOLLOW b) NOW-WIRED c) HONESTLY-ABSENT (fails closed, acceptable) d) TEST-ONLY. For handler fns, caller analysis is decisive: zero non-test callers = hollow even if body correct.

## Confirmed on origin/main (independently by me, before agent re-run finished)
- `identity_execute_recovery` (crates/scp-ffi/src/identity.rs:2535, backend 2588-2628; + napi scp.rs, uniffi bridge.rs): installs `FfiRecoveryBackend`/`NapiRecoveryBackend` where every step (mls_update/revoke_ucans/rotate_key_packages → Ok(()); notify_contacts/rotate_psk → true) is a no-op, then returns success JSON claiming "runs the 6-step §9.12 recovery protocol." SECURITY, fail-OPEN. napi doc lie: "real backends are injected via the SDK wrapper" — no injection point exists. Same pattern: identity_execute_custody_migration. Real ProductionRecoveryBackend exists (recovery.rs) but referenced only in tests. NO issue filed (#1439 covers only social recovery).
- §9.16/§9.17 key distribution: `handle_sender_key_request` has ZERO production callers (all cfg(test)/scp-testing); production inbound `decrypt_and_dispatch` only handles push KeyResponse. "recover via SenderKeyRequest" comments in governance_helpers/lifecycle_helpers promise a responder that doesn't exist. (#2049)

## FINAL origin/main (0cdeb635f) verdicts (re-run against worktree)
SECURITY / fail-OPEN false-success (highest priority):
- identity_execute_recovery no-op backend (identity.rs:2588 / napi scp.rs:1188 / uniffi bridge.rs:17379) — CRITICAL, NO issue. Real ProductionRecoveryBackend (recovery.rs:892) exists but test-only, bypassed.
- §9.12 recovery revoke_ucans synthetic marker "recovery:{ctx}:scopes=...:before=" never merged, sets ucan_revoked=true (recovery.rs:965-1016) — HIGH, #2069.
- event_log_verify proves over disjoint near-empty tree → false verified:true absence/inclusion (PyO3 event_log.rs:586/640 + UniFFI bridge.rs:15026/15097) — HIGH, #1933.
- MCP resources/subscribe returns Ok + advertises subscribe:true, wired to nothing (PyO3 mcp.rs:1191, UniFFI bridge.rs:5327; NAPI honestly Errs) — HIGH, #1341.
- Welcome-join installs stale genesis params (supervisor.rs build_welcome_joiner_state ~14095); lowered-ceiling → joiner gets higher genesis ceiling — SECURITY, #2028.
Capability-absent / fail-CLOSED (dead but honest, mostly commented):
- §9.16.1 wrapping-key publication unwired: Supervisor::set_wrapping_keys zero prod callers → every prod KP wrapping_pubkey=None → distribute_sender_key no-op (state.rs:2830). ROOT CAUSE. CRITICAL-capability, #2032.
- CONSEQUENCE: multi-member encrypted messaging never completes e2e in prod — added member joins MLS but never gets peers' sender key → ContextCryptoState::open fails "sender key lookup failed" (state.rs:1921). Tests green only because scp-testing/fullstack/node.rs manually does set_wrapping_keys + key dances.
- §9.16 pull: responder NOW wired (decrypt_and_dispatch→handle_sender_key_request messaging_helpers.rs:3156) but INITIATOR request_sender_key zero prod callers → never fires. HIGH, #2049(partial).
- §9.16.2 block-list empty hardcoded (messaging_helpers.rs:3154). #2146.
- §9.17 access-key both dirs unwired; inviter stores locally only, false comment "via Welcome payload/out-of-band" (lifecycle_helpers.rs:1377). HIGH, #2050/#2051.
- §19.5 UCAN max_total window unenforced (BudgetTracker test-only); governance MemberBudgetTracker IS enforced. #2070.
- Spending-UCAN revocation set never populated (no RevokeSpending action). #2072.
- Event-log leaves unsigned (event_log.rs:101) + non-convergent (receive-side replication dormant, event_name always None). #1845.
- Genesis params.outlets dropped (state.rs:1935 registered_outlets:Vec::new()) → genesis outlets uninvokable (13016). #2020.
- Economy FFI economy_budget_grant unauth + disconnected DashMap (economy.rs:280). #1667.
- Metadata-routing publish dormant #2080/#1760; webhook register test-only #2079/#1764; governed-context invites InvalidState #2027; payment_history in-mem ring #2082; per-ctx msg-pricing escalation always spec_default #2081; Sybil IdentityDepthAssessment external signals always empty #1619/#1620.
FIXED since stale checkout (verify before re-flagging): custody_migration now fails-closed NotConfiguredMigrationBackend; InMemoryPreRotationCustody now testing-gated + G1 shipped-feature-graph enforced; device attestation typed IDENT_1016 (#2171); GovernanceAction::AddMember NOW functional via Supervisor::invite_member (supervisor.rs:13017, FFI-exposed all 3 bridges) for SingleAdmin encrypted ctx — generic path fails closed (#2029 largely closed).
HONEST FALSE-COMMENT (not hollow, but scar-tissue to correct): OutletRateExceeded "cannot fire today" comment (consequence.rs:92) is FALSE — trigger IS live for streaming outlets (OutletInvoked leaf lands via ActorOutletInvokedEventSink).

## Pending origin/main re-verification (superseded by FINAL above)
Cross-ref filed issues: recovery=NONE; max_total=#2070; spend-revocation=#2068/69/72; §9.12 revoke marker=#2069; payment persist=#2082; msg pricing=#2081; economy FFI auth=#1667; sender-key pull=#2049; block-list=#2146; access-key=#2050/51; wrapping-key=#2032; AddMember=#2029; event-log convergence=#1845; event_log_verify=#1933; metadata-routing=#2080/#1760; webhook=#2079/#1764; genesis tools=#2020; stale join params=#2028.
