---
name: pr2234-kea-failclosed-432691d70
description: PR #2234 @432691d70 (fix/rotate-content-keys-review-followup) alignment review pass 1 — KEA best-effort→fail-closed + §5.14.8 spec back-fill. 1 BLOCKER, 3 HIGH.
metadata:
  type: project
---

# PR #2234 @ `432691d70` — alignment review pass 1 (2026-08-03)

Branch `fix/rotate-content-keys-review-followup`, 10 commits over `origin/main`.
Fast-follow to PR #2218 / issue #1847. Verdict: **NEEDS DISCUSSION** (1 blocker).

## BLOCKER — fail-closed KEA + executed-marker rollback = re-executable governance action

`execute_governance_action` (governance_helpers.rs ~5680) explicitly **removes the
`executed_proposals` replay marker on dispatch failure "so the proposal can be retried."**
Both `execute_revoke` and `execute_rotate_content_keys` destructure `CommitMeta { pid: _ }`
— **no idempotence guard**. The Class-S key rotation persists fail-closed *before* the leaf
loop. So a KEA append failure at author k of n now yields: keys rotated + persisted,
`ContentKeysRotated`/`AccessRevoked` leaf durable, KEA leaves 1..k-1 durable, `Err`, marker
rolled back → a retry re-rotates **every** author (epoch +2) and appends a **second full leaf
set**. Pre-PR that retry was unreachable (the loop swallowed and returned `Ok`). Net: the
change converts a bounded one-leaf log gap into unbounded state+log divergence. What ADR-011
convergence actually needs is **atomic all-or-nothing durability of the whole fan-out**, not
error propagation mid-loop.

## Answers to the two routed questions

**(1) Is the ADR-011 convergence doctrine real?** YES, and pre-existing — not invented here.
ADR-011 lives in `.docs/adrs/phase-2.md` §"ADR-011: Verifiable Event Log", **Status: Decided**
(no unsettled-upstream blocker). Its native↔WASM amendment states verbatim: *"a derived record
is automatic **and** convergent iff its trigger input is convergent"* and *"The log therefore
MUST contain **only convergent events**."* Already applied at `governance_logic.rs`
`enforce_triggered_consequences` (durability gated on `is_convergent_trigger`).
BUT: that is a **classification** rule (does the leaf belong in the log), not an
**error-handling** rule. "Convergent ⇒ propagate the append error" is a downstream inference
made in a code commit, never stated upstream. KEA was best-effort by inheritance from the
`MemberBlocked` pattern, not by a traceable deliberate decision.

**(2) Is the §5.14.8 spec edit a back-fill?** YES — proven by commit ordering:
- `46be0780f` adds a **new normative** §5.14.8 RotateContentKeys paragraph (§5.14.10 "Event Log"
  does NOT prescribe KEA-on-RotateContentKeys — only introduces the type; so this is new
  content, not a restatement) describing code that already shipped in #2218/#1847, and plants a
  `TODO(spec)` marking the convergence tier as an **open question** (`§2033 vs §5.14.10/ADR-011`).
- `e0f82544c` **resolves that open spec question from downstream**: same commit changes the code
  to fail-closed, rewrites the spec sentence to say "fail-closed per ADR-011", deletes the TODO.
- `e2f703eb3` propagates the new wording to the ban-path clauses for internal consistency.
The spec cannot be the upstream authority for the code — it was authored from it.
(`§2033`/`§2008`/`§2015` were 05-contexts.md **line numbers** cited as section numbers; the PR
correctly replaces them with real §5.14.8/§5.14.10 refs and leaves no residue.)

## Other findings
- **HIGH** counter tests don't lock the fix: `block_broadcast_subscriber_counter` et al. assert
  event-log **leaf-count** deltas (already correct on main); the counter (1→2) is never read.
  All pass against pre-fix code. The stated excuse "the counter is internal to the actor" is
  false — `class_s.rs:~7073` asserts `cell.checkpoint_events_since` directly, and it rides
  `ContextSnapshot` (`manager_methods.rs:334`). No test exercises the new `Err` path at all.
- **MED** `governance_logic.rs::append_consequence_event` swallows append errors for
  *convergent* (`durable==true`) leaves and the caller bumps `checkpoint_events_since += 1`
  unconditionally → over-count on failure: the exact §9.9.3 drift this PR fixes elsewhere.
- **MED** invented premise in `broadcast_helpers.rs` ~731-742: calls the per-author block a
  "non-convergent trigger" to justify best-effort KEA — but then `MemberBlocked` on the *same*
  trigger is fail-closed and both still go into the canonical log, contradicting ADR-011's
  "only convergent events" MUST. Confidentiality is enforced by the block-state persist, not
  by an audit leaf.
- **LOW** `BroadcastKeyEpochAdvance.timestamp` documented as permanently unconsumed (residue
  kept, not deleted); new §5.14.8 clause filed under "Blocking" though its own text says it
  does not touch block lists.

## Clean / verified
`seed_broadcast_author` test seam is `#[cfg(feature = "testing")]` at all five layers
(Supervisor method, `BroadcastCommand` variant, dispatch arm, handler fn, `ClassCMut` method),
not FFI-exported → no dev stand-in on a production path. Determinism sorts by `author_did`
(`rotate_all_author_keys`, `governance_ban_subscriber`, `unsubscribe`) are correct and tested
without re-sorting. Block-path counter fix (2 leaves, 1 bump → 2 bumps) is a genuine bug fix.
Rebase-integration commit `432691d70` (bounded_reply_await per #2268 + rustdoc link repairs) is
correct.

Related: [[two-dot-diff-stale-base-trap]]
