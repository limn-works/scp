---
name: issue-1845-commit-metadata-replication
description: Attack analysis of #1845 cross-member leaf replication via signed CommitMetadata — "trust asserted leaf" is unsound, must derive
metadata:
  type: project
---

# #1845 Cross-Member Leaf Replication (CommitMetadata) — UNSOUND DESIGN

**Verdict:** "Trust any MLS-authenticated member's asserted leaf {event_type, actor_did, payload, created_at, epoch}" inverts the §9.9.3 convergence property. Receivers MUST independently DERIVE each canonical leaf from the MLS-commit stream they already process — never copy a sender's assertion.

**Why:** §9.9.3 (`.docs/specs/09-security-model.md:823`) requires canonical log hold only events "every honest member DERIVES identically from the MLS-commit-ordered stream." Equivocation test = equal eventCount + different merkleRoot (`09:821`, MUST NOT loosen). An asserted leaf is a free variable the sender chooses, not a function of the stream.

**The codebase already documents the correct design and refuses the wrong one:**
- `messaging_helpers.rs:356,622,2374,2460,2582,2689` — six comments: "receiver-minted leaf is not sender-authenticated, would diverge honest roots."
- `run_buffered_post_delivery` (`messaging_helpers.rs:630`) has DORMANT `event_name=None`/`event_timestamp_secs` hooks awaiting this work — every caller passes None.
- `eventlog_convergence.rs:331-348` `#[ignore]`d `two_real_members_converge_pending_cross_member_replication` specifies correct design: "lets B reconstruct its log PURELY FROM those envelopes" (derivation, not assertion).

**Key fact:** Today receivers do NOT append governance/membership/lifecycle leaves — only committer does (logs non-convergent). #1845 fixes the gap the WRONG way (assertion-trust) instead of receiver-derivation.

## Attacks
- BLACK-1845-001 CRITICAL: Forged-leaf injection. A1 asserts AccessRevoked/MemberSuspended/GovernanceActionExecuted with actor_did != sender. Honest receivers append → permanent false accountability record + poisons tree::root + frames honest committer (committer's log lacks leaf → equal count diff root → §9.9.3 step 5 suspend_write/remove against the HONEST member). Real append sites gated by engine+capability: governance_helpers.rs:763 (MemberSuspended), :887 (AccessRevoked), :331 (ContextTombstoned). Replicated path has NONE.
- BLACK-1845-002 HIGH: dedup per-(sender,epoch,event_type) omits payload/actor_did → distinct-payload dups through (mutual false equivocation B vs C) AND blocks legit same-type leaves in one epoch → divergence. Unsound both directions. Only sound dedup is positional/derivation.
- BLACK-1845-003 HIGH: in-memory dedup (event_log.rs:197 Mutex<HashMap>) resets on restart (restore_event_log:347, TTL re-init). Relay stores+replays after victim restart → double-append → divergence vs peers. Also cross-context injection unless sig covers (context_id,epoch,leaf) AND receiver checks.
- BLACK-1845-004 MED-HIGH: import creation_timestamp_secs feeds deadlines (TTL = creation+ttl: actor/state.rs:776-789, ttl.rs:1095, commands.rs:2057). Backdating UNBOUNDED by future skew check → immediate force-close / elapsed cooldown. Branch already hardened import (commit b54eee5f9 non-backdatable window; lifecycle_helpers.rs:1786 re-pin) — #1845 must not reintroduce. Skew check insufficient (only future bound).
- BLACK-1845-005 MED: send-path drain (Option 1) → malicious committer withholds CommitMetadata after local append → divergence. Relay drops sidecar (no multi-relay/ACK req unlike MLS commits 09:876). Convergence depends on best-effort delivery of non-load-bearing msg = contradiction.

## Required fix
Replication = receiver-side derivation (engine output on inbound commit, byte-identical by construction). CommitMetadata at most a hint cross-checked vs own derivation, REJECT on mismatch (=sender equivocating). If not derivable → not convergent → route to ADR-051 DAG or local ContextEvent, never canonical prefix. New invariant: MLS send-auth does NOT authorize writing another member's canonical history.
