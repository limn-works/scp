---
name: eventlog-phase2-merge-1852-persona
description: Phase-2 event-log substrate merged with #1852 #agent-persona pipeline (merge 5df11a2ee, HEAD d6fb9d13b) — clean compose, APPROVED
metadata:
  type: project
---

PR #1850 Phase-2 event-log substrate swap, after merging origin/main (#1852 shared-DID #agent persona, ADR-039). Merge commit `5df11a2ee`; reviewed at HEAD `d6fb9d13b`. ARCHITECTURALLY SOUND — the two designs compose on disjoint planes.

**Why:** Alec needed confirmation the #agent-persona sender identity (#1852) and the convergent event-log actor_did (Phase-2) didn't create a seam problem.

**How to apply:** When reviewing future event-log or messaging changes on this branch, the persona/substrate separation below is the load-bearing invariant — re-verify it isn't violated.

Key findings (persona vs substrate are disjoint by construction):
- `signing_key_id` (#active/#agent) is an INNER-ENVELOPE verification-method selector only. It NEVER enters a Merkle-leaf identity. `MessageSent`/`MessageReceived` are per-author non-convergent events EXCLUDED from canonical log (§9.9.3 / ADR-051 §6), emitted as local ContextEvents keyed on `sender_did`, not persona.
- Substrate convergent leaves (saga CrossContextDivergenceMarker/CrossContextToolInvoked, membership, governance) are committer-appended with CONVERGENT committer-assigned timestamps (saga.rs:2107-2115 uses committed_timestamp_secs not now()); authenticity rides in the SIGNED payload, persona-independent.
- Receive-path typed-append channel is `None` for application traffic by design — #1852 receive resolution and substrate append never contend for the same leaf.

Merge resolution mechanics (all clean):
- `MessageSigner<'a>` enum (Active/Agent) added in supervisor/supervisor.rs — binds key+persona into ONE source of truth; `signing_key_id()` derived from same variant carrying `key()`. Re-exported via supervisor/mod.rs.
- Threading: SendMessagePayload.signing_key_id (commands.rs:153) → handlers/messaging.rs → messaging_helpers::send_message reconstructs MessageSigner (774-776) → build_encrypted_envelope single stamp+sign (183).
- `KeyResolver` widened to `Fn(&DID, SigningKeyId) -> Option<VerifyingKey>` (governance/mod.rs:88). All closures propagated; follow-up 118f3318c caught stragglers; zero 1-arg closures remain.
- `ContextEventLogProvider` trait (substrate's central seam) UNTOUCHED by merge.

ADR-049 intact: actor stores NO signing key — SigningKeyBytes arrives per-command, zeroizes on drop (pre-existing send-only pattern). #1852 only added co-traveling non-secret SigningKeyId selector. No new lock on read path, no new resident secret/shared state.

Honest in-code deferral (not a merge gap): run_buffered_post_delivery committer-copied timestamp marked "dormant — live only once cross-member leaf replication lands (ADR-051)" (messaging_helpers.rs:2725-2730).

Related: [[eventlog-unification-phase2-final]], [[eventlog-unification-phase2-substrate]], [[eventlog-unification-adr011]].
