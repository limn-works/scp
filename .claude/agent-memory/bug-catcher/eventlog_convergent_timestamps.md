# Event-log convergent leaf timestamps (commit 88c856360)

Architecture fact (load-bearing for any future timestamp/equivocation review):
The runtime canonical Merkle log is built LOCALLY PER MEMBER from each member's
own actions. Receivers do NOT re-append commit-ordered leaves: in
`messaging_helpers::deliver_incoming`, MLS Commit/Proposal messages return
`DeliverOutcome::Handled` BEFORE any canonical append (the inner-envelope
dispatch returns early). The only receive-path append is in
`run_buffered_post_delivery` (messaging_helpers.rs:656), gated on
`Some(event_name)`, which is ALWAYS `None` for current received traffic
(MessageReceived/PseudonymAnnounced are per-author/local). So no receiver
re-stamps with local now().

Consequence: cross-member convergence of membership / governance-proposal /
vote / lifecycle leaves is NOT achieved by independent appends — those leaves
are committer-local. This is a PRE-EXISTING architectural gap, not introduced by
the timestamp commit. The commit only makes the timestamp VALUE convergent for
the ONE class where multiple members independently execute and append the SAME
leaf: GovernanceActionExecuted + dispatch action leaves (proposal.created_at,
via finalize_governance_action / dispatch_governance_action ts=proposal.created_at)
and the durable consequence leaf (convergent_consequence_timestamp = max-by-
event_sequence evidence timestamp; shared scp_protocol helper; native + WASM use
same helper; event_sequence is unique so max_by_key tie-break is moot).

Residual / latent issues found (mostly pre-existing, not regressions):
1. Consequence durable leaf evidence WINDOW uses local `now`
   (`evaluate_consequence_rules`: window = [now-W, now]). Even with convergent
   Source-1 timestamps, an evidence event near a window edge can be in/out per
   member → different evidence set → different leaf ts. Pre-existing; deeper than
   this commit. MEDIUM if these leaves are ever compared cross-member.
2. TTL `ContextExpired` leaf ts = `ttl.timer.deadline_unix_secs`, set in
   spawn_ttl_timer / spawn_with_transport as `clock.now_secs() + duration`
   (LOCAL clock at spawn). Import path: deadline' = importer_now + (deadline -
   exporter_now) → drifts by import-time skew. Commit doc claims "every member
   holds identical value" — FALSE for the actor model. But TTL timer only spawned
   on creator (finalize_create) + import/restore, NOT on regular join, so in the
   common multi-member case only one member appends ContextExpired anyway
   (content gap, not ts divergence). LOW-MEDIUM, mostly architectural.
3. Deferred CeilingModified / economic-policy leaf ts = `pending.effective_at`,
   computed as `proposer_local_now + PERIOD` (governance_helpers.rs:1364, 2449),
   NOT `proposal.created_at + PERIOD`. So not reconstructible convergently by
   other members from the proposal. Commit calls it "deterministic across
   members" — only true if the pending record is shared, not recomputed. Local-
   only append today, so no active divergent root. LOW (doctrine inconsistency).
4. ContextCreated leaf ts (builder.rs:838, creation_timestamp_secs from
   lifecycle_helpers.rs:1147 clock.now_secs()) is a SEPARATE clock read from
   PerContextState.created_at (lifecycle_helpers.rs:1189). Two values can differ
   by a tick on the creator. created_at feeds snapshots not leaves, so harmless.
   Creator-only append → OK. LOW/cosmetic.

Correct / verified-good:
- MerkleEventLogProvider (providers/event_log.rs:671) is the only persisting
  impl; SystemTime::now() removed, uses passed timestamp. FFI providers are
  NoOp. builder.rs default trait impls thread timestamp_secs through.
- Receive path ms->s: msg.inner.timestamp / 1000 consistently (messaging_helpers
  2248/2329/2446/2547). inner.timestamp = sender clock.now_millis() (line 165).
- WASM append_log_event stores timestamp_secs directly (seconds); proposal
  created_at = now_secs (seconds) on both native+WASM → unit-consistent.
- WASM GovernanceActionExecuted uses proposal_created_at from pending/resolved
  proposals (manager.rs:2833). map_or(0,...) fallback could yield 0 if proposal
  absent — only divergent vs native if native sources non-zero for a direct
  (no-stored-proposal) execution. Worth a targeted check if such a path exists.
</content>
</invoke>
