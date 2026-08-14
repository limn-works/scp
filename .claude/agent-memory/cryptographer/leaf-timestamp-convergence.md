# Convergent Committer-Assigned Leaf Timestamps (commit 88c856360, spec 2ecfa23fb)

Fix: replace per-member `SystemTime::now()` on the RFC-6962 leaf timestamp with
committer-assigned values. Leaf = SHA-256(0x00 || rmp_serde(Event)); Event has 7
fields (event_type, actor_did, timestamp, sequence, payload, prev_hash, signature).
signature=empty Vec (deterministic), sequence/prev_hash convergent inductively.
serialize_event_for_hashing = full rmp_serde(Event) incl signature (tree.rs:277).

## Timestamp source taxonomy (by convergence strength)

STRONG (signed, tamper-evident, cross-member identical):
- Governance leaves: `proposal.created_at`. dispatch_governance_action runs on every
  member; created_at is bound into proposal_id (compute_proposal_id line 129 hashes
  timestamp), proposal_id bound into vote sigs (compute_vote_hash line 165). A
  Byzantine relay CANNOT fork created_at per-recipient without invalidating votes.
- Conflict/tombstone: proposal.created_at / migration.grace_period_end (convergent
  signed sources).
- Receive path: msg.inner.timestamp/1000 (signed envelope created_at). BUT the
  receive append channel is DEAD: deliver_plaintext_or_announcement returns None for
  ALL 3 arms (messaging_helpers.rs:388/404), so msg.inner.timestamp/1000 is never
  used in prod (only flows to dead Some(event_name) branch).

WEAK (local clock of acting member; convergent ONLY if that exact value reaches
other members via signed envelope AND they copy it — but receive append is dead, so
these leaves are appended ONLY by the acting member, never replicated):
- Membership/lifecycle: join/leave/close/create use deps.clock.now_secs() (native)
  and crate::time::now_secs() (WASM). Comment claims = created_at on outgoing commit.
- Commit-retry lifecycle leaf: governance.rs:1064 uses local `now`.

RESIDUAL NON-CONVERGENT BASE (timer deadlines computed from local now()):
- TTL ContextExpired: expiry_deadline_secs = self.clock.now_secs() + duration
  (ttl.rs:1092-1093). Base now_secs is the ARM-TIME local clock of each member. Two
  members arming the timer at different local times -> different deadline -> divergent
  ContextExpired leaf. Spec §7.3.1 says deadline must come from "convergent context
  state"; impl derives from local now(). Fixable via creation_time + ttl_duration but
  creation_time not stored convergently.
- GovernanceFreezeExpired: freeze_start + FREEZE_TIMEOUT_SECONDS, but freeze_start =
  deps.clock.now_secs() at conflict-detect time (governance_helpers.rs:545,579).
  Per-member-local base -> divergent freeze-expiry leaf. Could derive from
  max(proposal_a.created_at, proposal_b.created_at).

## convergent_consequence_timestamp (consequence.rs:160, governance_logic.rs:51)
max_by_key(event_sequence).map_or(0, timestamp). SOUND: event_sequence is unique per
commit-ordered leaf -> unique max, no tie ambiguity. Empty evidence -> 0 (only
non-convergent-trigger consequences are evidence-less, and those never mint a durable
leaf). BUT evidence SET depends on evaluate_consequence_rules `now` (per-member local
time-window filter event.timestamp in [now-window, now]). Two members at different
`now` could derive different evidence sets -> different max-seq -> different ts. This
is a pre-existing property of consequence minting (whether/which leaf), inherited.

## Architectural caveat (NOT introduced by this commit)
Runtime event log is NOT replicated across members on commit receipt (receive append
dead). Full convergent replication is the in-flight ADR-011/ADR-051 unification (see
finding_runtime_eventlog_not_rfc6962). So cross-member divergence of WEAK/RESIDUAL
leaves is latent, not active. This commit is a strict improvement (removes fresh
now() at fire/append time) and matches spec intent for the STRONG class. The WEAK +
RESIDUAL classes are an incomplete realization of the spec's "convergent value" rule.

## Tests
eventlog_convergence.rs + wasm_conformance.rs: positive (skew ignored -> converge) +
negative control (per-member-local stamping -> diverge) on native and cross-impl.
Cross-impl byte-parity test covers GovernanceActionExecuted (STRONG path, ts=
1_700_000_000 fixed). NO cross-impl test for membership leaves where native uses
deps.clock.now_secs() and WASM uses crate::time::now_secs() (WEAK path).
