# Slice 3 consequence-window (PR #1859, HEAD c6903ecc4) — RE-ATTACK: only documented #1861 limitation remains

Diff 1f1ea7cd2..HEAD: `evaluate_consequence_rules` gains a `convergent_now` param.
`event_log_entries_for_consequences` now returns `(merged, convergent_now)` where
`convergent_now = max ts over RAW Source-1 log entries` (pre-merge/pre-projection).
Window anchor splits on `is_convergent_trigger`: convergent (WarningCount/Custom) -> convergent_now;
non-convergent (MessageVelocity/ToolRateExceeded) -> local now. WASM mirrors (max over event_log_events()).

## Verified SOUND (no NEW chain beyond documented #1861):
- **Empty-log `now` fallback**: convergent triggers match ONLY EventType::GovernanceAction (matches_trigger
  l.1385-1397). GovernanceAction comes EXCLUSIVELY from Source-1 (merge buffer arm only mints MessageSent,
  l.860-864). Empty/non-governance log => zero convergent evidence => anchor irrelevant. Fallback sound.
- **Participation-discard paths** (post_join_bookkeeping, actor_check_proposer_eligibility,
  finalize_governance_action participation block): compute_participation_record takes `computed_at` but
  NO window anchor — ingests whole merged set, no `[anchor-window,anchor]` filter. Discarding `_convergent_now` sound.
- **Tuple threading**: all 8 consequence-eval callers thread convergent_now from the SAME
  event_log_entries_for_consequences call that produced events. finalize_governance_action shares ONE anchor
  across proposer+target. Periodic sweep shares ONE anchor across all members. Path-independent => convergent.
- **Durable leaf bytes**: leaf ts = convergent_consequence_timestamp(evidence) (governance_logic l.333/375/413),
  payload = (member_did,rule_index,trigger_kind,action_type). NO `now`/`convergent_now` in leaf. For convergent
  triggers window_anchor=convergent_now so evidence set is fully `now`-independent => leaf converges.
- **WASM/native parity**: both max over RAW full stored event set (native provider entries() / WASM
  event_log.events()), pre-projection. Identical computation.
- **Anchor is NOT non-privileged-forgeable** (defends disclosure's "admin/quorum-gated" claim):
  convergent_now = max over ALL raw leaf types, but checked every durable append's ts source:
  - governance leaves (dispatch_governance_action l.3967): `proposal.created_at` = proposer-chosen, signed,
    NOT clock-bounded = the DOCUMENTED limitation. admin/quorum-gated. ACCURATE.
  - MemberJoined/Left/Role local-commit (lifecycle_helpers l.674/865): `deps.clock.now_secs()` HONEST processor clock.
  - broadcast subscribe/unsubscribe (broadcast_helpers l.112/172): doc comment says "subscriber's signed
    subscribe-request timestamp" (aspirational/forward-looking) BUT as-built the bridges
    (scp-ffi/src/context.rs l.4071, napi, uniffi) inject LOCAL `SystemTime::now()` into payload.timestamp —
    NOT wire-carried created_at. So broadcast join/leave anchor = local honest clock today. No non-quorum forgery.
  => Only governance `created_at` is attacker-movable. Disclosure framing accurate.
- Disclosure (governance_logic.rs l.643-661) NOW covers BOTH directions (amplification + suppression),
  matching c6903ecc4. Accurate + complete for the known limitation.

## Pre-existing residual NOTED (not introduced by this slice, untouched by diff):
- Cooldown gate (process_one_triggered_consequence l.197-201) keys on LOCAL `now`:
  `if now < cooldown_until[rule_index] { return }` SKIPS emit_consequence_triggered entirely => no durable leaf.
  cooldown_until recorded as `now + window` (l.287). This is local-clock-dependent CONTROL FLOW gating whether
  the durable leaf is minted — orthogonal to the window-anchor fix, on per-member-local mutable state (not in
  convergent log). Two honest members at skewed clocks / different eval histories could diverge on whether the
  leaf is minted at all. PRE-EXISTING (slice didn't touch it); only matters once cross-member leaf replication
  lands (currently dormant — see below). Worth folding into the same convergent-wall-clock RFC as #1861.

## Structural context (dormancy, pre-existing):
- Cross-member durable-leaf replication is DORMANT (messaging_helpers l.656-660, lifecycle_helpers l.858-864,
  dispatch_governance_action l.3964-66): membership/governance leaves are committer-appended-ONLY, NOT replicated.
  Each member's Source-1 log holds only leaves it itself committed. So convergent_now is locally-deterministic
  but cross-member convergence is conditional ("convergent-by-construction WHEN replication lands"). The slice
  pre-stages the anchor for that future. Not a new attack — same acknowledged dormancy.

## RE-CONFIRMED pass (2nd visit c6903ecc4) — anchor-forgery surface widened, still clean:
- convergent_now = max over RAW Source-1 leaves => checked EVERY durable leaf type's ts source, not just gov/member/broadcast:
  - ToolInvoked saga leaf (actor/handlers/saga.rs:1494) ts = receipt.timestamp_ms = recorded_timestamp_ms set in
    prepare_b (saga.rs:818) = `deps.clock.now_millis()` = TARGET ctx's OWN honest clock; caller's asserted_timestamp_ms
    (l.785) DELIBERATELY discarded. Leaf lands in + evaluated by same target ctx => no cross-context forward-dating.
    Same honest-clock class as MemberJoined/Left. NOT a new vector.
  - RecoveryEpochAdvanced (trust_recovery_helpers.rs:265) ts = deps.clock.now_secs() = committer/initiator honest clock.
  - Only attacker-movable leaf ts = governance proposal.created_at = the #1861 limitation. CONFIRMED exhaustive.
- WASM event_log_events() == native event_log_entries() == full scp_event_log::EventLog::events() (same backing set) => max can't diverge cross-impl.
- is_convergent_trigger (consequence.rs:143) UNCHANGED by diff, exhaustive match, no reclassification.

CONCLUSION: No NEW attack chain. Only the documented/tracked #1861 limitation remains; disclosure is accurate
and complete on both directions. One pre-existing cooldown-gate divergence worth noting for the same RFC.
