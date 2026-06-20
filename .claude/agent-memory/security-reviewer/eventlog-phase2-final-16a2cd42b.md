# Event-Log Phase-2 Substrate Swap — Final State (16a2cd42b) -- 2026-06-20

Re-review of 3 commits added since the CLEAN bfa5baf73 pass:
88c856360 (committer-assigned leaf timestamps), bf9266777 (convergent deadline
bases), 16a2cd42b (shared merge_consequence_events + removed unsigned
ContextExport.merkle_root mirror).

## HIGH — notification-window backdating regression (bf9266777)
- execute_set_economic_policy / execute_modify_ceiling now compute
  `effective_at = proposal.created_at + NOTIFICATION_PERIOD` (governance_helpers.rs
  ~1386 ceiling, ~2483 econ-policy). `created_at` = `context.now` set by the
  PROPOSER at proposal build (scp-protocol governance/mod.rs:1594). Signature-bound
  (tamper-evident vs third parties) but PROPOSER-CHOSEN — proposer can backdate it.
- `is_effective` (state.rs:295) is bare `now >= effective_at`, no lower clamp.
  Backdating `created_at` by >= PERIOD makes effective_at <= commit time ->
  pending change applies on first tick -> 24h window collapses.
- §19 (specs/19 L297) MUST: econ-policy "MUST NOT take effect sooner than 24 hours
  after the EconomicPolicyChanged event is committed to the EVENT LOG" (commit-anchored,
  NOT created_at). Phase-2 breaks this MUST. Ceiling = same pattern, security-boundary change.
- PRE-PHASE-2 (origin/main governance_helpers L1243/L2214): effective_at = now()+PERIOD
  using the APPLYING member's local clock (proposer cannot influence). => GENUINE NEW REGRESSION,
  introduced for cross-member convergence.
- FIX: anchor on a value that's BOTH convergent AND not unilaterally backdatable:
  effective_at = max(proposal.created_at, convergent_commit_time) + PERIOD, or clamp.
  Pure signing of created_at is insufficient (proposer signs their own backdated value).

## Verified CLEAN
- Removed unsigned ContextExport.merkle_root mirror (16a2cd42b): step-5 signed-snapshot
  binding (recompute + ct_eq vs SIGNED event_log_merkle_root) is sole authority. NO orphan
  reader anywhere (grep: all remaining merkle_root refs are the SIGNED field, checkpoint
  structs, or tree::root recompute). ContextExport built only in export_import.rs producer+tests.
  Removal is neutral-or-stronger (no unsigned root field left to be tempted to trust).
  verify_merkle_chain renamed recompute_event_log_root; truncation/substitute/tamper tests retained.
- Committer-assigned leaf timestamp (88c856360): receive path threads inner.timestamp/1000;
  inner.timestamp is IN the signed preimage (envelope/inner/mod.rs:554 CanonicalField::U64).
  Convergent-by-copy. Worst case = self-asserted leaf timestamp, same as the envelope already
  self-asserts pre-change. No new authz/audit trust dependency. NOT a regression.
- TTL creation_timestamp_secs = creator's clock at create (lifecycle_helpers 1756/2204). Creator
  already controls params.ttl + own context lifetime; not a cross-member boundary. Honestly
  annotated that restore/import arm locally (signed snapshot lacks convergent creation time yet).
- Freeze freeze_start = max(created_at_a, created_at_b): liveness safety valve (deadlock), not
  authz; needs two conflicting signed proposals. Shares created_at-backdating root but low impact.
- Equivocation in-memory dedup unchanged from prior pass; #1845 false-positive PRE-EXISTING,
  Phase-2 does not worsen. Removed MessageReceived/EquivocationDetected appends = buffer-only,
  no durable leaf any authz check depended on.

## Net
ONE HIGH (econ-policy/ceiling notification backdating). Everything else clean.
Export integrity stronger. Not double-zero until the HIGH is fixed or spec amended.
