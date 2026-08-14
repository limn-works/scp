# ADR-051 Causal-DAG Application-Event Ordering — Security Review (2026-06-18)

VERDICT: APPROVE. Model + interim qualifications sound, honestly scoped, no findings.

## The model
- Canonical Merkle log = CONVERGENT events ONLY (MLS-commit-ordered: governance,
  membership, lifecycle, role, access, attestation, provenance, economic ACTIONS,
  compromise recovery, app-binding). Governing rule: a derived record is automatic
  AND convergent IFF its trigger INPUT is convergent.
- MessageSent / ToolInvoked = per-author application activity, per-author sequence,
  NO global order → diverge at equal count → EXCLUDED from canonical log in interim,
  surfaced as local ContextEvent. ADR-051 causal-DAG gives them convergent order
  (each event refs observed DAG heads; deterministic topo-sort, tie-break = leaf-hash
  ascending constant-time) → re-enter canonical log as convergent leaves.
- Two exclusion CATEGORIES (phase-2.md ADR-011 amendment): (1) permanent local signals
  MessageReceived/EquivocationDetected/PseudonymAnnounced (never EventType); (2) interim
  per-author MessageSent/ToolInvoked (canonical in ADR-051 end state).

## Why interim is NOT a regression
- Per-message non-repudiation is INDEPENDENT of Merkle membership: every message carries
  Ed25519 identity sig SHA256(context_id||sender_did||epoch||generation||sequence||
  timestamp||payload_hash||provenance_hash) (§9.8.1, 09-security-model.md:706). Travels
  with message regardless of log. Human-accountability tenet carried by sig+attestation
  chain, not Merkle anchoring of the log entry.
- Including per-author events in convergent log BEFORE convergent order exists would BREAK
  §9.9.3 (false-positive equivocation at equal count). Interim chooses "not yet anchored"
  over "anchored incorrectly" — correct ordering.
- Velocity-triggered consequences: durable-consequence invariant QUALIFIED (phase-2.md):
  convergent-triggered durable now; velocity-triggered fire locally (state + ContextEvent)
  no canonical leaf until ADR-051. Residual split-brain on VELOCITY enforcement only,
  honestly stated at §7.3.7.

## DAG attack surface — no new structural surface
- Forged head ref: edges are content hashes (backward-only). Can't forge edge to unseen
  content; dangling hash just excluded. Lying "later" only delays own events in tie-break.
- Relay reorder/withhold: order is pure fn of DAG not arrival → relay can't forge causal
  order, only delay convergence (§23.7 handles). Why relay-assigned seq was rejected.
- Equivocation: concurrent branches expected/linearized; true equivocation still surfaces
  under §9.9.3 once DAG is convergent substrate (extends coverage, doesn't weaken).
- Tie-break gaming: position is not a capability; leaf hash over signed full event.

## Observations (non-blocking, for ADR-051 impl program)
- EventType count: §25 Vector 32 now says 75-variant (was 76). VERIFY phase-2.md enum
  block + ADR-011 AC1 + actual scp_event_log enum all consistent before unification PR.
- ADR-051 impl story MUST make NORMATIVE: head-set count bound (DoS), reject-on-unknown-
  parent + reject-on-cycle (acyclicity "by construction" is impl-dependent otherwise),
  constant-time leaf-hash tie-break.
- POSITIVE: each weakened guarantee qualified AT ITS OWN SOURCE (§7.3.2/§7.3.7/§19.7/
  §9.9.3/ADR-011) w/ forward ptr to ADR-051 — keeps interim from silently becoming gap.
- EquivocationDetected durable accountability is retained convergently via
  RelayEquivocationViolation in ViolationStore (09:862), commit/governance-ordered.
