# Saga gating ADR-049 §3a (branch feat/actor-2c-saga-gating, supervisor.rs)

Per-participant-context-set saga reservation replaces instance-wide AtomicBool.
`reserved_saga_contexts: std::sync::Mutex<HashSet<String>>`. RAII `SagaSetReservation`
removes ids on Drop (every terminal incl NeedsRepair + panic-unwind).

## SOUND (cite)
- Supervisor wedge: BLOCKED. run_saga_fsm returns Result; NeedsRepair=>Err returns to
  start_saga so `_reservation` drops. No abort/panic in path. Drop is sync lock->remove.
- Mutex poison (#5): BLOCKED. Both lock sites (try_reserve_context_set ~4487, Drop ~7010)
  use `.unwrap_or_else(PoisonError::into_inner)`. Critical section panic-free (clone+insert).
- TOCTOU overlap (#2): BLOCKED. check+insert in ONE lock scope (significant_drop_tightening
  allow is deliberate). Per-variant set de-duped via HashSet (caller==target self-conflict avoided).
- Canonicalization: context_id is [u8;32] -> hex::encode (deterministic lowercase). No user
  string => no case ambiguity. StandingPairCreate uses "standing-"+hex matching actor key;
  Cross/Broadcast use raw hex. These are genuinely DIFFERENT contexts, not same-context-two-names.

## RESIDUAL GAPS
- CI gate launderable (#3, MEDIUM-as-future): NEG regex requires field NAME to start with
  `saga`. A guard named `inflight_guard: AtomicBool` (no saga prefix) PASSES the gate. Also
  `saga_inflight: Mutex<u8>` PASSES (u8 not in type list). P3 is token-only: a dead
  `reserved.contains(x)` + literal "SagaBusy"/"ActorBusy" strings satisfy P1/P2/P3 even with
  zero real gating. Proved both bypasses pass /tmp gatetest. Gate enforces presence-of-tokens,
  not that the wedge is absent by SEMANTICS as the header claims.
- No authz on start_saga context ids (#4, LOW-today): start_saga is pub on handle, no check
  on which context ids a saga may reserve. Today only live caller is handle.rs:811
  StandingPairCreate (id derived from DIDs, not attacker-chosen); Initiate* commands all
  ack_not_impl. Becomes real once Phase 2C wires attacker-influenced caller/target/host/
  broadcast context_ids -> griefing reservation of victim contexts.
