# PR2b WASM Governance Engine Adoption (commit f4e4d7c52) — Final Adversarial Pass

Branch wasm/1900-pr2b-engine-adoption. WASM bridge adopts shared scp-protocol
governance engines (Threshold/Majority/Unanimity) via keyless TrustedVoteIngest
+ transient per-op engine. Single file: crates/scp-ffi/wasm/src/manager.rs.

## Verdict: GO (held against real effort; all probe tests pass on host)

## Attack surfaces probed — ALL CLOSED
- Forged-import quorum: import forces every imported Approved proposal ->
  Invalidated unconditionally (rederive_imported_proposal_statuses ~7983).
  Execute requires Approved (require_proposal_approved ~3816). pending_proposals
  is HashMap::new() on import (7866) — pending not imported, can't resurrect.
- Frozen denominator: engine denominator = eligible_voter_dids/signers frozen at
  engine::new from ctx fields, NEVER live members. members left empty in
  governance_context_for_engine.
- threshold==0 / threshold>signers: rejected in resolve_governance_config (419)
  AND ThresholdEngine::new (multisig.rs:91). Import re-resolves from untrusted
  snapshot (import_context 7670).
- Canonical replay: execute keys replay on canonical compute_proposal_id, not
  caller hex — fresh-hex double-execute blocked (~5357).
- ingest_proposal: proposer-in-frozen-set + dup-id + is_terminal/is_pending
  guards. Stores status verbatim but WASM only seeds from own pending (Pending).
- Majority 5000 bps pinned: native state.rs:1771 == WASM manager.rs:5439.
  Below-quorum past-deadline -> Rejected{InsufficientParticipation} (275).
- Non-eligible proposer blocked at engine, no stranding (my probe).

## Tests run on host
- 15 pr2b_* PASS + 4 custom bh_probe_* PASS.

## Pre-existing (filed, NOT new): #1926 reject->Approved executes native not WASM;
#1927 other imported collections uncapped. Capped: members/eligible_voters/
threshold_signers/nonces/executed_proposals/resolved_proposals_json.
