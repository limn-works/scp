# #1900 PR-2b WASM governance engine adoption — STRUCTURAL BLOCKER (2026-06-28)

## Verdict: BLOCKED at plan item E. Plan's "transient engine + replay stored votes" is NOT implementable against the shared engine as it exists after PR-2a, without changing the shared engine (which the task forbids).

## Root cause
PR-2a (commit ad8f6e8a3) added ONLY a keyless **vote** path: `TrustedVoteIngest::ingest_approve`/`ingest_reject` on ThresholdEngine/MajorityVoteEngine/UnanimityEngine. It ingests a vote into a proposal the engine **already holds**.
- The engines' `proposals: HashMap<ProposalId, GovernanceProposal>` field is PRIVATE (multisig.rs:51, majority.rs:66, unanimity.rs:53, mod.rs:1668 SingleAdmin).
- The ONLY way a proposal enters that map is signed `propose(proposer, action, ctx, &SigningKey)` — which (a) needs a real Ed25519 SigningKey for the proposer, and (b) calls `(key_resolver)(proposer, Active)` then `verify_vote` (multisig.rs:368-380). WASM has NO signing key and NO real resolver (ADR-034 no-key custody). A no-op resolver returning a dummy key fails `verify_vote`.
- There is NO public keyless seed/insert/restore method on any engine (grep-confirmed). PR-2a did not add a keyless propose.
- `ingest_approve`/`ingest_reject` both start with `self.proposals.get(proposal_id)` → `ProposalNotFound` if the proposal isn't already in the engine.

## Why per-call replay can't work either
WASM stores proposals in its OWN `pending_proposals: HashMap<String, GovernanceProposal>` (manager.rs:453), NOT in an engine. To use the engine's tally per-call you'd build a transient engine and replay stored votes. But:
1. You cannot CREATE the proposal in the transient engine (no keyless propose) — replay is dead at step 0.
2. Even if you could seed via ingest, ingest RESOLVES after each vote (push_and_resolve → resolve_proposal), so replaying a threshold-met intermediate state resolves early and the new vote then hits `ProposalNotPending`. Terminal-status preservation (BLACK-04) is impossible through ingest.

## Native is different (why native works without this problem)
Native holds the engine PERSISTENTLY in PerContextState across the process lifetime; the engine IS the durable in-memory store. Native `propose`/`approve`/`reject` always have a real SigningKey + KeyResolver. On restore (state.rs:1859 restore_governance_engine_from_snapshot) native rebuilds an EMPTY engine and does NOT replay pending proposals — pending proposals do not survive persistence in native either. So native never needs a keyless seed.

## Minimal unblock options (all require a human decision; all touch the shared engine, which PR-2b forbids)
- **Opt 1 (smallest):** Add a keyless proposal-creation method to the `TrustedVoteIngest` trait (object-safe, additive, NOT on `GovernanceEngine` so native's signed path is unaffected): e.g. `fn ingest_proposal(&mut self, proposal: GovernanceProposal) -> Result<(), GovernanceError>` that inserts the caller-built (empty-sig) proposal into the engine's private map after validating proposer ∈ frozen set + no duplicate. Then WASM per-call: build transient engine → `ingest_proposal(stored_proposal_with_all_votes)` → `ingest_approve/reject(new_vote)` / `withdraw_vote`. This makes replay trivial AND preserves terminal status (insert the stored proposal verbatim, including its terminal status; ingest then returns ProposalNotPending correctly).
- **Opt 2:** Hold the engine persistently in WASM PerContextState (mirror native). Requires a keyless propose on the engine anyway (WASM has no key) + engine is not Serialize/Clone (KeyResolver is Arc<dyn Fn>) so export/import can't carry it — WASM would still need to rebuild+reseed on import, i.e. still needs Opt-1's seed method. Strictly larger than Opt 1.

## Recommendation
Reframe as PR-2a-bis (shared-engine change, ~30 lines + tests) adding the keyless `ingest_proposal` seed to `TrustedVoteIngest`, THEN PR-2b WASM adoption becomes mechanical and clean (build transient engine, ingest_proposal(stored), ingest_approve/reject or withdraw_vote, read status). Without that, PR-2b items E/F/G cannot be done correctly — any WASM-side workaround would re-implement the tally (the exact divergence PR-2b exists to delete) or silently mis-handle terminal/threshold-met states.

## Items that DO NOT depend on the engine seed (could be done independently if desired)
- A (frozen eligible-set state fields on PerContextState + snapshot), B (parse governanceSigners/Threshold/Voters/MinParticipationBps at create), C (collapse-to-single_admin on create+import, mirror context_params.rs:189-218), D (reject threshold_value==0 with non-empty signers), H (leaf byte-parity is already correct, untouched). These are pure WASM-side and don't need the engine. But E/F/G — the actual "adopt the shared engine for the tally" core — are blocked.
