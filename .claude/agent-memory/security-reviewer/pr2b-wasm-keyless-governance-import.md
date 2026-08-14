---
name: pr2b-wasm-keyless-governance-import
description: HIGH forged-vote quorum on WASM keyless governance import (commit d8089c583, PR-2b #1877/#1900)
metadata:
  type: project
---

# PR-2b WASM keyless governance engine adoption (commit d8089c583) — security review 2026-06-28

GO-WITH-CHANGES. Reviewed `crates/scp-ffi/wasm/src/manager.rs` import + auto-execute boundary and `scp-protocol` `TrustedVoteIngest::ingest_proposal` (multisig/majority/unanimity).

## HIGH (OPEN, escalate — ADR-034 trust-model): forged-vote quorum on untrusted import
- `rederive_imported_proposal_statuses` / `rederive_multiparty_status` (~manager.rs 7836-7918) re-tally an imported Approved proposal's CARRIED votes via keyless `ingest_approve`/`ingest_reject`. Those validate only DID∈frozen-set + pending + deadline + not-already-voted. **NO signature verification** (keyless ADR-034; `no_op_key_resolver` always None).
- Malicious-but-validly-signed creator authors the WHOLE signed snapshot: chooses `eligible_voters`/`threshold_signers` = [creator, victimA, victimB...] AND fabricates `approvals` = SignedVote{voter_did: victimX, signature: []} with future deadline. Re-derivation counts them all "eligible" → reaches quorum → Approved → survives re-derivation → executable via `require_proposal_approved`/`execute_governance_action` (forged proposal NOT in `executed_proposals` replay set).
- Pre-baked-STATUS hole IS closed (status re-derived, not trusted); single_admin arm correctly Invalidates. But multi-party re-tally of UNAUTHENTICATED votes adds no trust. Commit msg "closes pre-baked-Approved hole" is true ONLY for single_admin.
- PR's regression test only covers single_admin import; never tests multi-party + fabricated eligible-DID approvals.
- FIX (recommend opt 1): Invalidate ALL imported multi-party resolved-proposal state too (symmetric w/ single_admin); honest executed proposals already protected by imported executed_proposals replay set → nothing stranded. Opt 2 (verify vote sigs) contradicts keyless WASM.

## MEDIUM: min_participation_bps unvalidated at create/import
- `resolve_governance_config` majority arm (~235-252) stores bps verbatim; `MajorityVoteEngine::new` (majority.rs:113) requires (0,10000]. bps=0 or >10000 → context created but EVERY vote op fails (engine InvalidConfig) / re-derivation invalidates all. Fail-closed (no exec) but bricked context; weaker than the threshold==0 reject (item D) which IS done up-front. Fix: reject in majority arm w/ VALID_7005.

## MEDIUM: unbounded eligible_voters/threshold_signers on import
- Import pre-pass (~1467-1530) caps seen_nonces/executed_proposals/resolved_proposals_json but NOT voter/signer vectors, no per-DID validate_imported_string. Re-derivation builds engine per resolved proposal, O(proposals×votes×voters) attacker-chosen, large DID clones. Browser DoS. Fix: add caps + per-element string validation.

## CLEAN / improved (do not re-flag)
- Empty signer/voter → collapse to single_admin (create AND import), quorum-0 `governance_quorum` arm DELETED. (b) closed.
- threshold_value guarded 1≤t≤signers.len() at create/import + ThresholdEngine::new.
- Replay guard now keyed on canonical compute_proposal_id (item F) — fresh-id double-execute blocked; conflict-invalidation shares canonical keyspace.
- Frozen-denominator invariant (eligible_voters never from live members) correct + tested.
- Envelope sig + exporter_did==creator_did + HMAC checks untouched; validate_governance_model still fail-closed pre-mutation. No validation weakened.
- No panic/unwrap/index in new prod helpers.
- ingest_proposal stores VERBATIM (no dedup/eligibility of carried votes) — fine on live path (stored vectors kept clean by prior validated votes) but it's WHY the import re-tally is forgeable (re-derivation reseeds empty + replays, which DOES validate per-vote, but against attacker-chosen frozen set).

GOTCHA: bare `-p scp-event-log`/`scp-primitives` tests need `--features testing` (hex did:key gated).
