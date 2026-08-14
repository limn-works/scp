---
name: leaf-actor-did-convergence
description: Adversarial review of branch fix/leaf-actor-did-convergence (native↔WASM Merkle leaf §9.9.3). Updated for HEAD 2b668715c.
metadata:
  type: project
---

# Branch fix/leaf-actor-did-convergence (HEAD 2b668715c over b5b0eb02c)

Change: shared system actor_did consts (scp-event-log/system_actors.rs), executor-DID
stamping on GovernanceActionExecuted + per-action leaves, WASM convergent close timestamp,
WASM governance-execute hardening (status guard, 14d TTL, dispatch rollback, fail-closed encode).

NOTE: an earlier pass of this branch (24h WASM TTL, no status guard, direct path unfixed) is
SUPERSEDED. At HEAD: WASM TTL=14d (matches native), require_proposal_approved added, WASM
direct path resolves proposer via proposal_proposer_did. Those earlier findings are RESOLVED.

## Security model context (load-bearing)
- ALL runtime context-log leaves are UNSIGNED (tree::append_unsigned_event, signature=[]).
  actor_did is the ONLY origin attribution, an UNAUTHENTICATED string.
- Convergence model = compare Merkle ROOTS via SIGNED snapshots/checkpoints.
- validate_did requires `did:` prefix → system:* sentinels disjoint from member-DID namespace
  at FFI boundary. BUT see LOW below: proposer_did on native direct path is NOT validate_did'd.

## Findings at HEAD (severity)

### HIGH (out-of-diff, diff RELIES on it): native direct-execute trusts caller proposal
- crates/scp-ffi/src/context.rs:3042 governance_execute deserializes full GovernanceProposal
  from caller JSON; validates ONLY proposal.action strings. proposer_did/status/created_at/
  proposal_id/approvals caller-controlled+unvalidated.
- handle_execute_governance_action_actor (governance.rs:660) stamps executor=payload.proposal.
  proposer_did. execute_governance_action (governance_helpers.rs:4490) checks only status==
  Approved (caller-set), context_id, replay. Dispatch capability check = CONTEXT CEILING, not
  caller auth. → caller forges Approved proposal, runs any ceiling action, attributes to ANY DID.
- NAPI napi/src/context.rs:2718 takes proposer_did: String free arg, stamps it; created_at=now.

### HIGH: direct-execute input model incompatible native vs WASM (breaks the §9.9.3 it claims)
- WASM context.rs:717 takes proposal_id only, tracked-proposal lookup, Approved-in-store,
  executor+timestamp from tracked created_at. Cannot inject a proposal.
- Native takes full caller struct. Leaf timestamp: PyO3=caller JSON created_at, NAPI=local now,
  WASM=tracked created_at. Same op → divergent convergent-leaf timestamp + executor.

### MEDIUM/HIGH: consequence-SUBJECT cross-bridge divergence (tracked #205)
- Native subject = proposal.proposer_did (governance_helpers ~4360/4392); WASM subject =
  initiator_did caller (wasm/manager.rs:3133). Direct path with caller!=proposer → consequence
  enforcement (freeze) lands on different members across bridges + divergent consequence leaf.

### MEDIUM: WASM governance event-COUNT diverges from native (tracked #206)
- WASM dispatch_governance_action emits NO per-action leaves, only GovernanceActionExecuted.
  Native emits per-action leaves (now executor-stamped) PLUS executed leaf. Roots differ
  regardless of single-leaf parity. Diff widens native side only.

### LOW: no system-sentinel forgery guard on proposer_did
- proposer_did on native direct path NOT validate_did'd → caller can set "system:close" etc,
  stamped on GovernanceActionExecuted leaf. Pollutes attribution / actor_did!=subject_did rules.

### LOW: WASM quorum approve fall-through reports "Pending" when proposal vanished (cosmetic).

## Resists attack
- WASM import creator-signed (Ed25519 verify_strict JCS) + exporter_did==creator_did;
  creation_timestamp_secs creator-authenticated → convergent across honest members.
- WASM direct-execute tracked-proposal-only + require_proposal_approved — safer than native.
- 14d WASM TTL now mirrors native EXECUTED_PROPOSALS_TTL_SECS.
- WASM propose rejects duplicate proposal_id before insert → rollback can't destroy existing.
- Initial TTL arm + ExtendTtl use convergent override (creation+ttl); promotion clears ttl both
  sides. Converges. reset_ttl_timer local-clock fallback = pre-existing latent, not this diff.
- Shared consts make sentinel parity true-by-construction.
- Fail-closed payload encode on WASM is correct (no empty-payload divergent leaf).
