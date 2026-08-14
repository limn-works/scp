# Native↔WASM Durable Leaf-Payload Parity (f234988bc audit)

Merge-gating audit at HEAD f234988bc. The §9.9.3 equivocation-detection convergence
invariant: for the SAME EventType, every member's durable Merkle leaf preimage
`SHA-256(0x00 ‖ rmp_serde(Event))` must be byte-identical. `Event.payload` is in
the preimage, so ANY payload-byte difference for the same EventType = convergence bug.

## Where appends live
- WASM durable: `crates/scp-ffi/wasm/src/manager.rs` PerContextState::append_log_event
  (+ append_consequence_leaf, append_provenance_event). All call sites enumerated.
- Native durable: `crates/scp-runtime/src/context/` builder.rs
  append_context_event (EMPTY = EventPayload::default()) vs
  append_context_event_with_payload (typed via encode_payload / shared helper).
- ProvenanceAttached/Received native append is in the PyO3 bridge
  (`crates/scp-ffi/src/provenance.rs::append_provenance_event`), NOT in scp-runtime.

## Matrix result: NO REMAINING PAYLOAD MISMATCH
- Empty both: ContextCreated, MemberJoined, MemberLeft, ContextClosing,
  ContextClosed, ContextExpired, ToolRegistered, GovernanceProposalCreated,
  GovernanceVoteCast, GovernanceVoteWithdrawn (last 3 = f234988bc fix: were
  `proposal_id.as_bytes()`, now `b""`).
- Shared producer (identical bytes): TokenRevoked (token_revoked_payload),
  GovernanceActionExecuted (encode_payload GovernanceActionExecutedPayload{target_did,
  action_type via shared variant_name}), Consequence{Triggered,Enforced,
  EnforcementFailed} (consequence_event_payload + shared enforce_triggered loop).
- ProvenanceAttached/Received: BOTH put a 32-byte prov_hash in the leaf. Hash
  preimages converge by design via WASM CanonicalProvenance mirror of
  scp_core DataProvenance (field order verified identical; covered by
  provenance_hash_conformance_* tests). Unchanged by f234988bc. MATCH.

## f234988bc verification (all PASS)
- Item 1 (empty leaves): correct. BUT test gap (LOW): parity tests use synthetic
  `b""` literals via test_append_log_event_at; they do NOT drive the real
  propose_governance_action/cast_vote/withdraw_vote handlers, so a regression at
  manager.rs:3959/4083/4200/4278 (arg flipped back to proposal_id.as_bytes())
  would NOT be caught. test_append_log_event_at IS byte-identical to production
  append_log_event (only timestamp param differs).
- Item 2 (import re-pin observed_at): CORRECT. import_context (lifecycle_helpers.rs
  ~1743) re-pins observed_at to local import clock on UNTRUSTED path; restore_context
  (line 2259) keeps verbatim (trusted). Single chokepoint: Supervisor::import_context
  → ImportContext dispatch → lifecycle_helpers::import_context. No constructor bypass.
  is_effective = current >= effective_at.max(observed_at+PERIOD). Test exercises
  backdated observed_at AND effective_at. PASS.
- Item 3 (dedup convergent_consequence_timestamp): deleted dup in governance_logic.rs
  was byte-identical to scp_protocol fn. Identical behavior.
- Item 4 (dense sequence in merge_consequence_events): behavior-preserving. Merged
  events are EVIDENCE-only (feed enforce_triggered_consequences), never durable
  leaves. Function is SHARED by native+WASM so no divergence possible by construction.

## LOW doc nit
EventType::GovernanceProposalCreated doc (event-log/src/lib.rs:173) says
"Payload fields: proposal_id, proposer_did, action, voting_deadline" but durable
leaf is now EMPTY (data rides buffer-only ContextEvent). Same for VoteCast/Withdrawn.
Documents the logical event, not the durable leaf — stale after f234988bc.
