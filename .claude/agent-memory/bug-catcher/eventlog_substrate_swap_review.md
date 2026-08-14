# Event-log substrate swap review (loom/main-0301-0312 follow, HEAD bf9266777)

Migrated runtime event log onto canonical `scp_event_log::EventLog` (RFC 6962). Reviewed: trait &str→EventType (81 sites), MerkleEventLogProvider rewrite, merkle_tree twin deletion (3a30fcce), export-root onto tree::root, buffered post-delivery governance fix (98f7af9b).

## Verdict: CLEAN. No correctness/security defects found.

Verified sound:
- All 21 removed `&str` governance/membership appends re-added with exactly one matching `EventType::` variant (grep count == 1 each). MessageSent/MessageReceived/PseudonymAnnounced/PaymentReceived correctly DROPPED (per-author/non-convergent, ADR-051 §6).
- PseudonymAnnounced fully removed from taxonomy (76→75 variants); tag 59 retired as a gap (tags stay byte-stable). is_structural_event table + tag-distinctness tests updated.
- export_import::verify_merkle_chain replays via append_unsigned_event + tree::root — bit-identical to live provider merkle_root (tree::root). Signed snapshot root = provider root. Tamper/truncation rejection sound (ct_eq against signed root, step 5/6).
- prune_before_checkpoint re-chains tail to GENESIS (leaf hashes + root change) — documented; pre-prune proofs intentionally invalidated. persist_entries bulk-rewrites prefix (deletes stale keys). restore replays renumbered seqs OK.
- checkpoint_events_since: incremented once per top-level in-order msg AND once per drained buffered msg (run_buffered_post_delivery line 710). No double-count, no skip.
- event_log_entries_for_consequences: Source 1 (durable log, bucketed to GovernanceAction) + Source 2 (buffer, MessageSent only). Convergence invariant maintained. matches_trigger sees bucketed GovernanceAction. WASM consequence.rs mirrors bucketing (EL01 test asserts cross-member equal counts).
- payload.rs typed structs: target_did is field 0 in AccessRevokedPayload + GovernanceActionExecutedPayload → rmp_array_first_string decodes correctly. consequence_event_payload uses sorted-key JSON (deterministic). GovernanceActionExecutedPayload.target_did populated from action.target_did().
- payment_history moved from log-scan to per-context payment_receipts ring (pushed at economy_helpers.rs:245, bounded eviction). Real push site exists.
- NAPI/store typed Event return: payload_json surfaces only leaf hash (via tree::leaf_hash), not raw payload — no positional-msgpack-as-JSON bug. push_leaf_raw sync consistent.
- merkle_tree twin fully deleted from actor/state.rs; no lingering refs. Proofs route through provider with_log (single tree, no off-by-one — leaf index == event sequence 0-indexed).
- cargo check -p scp-runtime -p scp-event-log: clean.

## Documented incompletenesses (NOT bugs — explicit DORMANT per ADR-051)
- Cross-member leaf replication dormant: membership/governance leaves are committer-appended-only; roots do NOT converge cross-member yet. run_buffered_post_delivery event_name always None (receive-side append unwired). Convergence is aspirational until ADR-051 §2 causal DAG lands.
- Committer timestamps: native + WASM both stamp local now() for own commit leaf (= envelope created_at); receivers don't yet copy it. Same on both sides.
- payment_history now returns only RECENT buffered receipts (bounded, non-persisted, empty after restart) vs prior complete durable history. Documented semantic change; spec §19.11 question is upstream, not a code defect.
- prune time-loop breaks at first retained event → can under-prune old operational events after a retained structural one (conservative, pre-existing, size-path backstops).
