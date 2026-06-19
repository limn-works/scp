---
name: eventlog-unification-phase2
description: ADR-011 event-log unification Phase 2 crypto review (round 4 APPROVE) — runtime onto scp_event_log RFC 6962 substrate, export-root migration, §9.9.3 equivocation dedup
metadata:
  type: project
---

ADR-011 amendment / event-log unification Phase 2. Round-4 confirmation review = APPROVE, no blocking findings. Resolves the prior finding that runtime used a hash-CHAIN, not the RFC 6962 tree.

**Why:** runtime ContextManager event log diverged from the protocol RFC 6962 Merkle substrate (`scp-event-log/tree.rs`). Native↔WASM equivocation latent; #1540/#1535 blocked. Alec chose FULL unification.

**How to apply:** single root authority is `scp_event_log::tree::root` (RFC 6962: leaf=SHA-256(0x00‖rmp_serde(Event)), interior=SHA-256(0x01‖L‖R), odd-node promotion, empty=SHA-256("")). All three paths use it identically: provider `merkle_root` (providers/event_log.rs:278), checkpoint create (:623), exporter+importer via `verify_merkle_chain`.

Verified sound this round:
- **Export-root binding migration**: `verify_merkle_chain` (export_import.rs) REPLAYS entries through `tree::append_unsigned_event` (per-leaf sequence-from-0 + prev_hash chain, genesis for entry[0]) then returns `tree::root`. Exporter binds it into signed snapshot (create_export:890); importer recomputes + ct_eq. Prefix-truncation rejected (nonzero seq); suffix/reorder/middle-removal → different root. Truncation forgery CLOSED.
- **§9.9.3 equivocation dedup**: received app messages + EquivocationDetected + (former) MessageReceived NO LONGER appended to durable log — receiver-minted, sender-unauthenticated leaves would make honest receivers diverge roots and false-positive detection. No MessageReceived/EquivocationDetected EventType variant exists; both in-memory ContextEvent only. Detection unchanged (Equal count + ct_eq root false ⇒ Divergent). Dedup = per-sender `(event_count, merkle_root)` HashSet (record_equivocation_if_fresh, queries_helpers.rs:867) — sole mechanism now append no longer advances local_count. New root at seen count = fresh. Bounded at MAX_SEQUENTIAL_COMMITS: alert still EMITS when full, only stops inserting (never misses).
- **Governance decoupled**: run_buffered_post_delivery runs velocity/consequence/checkpoint-counter UNCONDITIONALLY; event_name:Option<EventType> Some only for sender-authenticated events. Fixes prior buffered-drain governance-skip regression.
- **Consequence typed-payload decode** (consequence.rs): payload_target_did decodes exactly 2 live encodings — positional MessagePack typed struct (rmpv first array element) + JSON object target_did. rmpv array-vs-map disambiguates. Legacy null-terminated fallback removed (pre-release, correct).
- **Typed API**: append_context_event takes EventType + EventPayload; no string-literal event names remain.
- **76 EventType tags**: 0-35 pinned (EconomicPolicyApplied=33 historical gap-fill), 36..=75 unification variants, all distinct (test-enforced).
