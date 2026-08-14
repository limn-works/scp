---
name: eventlog-substrate-swap-review
description: API review of the phase-2 event-log substrate swap (typed EventType seam, proof seam, anchored fields) — naming + timestamp footgun findings
metadata:
  type: project
---

Phase-2 substrate swap (HEAD bf9266777, branch off main): runtime event log moved from a bespoke SHA-256 hash-CHAIN (EventLogEntry, compute_entry_hash, `SCP-EXPORT-ENTRY:`) onto the canonical `scp_event_log::EventLog` RFC 6962 tree, unifying native↔WASM leaf preimages (`SHA-256(0x00 ‖ rmp_serde(Event))`). Reviewed `git diff origin/main...HEAD`.

**Verdict: NEEDS REVISION (2 mechanical naming fixes).**

Findings worth recalling:
- **Stale "chain" naming.** `export_import::verify_merkle_chain` (pub fn) now returns `tree::root` via replay through `append_unsigned_event` — its own doc says "not a hash-chain head." Name asserts the opposite of behavior; also returns a root not a bool so `verify_*` is wrong twice. Rename to `recompute_event_log_root`. Paired field `ContextExport.merkle_root` is a mirror of signed `snapshot.event_log_merkle_root` — two same-value differently-named fields; rename mirror to signal observability-only.
- **`timestamp_secs: u64` footgun.** New explicit param on `ContextEventLogProvider::append_event` (and WASM `append_log_event`). Must be the committer-assigned envelope `created_at` (or a convergent deadline), NEVER local `now()`, else leaf preimages diverge and false-positive §9.9.3 equivocation. WASM passes `crate::time::now_secs()` — DEFENSIBLE because WASM is single-member-per-tab so local member IS the committer for events it originates (comments justify each site). But bare u64 has no type-level guard; a future non-committer-event caller silently breaks convergence. Recommended a `CommitterTimestamp` newtype. This is the highest-risk seam in the change.
- **`anchored` truth-in-advertising flags.** `ParticipationProfile.tool_invocation_count_anchored` mirrored Rust/Python/TS, folded into signed preimage (good). `PaymentReceipt.anchored` is runtime-only — NOT in any SDK binding (no PaymentReceipt interface in types.ts; the SDK "PaymentReceipt" greps are method names), so no divergence today. When PaymentReceipt gets an SDK type the field + its "UNSIGNED WIRE FIELD do not trust deserialized value" caveat must come with it.
- **Good simplifications:** proof seam collapsed twin `state.merkle_tree` + `sync_merkle_tree` into provider-owned `with_log`/`rebuild_event_log_for_proof`; `prove_event_inclusion/consistency` dropped `state: &mut` (now pure reads). `payment_history` moved from `&[Event]` (deserialize-from-log) to `IntoIterator<&PaymentReceipt>` (local ring buffer) — decoupled + honestly documented as "RECENT sliding window, not authoritative ledger."
- **WASM event-name divergence risk:** WASM `manager.rs` emits `eventType` via inline `format!("{:?}", ev.event_type)`; native bridges use shared `scp-ffi-common::event_log::event_type_label` (also `{:?}`). Agree today; WASM can't import the helper (ADR-034). Pin agreement with a wasm_conformance assertion or they drift silently.
- **`ContextEvent::PaymentReceived`** is consistent with sibling struct-variants (kind() arm + strip_event_payload arm present).

Equivocation handling change: `record_equivocation_if_fresh` no longer appends an `EquivocationDetected` leaf to the durable log (receiver-minted, not sender-authenticated → would diverge honest roots). Now buffer-only; per-sender `(count,root)` set is the SOLE dedup (was secondary). Tests updated to assert 0 appends.
