---
name: pr1850-eventlog-phase2-persona-merge
description: PR #1850 Phase-2 RFC6962 Merkle substrate review AFTER #1852 (#agent persona) merge + 82fbef9dd divergence-marker provenance fix — both SOUND
metadata:
  type: project
---

# PR #1850 event-log Phase-2 substrate × #1852 persona merge — crypto/convergence review (2026-06-21, HEAD 44f2ebeda)

Leaf = SHA-256(0x00 ‖ rmp_serde(Event)). Event struct (scp-event-log/src/lib.rs:480) = {event_type, actor_did, timestamp, sequence, payload, prev_hash, signature}. NO signing_key_id/persona field. scp-event-log UNTOUCHED by the merge (git log origin/main..HEAD -- crates/scp-event-log = all Phase-2 commits; merge commit 5df11a2ee touched 0 files there).

**Why:** Confirm #1852's shared-DID #agent persona (signing_key_id #active/#agent VM selector + 2-arg KeyResolver) does NOT enter convergent Merkle leaf bytes, so honest members still derive identical roots.
**How to apply:** When reviewing event-log convergence, the leaf preimage is the Event struct only. Persona is WIRE-LAYER (InnerEnvelope field, messaging_helpers.rs:183, governs envelope signing/verify). It never reaches append_context_event{,_with_payload} (actor_did:&str only — builder.rs:187/213). grep for any append site carrying signing_key_id/persona/signer. across scp-runtime/src = EMPTY. MessageSent was REMOVED from canonical Merkle log in Phase-2 (messaging_helpers.rs:1793) → now local ContextEvent only (per-author non-convergent, exclusion taxonomy §2). Convergence tests: tests/eventlog_convergence.rs (same stream→identical root despite clock offset / divergent app streams / per-payee payment counts; non-vacuous negative controls).

## 82fbef9dd divergence-marker provenance fix — SOUND
divergence_marker_plan (supervisor.rs:7127) now binds `let prepared_b = ctx.prepared_b.as_ref()?;` (:7141) and draws marker_nonce = prepared_b.recorded_nonce (:7174) + committed_timestamp_secs = prepared_b.recorded_timestamp_ms/1000 (:7182). Removed the map_or(ctx.asserted_nonce/asserted_timestamp_ms,…) fallbacks — the ONLY path by which proposer-controlled (caller-asserted, untrusted) values could enter a convergent durable leaf. Now closed by TYPE (the ?), not call-ordering.

prepared_b is B-VERIFIED: returned by target actor's PrepareB handler (dispatch_xctx_prepare_b supervisor.rs:6470-6488; handler actor/handlers/saga.rs:800). recorded_timestamp_ms = deps.clock.now_millis() = B's OWN clock, captured only after run_prepare_b_checks passes (:818). recorded_nonce = req.asserted_nonce ONLY after validate_freshness (skew+replay/dedup, :914/:1165) — nonce is a public correlation token B copies verbatim by design. Staged + persisted fail-closed BEFORE reply (:850).

Marker leaf (emit_divergence_marker actor/handlers/saga.rs:2055): EventType::CrossContextDivergenceMarker + actor_did="" + payload=serde_json::to_vec(CrossContextDivergenceMarker::sign(key,{saga_id,nonce,committed_side,committed_event_id})) + timestamp=committed_timestamp_secs. Signing preimage (cross_context_saga.rs:375) domain-sep XCTX_DIVERGENCE_DOMAIN + length-prefixed VarBytes on variable fields (no splice ambiguity); Ed25519 sign_prehashed_preimage deterministic (RFC 8032). Byte-identical per context across honest members. Target-log vs caller-log markers differ (diff keys) but are DIFFERENT logs — convergence is per-context. Holds.

## LOW (defense-in-depth, non-blocking)
supervisor.rs:6886 — Commit-A caller-side CrossContextToolInvoked leaf nonce still reads ctx.asserted_nonce directly, relying on documented "B copies wire nonce verbatim" invariant (comment :6876-6885 flags fragility itself). Provably equal to prepared_b.recorded_nonce on live path (Commit-B landed ⇒ prepared_b Some). Sound today. The 82fbef9dd principle (defend by verified provenance not cross-module byte-equality invariant) applies here too — sourcing from prepared_b.recorded_nonce (guarded) would harden with no behavior change. xctx_prepared_evidence_bytes (:7308) reads asserted values pre-Prepare-B but that's the supervisor's single-writer recovery journal (not member-replicated convergent leaf) + only-aborting replay arm reads it — correct as-is.

Verdict: both NEW concerns SOUND. No CRITICAL/HIGH/MEDIUM. One LOW at supervisor.rs:6886.
