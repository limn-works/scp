---
name: canonical-context-id-pra-11b8498e0
description: PR-A canonical-context-id reconciliation (#1924 Model A) @ 11b8498e0 — decode-not-double-hash; ALIGNED, 0 findings, 1 OBSERVATION
metadata:
  type: project
---

# Canonical context-id reconciliation PR-A @ `11b8498e0` (base 598a56c37; #1924 Model A, Alec-approved) — ALIGNED, ship, 0 findings, 1 OBSERVATION

**Why:** PR-A of the canonical-context-id reconciliation. A context's canonical identity = its 32-byte digest; id STRING = `hex(digest)`. Pre-PR-A bug: runtime keyed crypto/event-log under `SHA-256(hex(digest))` (DOUBLE-HASH) while the §6.2.4 wire `target_context_id` is the RAW digest → every real-context §6.2.4 saga binding + send/receive missed the group. PR-A makes `state.context_id` + all keying DECODE the hex id (recover the digest) for real 64-hex ids.

**How to apply:** Conformance fix to §6.2.4:276 ("`target_context_id` is ALWAYS the raw 32-byte digest — 64-hex on wire, Fixed32 in preimage") — NO spec change needed. Scope = `scp-runtime` ONLY (context/** + crypto/mls/**); NO spec/ADR/FFI/binding/enforcement. ADR-055 does NOT exist as an artifact yet (PR-E, later slice) — code only FORWARD-REFERENCES it in doc-comments (sanctioned).

## Mechanism (load-bearing, verified end-to-end)
- `generate_context_id()` (scp-ffi/common/src/context_id.rs:50) = `hex::encode([32 CSPRNG bytes])` → 64-char lowercase-hex of a 32-byte digest. EXACTLY the decoder's target shape.
- NEW `decode_canonical_context_id(id)` (state.rs:2065): if `id.len()==64 && all [0-9a-f]` → `hex::decode`→`[u8;32]`; ELSE fallback `scp_protocol::context::context_id_bytes(id)` = `SHA-256(id)` BYTE-FOR-BYTE unchanged. TOTAL (no panic; both inner Ok arms fall back; clippy-deny safe). Lowercase-STRICT by design (uppercase 64-hex test ids stay on hash fallback).
- CHOKEPOINT: `context_id_to_bytes` (state.rs:2065) redefined to delegate to `decode_canonical_context_id`. The DOZENS of prod keying sites (broadcast_helpers/governance_logic/lifecycle_logic/trust_recovery_helpers/queries_helpers/lifecycle_helpers) already route through this funnel → fixed FOR FREE. The per-site diff edits are EXACTLY the sites that had bypassed the funnel by calling the raw `scp_protocol::context::context_id_bytes` PRIMITIVE directly (messaging_helpers.rs, lifecycle_helpers.rs). No prod crypto-keying site left double-hashing.
- §6.2.4 binding now succeeds: saga gets `target_context_id:[u8;32]` (raw wire digest, supervisor.rs:5453), `target_hex = hex::encode(...)` (5490), looks up actor by STRING. Post-PR-A `hex(state.context_id)==target_hex==id-string` for real contexts.
- §9.16.1 sender-AAD guard (provider.rs:1588/1682) correctly mirrors new keying (`decode_canonical_context_id(ctx_str) != *context_id` → fail closed). Raw-string AAD contract from 598a56c37 preserved; dedicated non-64-hex guard-rejection test retained (`open_rejects_..._does_not_resolve`). Note: `hex(ctx_id)` is now canonical 64-hex so the top-guard PASSES it (resolves back to ctx_id) — the negative `seal_open_binds_raw...` test's rejection now comes from the AEAD layer one level deeper (test comment correctly updated).

## Standing-context = DELIBERATE plan-level deferral (NOT a gap)
§6.2.4:315: for a standing-pair the wire caller/target_context_id = the RAW `derived_context_id` digest (§5.15.8), never the `"standing-"`-prefixed string. `decode_canonical_context_id("standing-"+hex)` = `SHA-256("standing-"+hex)` ≠ derived_context_id → §6.2.4 binding for a STANDING target STILL mismatches after PR-A. CORRECTLY out of scope: standing_helpers.rs UNTOUCHED (not in diff; `"standing-"+hex` ~73 chars, never bare 64-hex → hash fallback). Explicitly called out at supervisor.rs:9038-9047 + saga.rs:134 + state.rs:2045 as "separately-tracked concern"; orchestrator-stated plan defers it to the tracked follow-on (PR-E/ADR-055).

## OBSERVATION (non-blocking, tracking hygiene)
Standing-context follow-on cited in 3 comments as "separately-tracked concern" with NO issue number (correct per no-issue-refs-in-code). Confirm a GitHub issue ACTUALLY exists for the standing-context digest-id reconciliation so the deferral is genuinely filed, not just asserted in prose (project rule: deferred out-of-scope work must be filed-or-done; deferral itself is legit + plan-sanctioned).

## LESSON
A conformance fix that eliminates a double-hash across many keying sites: verify it's done at a SINGLE chokepoint (redefine the shared helper) so all existing funnel-callers get it free, and the per-site edits are ONLY the sites that bypassed the funnel by calling the raw primitive directly. Sweep BOTH `context_id_to_bytes` (funnel) AND raw `context_id_bytes` (primitive) call sites — residual non-test primitive calls must be the DELIBERATE synthetic case (supervisor.rs:3547 `"identity-private-state"` PSK, documented). For digest-as-identity: the load-bearing check is `hex(state.context_id) == the wire id-string` for real ids; standing-pair digest-id is a DISTINCT id-form (raw derived_context_id ≠ SHA-256(prefixed string)) that a "real-context" decode slice correctly leaves on the hash fallback as a tracked follow-on. Forward-referencing an ADR that doesn't exist yet is OK in doc-comments when it's an approved later slice (not phantom provenance — the rationale is the future ADR, not a claim it already landed).
