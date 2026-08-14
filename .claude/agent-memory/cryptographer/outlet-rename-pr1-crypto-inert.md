---
name: outlet-rename-pr1-crypto-inert
description: PR-1 tool→outlet rename (feat/outlet-report) is cryptographically SOUND — all signing literals + hand-hashed preimages byte-identical; only local event-log leaf JSON keys change
metadata:
  type: project
---

# tool→outlet rename (feat/outlet-report PR-1) — crypto assessment

Branch `feat/outlet-report` @ f04246019 (base aaa574d0f). Mechanical tool→outlet rename, 174 files. READ-ONLY crypto review verdict: **cryptographically inert modulo intended, non-KAT'd local-leaf JSON key rename. SOUND.**

## REBASE-onto-origin/main conflict resolution (HEAD 5e4353904) — VERIFIED CLEAN
Rebased PR-1 onto origin/main; sole conflict `context/actor/handlers/saga.rs` (2 regions, §6.2.4 xctx saga economy-rollback). Resolution = main's newer behavior + renames. Both regions BYTE-IDENTICAL to `origin/main:saga.rs` modulo mechanical rename:
- **Region A** (prepare_a reserve-FAIL branch ~517): `persist_state_best_effort(&*cell,...)` + `Outcome::err_mutated` PRESERVED exactly. Best-effort (not fail-closed) is SOUND — reserve_outlet_economy rolls back its OWN escrow/velocity/budget/Class-S; only durable residue = soft §6.2.0.2 Class-C anti-spam window increment (non-refundable at initiation by design). Dropped persist → anti-spam UNDER-counts (soft throttle fail-open), CANNOT cause double-reservation/escrow-leak/replay (reservation already rolled back). Main's reasoning holds.
- **Region B** (commit_a REPLAY branch ~2033): generation-check (`req.reservation.reservation.generation`), escrow-void-only-on-mismatch, `class_c_economy_reversed` gating `ok_mutated`(match)/`ok`(mismatch), `clear_committed_reservation_idempotent` NO-persist re-ack — ALL preserved exactly (ADR-049 §Decision-9/N1).
- All called helpers genuine pure renames (git 152/152 symmetric tools_helpers.rs→outlets_helpers.rs; bodies identical incl. DELIBERATELY-preserved literals `"tool_invoke"` resource key @outlets_helpers:542, `SCP-TOOL-6088` @1287). Capability action string `"tool_invoke"` @saga:1177 PRESERVED (only `req.tool_registration_id`→`outlet_registration_id` struct-field rename, same value). Confused-deputy §7 re-bind unchanged.
- NO non-rename logic anywhere in file — only rustfmt reflows. NO repointing to different-semantics fn. **NO soundness regression.**

**Why:** Every signed/hand-hashed preimage is byte-identical to origin/main. The only crypto-input delta is serde-JSON object keys in two LOCAL event-log leaf payloads.

**How to apply:** If re-reviewing this or a sibling rename PR, don't re-derive — the crypto-critical facts:

- **Signing domain literals ALL UNCHANGED (deliberately):** `SCP-XCTX-RECEIPT-V1:` / `SCP-XCTX-DIVERGENCE-V1:` (cross_context_saga.rs:37/40), `SCP-TOOL-REGISTRATION-V1:` (registry.rs:525 — NOT renamed to SCP-OUTLET, explicit code comment keeps it byte-identical), `SCP-OFFER-ID-V1:` (interface.rs:216). `SCP-TOOL-*`/`SCP-VALID-*` grep hits are ERROR CODES not signing domains, byte-identical both sides.
- **Preimage field order/encoding byte-identical** (normalized-diff-empty proof): CrossContextOutletReceipt::signing_preimage (9 CanonicalFields, cross_context_saga.rs:220-231), divergence marker (376-382), compute_outlet_registration_canonical_bytes (registry.rs:519 — raw length-prefixed SHA-256, value-only, serde-name-independent), compute_offer_id (interface.rs). Rust field IDENTIFIER renamed (tool_registration_id→outlet_registration_id etc.) but hashed BYTES are runtime string VALUES, unchanged.
- **Self-recomputing KATs pass unchanged:** cross_context_saga.rs:495-512/798-807 rebuild preimage from hardcoded literals kept VERBATIM (b"calc.add", b"evt-tool-invoked-1"). test_vectors.rs offer-id: binding renamed but VALUE "tool-abc123" kept → offer ID unchanged. NO frozen hex hash constant changed anywhere in diff.
- **The ONE real crypto delta (sound):** serde-JSON leaf payload KEYS tool_id/tool_registration_id/tool_invoked_event_id → outlet_* in (1) saga ToolInvoked leaf actor/handlers/saga.rs:1765 inline json!, (2) OutletInvokedEvent struct outlets/lifecycle.rs:272 (no #[serde(rename)], derives Serialize) serialized at scp-ffi/src/mcp.rs:1026 + uniffi/bridge.rs:4795. These change those Merkle LEAF hashes. SOUND: pre-release/no-migration, both saga members run identical code (convergent ToolInvoked leaf §6.2.4), EventType::ToolInvoked discriminant NOT renamed, OutletStatus enum renamed but variants (Success/Error/Timeout/Cancelled) NOT → status string identical. NO stale KAT (grep empty). Cross-member test supervisor.rs:19422 reads ti_payload["chain_depth"] by unrenamed key → still resolves. No old/new dual-hash path (pre-release).
- **Item 4 (KDF/HKDF/MLS/sign) clean:** only McpToolInfo→McpOutletInfo UniFFI converter renames + 1 Ed25519 doc-comment. No KDF/label/nonce/.sign() construction change.
