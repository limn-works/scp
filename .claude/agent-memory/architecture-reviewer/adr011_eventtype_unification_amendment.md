---
name: adr011-eventtype-unification-amendment
description: ADR-011 amendment (phase-2.md) closing EventType to 76 variants + native↔WASM event-log unification; the durable architectural decision behind the runtime-onto-canonical-tree migration
metadata:
  type: project
---

ADR-011 amendment (docs-only, commit c6bccc7d5 on branch spec-adr011-eventtype-unification) is the artifact-flow PREREQUISITE for scp-runtime adopting the canonical RFC 6962 Merkle tree.

**Why:** scp-runtime logged free-form `event: String` names to a hash-CHAIN ("SCP-EXPORT-ENTRY:"), while ADR-011 + FFI/WASM bridges use a typed-event RFC 6962 tree with a closed `EventType` enum. Native↔WASM root-set non-convergence is a latent equivocation-detection (§9.9.3) defect and blocks the catch-up consistency-proof story (#1535).

**The decision (durable, No-DOA):**
- `EventType` is a CLOSED set, 76 variants, NO catch-all. `Other(String)` explicitly REJECTED (reintroduces free-form strings into signed leaf preimage = the non-convergence vector being removed).
- Closure argument rests on the UNION of all append sources, not GovernanceAction alone: governance (ADR-031 §3), lifecycle/migration (ADR-049 §9 / §5.11A), membership/access (§5), media (ADR-024), economic (§19), consequence-enforcement (phase-4 trust / §7.3.7), app-sandbox (§8), compromise recovery (§9.12 step 2), provenance (§7.3).
- EXACTLY TWO exclusions, framed as TARGET END STATE (runtime currently appends both, unification removes the two append sites): `MessageReceived` (per-recipient local; canonical record is sender's MessageSent) and `EquivocationDetected` (local divergence alert → ContextEvent/EquivocationAlert §23.16.6). Logging either makes member root-sets non-convergent.
- Signed-export root corrected: chain-head → RFC 6962 `tree::root` (ADR-050 Consequences + §23.16.8). This UPGRADES the security property: truncation forgery now CLOSED by construction (any prefix/suffix/interior/forge alteration changes tree::root), where the old chain-head only attested integrity not completeness.
- `signing_key_id` REMOVED from Event struct (VM carried by signature apparatus, resolved from DID doc). Canonical `scp_event_log::Event` = 7 fields. NOTE: `generate_checkpoint(...signing_key_id)` is a separate CHECKPOINT-signing PARAMETER (criterion 8) and is unaffected — amendment correctly disambiguates.

**How to apply:** When reviewing the CODE-side unification PR: (1) verify all 40 net-new variants land in scp-event-log/src/lib.rs (canonical had only 36 at c6bccc7d5); (2) verify the runtime free-form-string append sites convert to typed event_type + EventPayload — esp. the format!/JSON-blob defects: AppBound/AppUnbound (app_sandbox.rs ~872), TTLExtended/SpendApproved JSON-blob-as-tag (governance_helpers.rs 1394/2267); (3) verify recovery/epoch_advanced (trust_recovery_helpers.rs ~256, actor "system:recovery") maps to RecoveryEpochAdvanced, distinct from ADR-007 KeyEpochAdvance; (4) verify MessageReceived (messaging_helpers.rs ~2537) and EquivocationDetected (state.rs ~951) append sites are REMOVED; (5) verify §25 typed-leaf KAT + checkpoint tree::root KAT get added when code lands.

**Casing gotcha:** code emits `TTLExtended`/`TTLExtensionRejected` (uppercase TTL) but canonical variant spelling is `TtlExtended`/`TtlExtensionRejected` — the EventType variant spelling is authoritative per the amendment.

**Minor doc wrinkle (non-blocking):** ADR-050 lines 12/14 (untouched historical Context narrative) still say "event-log Merkle chain" describing the as-was structure, next to the corrected Consequences bullet calling it the "hash-chain head." Same thing, slightly loose term; could tighten but accurate-as-historical.
