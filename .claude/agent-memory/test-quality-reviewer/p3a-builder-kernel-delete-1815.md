---
name: p3a-builder-kernel-delete-1815
description: PR #1815 typestate node builder deletion — test migration to Node::start_for_testing; coverage audit findings
metadata:
  type: project
---

# PR #1815 (feat/p3a-delete-builder-kernel) test migration audit

Deletes ApplicationNodeBuilder typestate kernel from scp-node/src/lib.rs; ports unit tests to `Node::start_for_testing(NodeConfig {..})`.

**Why:** ADR-051 / construction standard — replace compile-time typestate builder with runtime-validated NodeConfig struct + `validate_config`.

**How to apply (coverage verdict):**
- Behavioral coverage PRESERVED for the two flagged tests:
  - `identity_with_storage_reloads_on_subsequent_run` → config.rs Test 7 `persisted_identity_round_trips_same_did` (same two-run same-DID assert).
  - `identity_with_storage_rejects_mismatched_custody` → config.rs Test 16 `persisted_rejects_mismatched_custody_through_node_start` (same `"not found in custody"` assert).
- `builder_domain_sets_relay_url` + `domain_build_uses_wss_no_regression` → config.rs Test 1 `domain_generate_produces_did_dht_identity` asserts `wss://...config-gen.example.com/scp/v1` + `domain()==Some` (faithful, arguably stronger).
- `failing_tls_falls_through_to_nat` / `domain_fallthrough_on_acme_failure_probes_nat` → ported via `TlsMode::Custom(FailingTlsProvider)` + `NatSlot::Custom(RecordingNatStrategy)`; `domain()==None` + NAT-probe asserts retained. ROBUST.
- Pure compile-mechanic deletes (correct): type_state_builder_compiles_with_all_required_fields, type_state_optional_fields_at_any_point, no_domain_method_exists_and_transitions_type_state, stun_server_method_exists_on_builder, bridge_relay_method_exists_on_builder. All had `_builder` never built + "the fact it compiles proves..." comments. No runtime asserts lost.

**ONE LOW-SEV FINDING:** `builder_with_acme_email` (deleted) built a node end-to-end (domain + SucceedingTlsProvider + acme_email set) and asserted DID==`did:dht:` — proved acme_email coexists with the build path without breaking it. Replacement `defaults_spread_idiom_compiles` (Test 8) only asserts `matches!(config.tls, TlsMode::Acme{..})` on the CONFIG STRUCT, never calls start_for_testing. Reason it can't be fully ported: `apply_tls` returns `None` for `TlsMode::Acme` → start_for_testing falls through to engine default `AcmeProvider::new(domain)` = real network ACME, untestable offline. So Acme+Domain ✓ build cell remains structurally unbuildable offline (matches config.rs T17/TLS-matrix memory note). Net: build-path coexistence of acme_email degraded to struct-presence — minor, not a real-behavior regression (old test used a mock TLS provider, never exercised real ACME either).
