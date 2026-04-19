# UniFFI `check_ready()` Gate Audit — #1646 (ADR-048 PR 2 commit 14)

Enumerates every `#[uniffi::export]` function in `crates/scp-ffi/uniffi/src/bridge.rs`.
Classified by whether the function touches `ContextManager` state (Cat A),
`CoreFields` state (Cat B), or is a pure protocol helper with no state touch (Cat C).

Every Cat A / Cat B function MUST route through one of the lifecycle gates:
`default_bridge_instance()?`, `bridge_instance()`, `context_manager()?`,
`context_manager_expect()?`, `check_ready()`, or `ensure_bridge_instance()`.
Cat C is marked n/a.

**Enforcement:** `tests/check_ready_coverage.rs` runs a structural test on every
CI build that fails if any Cat A / Cat B export lacks a gate pattern.

## Free functions (165)

| # | Line | Function | Cat | Gate |
|---|------|----------|-----|------|
| 1 | 2386 | `identity_create` | B | yes |
| 2 | 2503 | `identity_create_with_custody` | B | yes |
| 3 | 2557 | `identity_load` | B | yes |
| 4 | 2605 | `identity_resolve` | C | n/a |
| 5 | 2657 | `identity_attest_device` | C | n/a |
| 6 | 2728 | `identity_verify_device_attestation` | C | n/a |
| 7 | 2861 | `identity_create_link_attestation` | C | n/a |
| 8 | 3027 | `identity_link_attestations` | C | n/a |
| 9 | 3047 | `identity_remove_link_attestation` | C | n/a |
| 10 | 3069 | `identity_verify_link_attestation` | C | n/a |
| 11 | 3119 | `context_create` | A | yes |
| 12 | 3300 | `context_join` | A | yes |
| 13 | 3464 | `context_leave` | A | yes |
| 14 | 3527 | `context_close` | A | yes |
| 15 | 3664 | `context_send` | A | yes |
| 16 | 3803 | `context_subscribe` | C | n/a |
| 17 | 3849 | `tool_register` | C | n/a |
| 18 | 4029 | `tool_invoke` | A | yes |
| 19 | 4275 | `tool_verify` | C | n/a |
| 20 | 4338 | `tool_invoke_cross_context` | A | yes |
| 21 | 4485 | `tool_session_create` | A | yes |
| 22 | 4571 | `tool_session_invoke` | C | n/a |
| 23 | 4702 | `tool_session_close` | C | n/a |
| 24 | 4750 | `tool_interface_expose` | C | n/a |
| 25 | 4851 | `tool_interface_accept` | C | n/a |
| 26 | 4937 | `tool_interface_revoke` | C | n/a |
| 27 | 5008 | `transport_connect` | A | yes |
| 28 | 5103 | `transport_status` | C | n/a |
| 29 | 5124 | `transport_disconnect` | B | yes |
| 30 | 5183 | `configure_relay_transport` | C | n/a |
| 31 | 6105 | `mcp_server_create` | C | n/a |
| 32 | 6194 | `mcp_server_stop` | C | n/a |
| 33 | 6238 | `mcp_client_connect_stdio` | C | n/a |
| 34 | 6283 | `mcp_client_connect_sse` | C | n/a |
| 35 | 6319 | `mcp_client_disconnect` | C | n/a |
| 36 | 6351 | `mcp_client_list_tools` | C | n/a |
| 37 | 6405 | `mcp_client_invoke` | C | n/a |
| 38 | 6472 | `mcp_configure_stdio_allowlist` | C | n/a |
| 39 | 6486 | `mcp_disable_stdio_allowlist` | C | n/a |
| 40 | 6500 | `mcp_reset_stdio_allowlist` | C | n/a |
| 41 | 6515 | `mcp_get_stdio_allowlist` | C | n/a |
| 42 | 6553 | `ucan_validate` | C | n/a |
| 43 | 6697 | `ucan_mint` | C | n/a |
| 44 | 6839 | `ucan_revoke` | C | n/a |
| 45 | 6943 | `ucan_delegate` | C | n/a |
| 46 | 7121 | `event_log_query` | C | n/a |
| 47 | 7308 | `event_log_verify` | C | n/a |
| 48 | 7503 | `event_log_checkpoint` | C | n/a |
| 49 | 7638 | `governance_execute` | A | yes |
| 50 | 7814 | `governance_propose` | A | yes |
| 51 | 7878 | `governance_approve` | A | yes |
| 52 | 7924 | `governance_reject` | A | yes |
| 53 | 7971 | `governance_withdraw` | A | yes |
| 54 | 8014 | `governance_get_proposal` | A | yes |
| 55 | 8050 | `governance_list_proposals` | A | yes |
| 56 | 8086 | `apply_pending_ceiling_modification` | A | yes |
| 57 | 8118 | `finalize_close` | A | yes |
| 58 | 8168 | `create_governance_checkpoint` | A | yes |
| 59 | 8232 | `add_checkpoint_cosignature` | A | yes |
| 60 | 8287 | `restore_context` | A | yes |
| 61 | 8328 | `restore_all_contexts` | A | yes |
| 62 | 8374 | `tombstone_migrated_context` | A | yes |
| 63 | 8404 | `migration_state` | A | yes |
| 64 | 8447 | `broadcast_subscribe` | A | yes |
| 65 | 8489 | `broadcast_unsubscribe` | A | yes |
| 66 | 8531 | `broadcast_publish` | A | yes |
| 67 | 8666 | `broadcast_publish_asset` | A | yes |
| 68 | 8816 | `broadcast_publish_assets` | A | yes |
| 69 | 8977 | `broadcast_block_subscriber` | A | yes |
| 70 | 9012 | `broadcast_unblock_subscriber` | A | yes |
| 71 | 9045 | `broadcast_handle_key_request` | A | yes |
| 72 | 9073 | `broadcast_subscriber_count` | A | yes |
| 73 | 9092 | `broadcast_is_subscriber` | A | yes |
| 74 | 9113 | `broadcast_admission` | A | yes |
| 75 | 9138 | `context_member_count` | A | yes |
| 76 | 9157 | `context_is_member` | A | yes |
| 77 | 9173 | `context_member_dids` | A | yes |
| 78 | 9191 | `context_member_role` | A | yes |
| 79 | 9250 | `context_drain_events` | A | yes |
| 80 | 9283 | `access_key_generate` | A | yes |
| 81 | 9305 | `access_key_revoke` | A | yes |
| 82 | 9327 | `access_key_restore` | A | yes |
| 83 | 9352 | `context_handle_ttl_expiry` | A | yes |
| 84 | 9391 | `context_propose_ttl_extension` | A | yes |
| 85 | 9418 | `context_reset_ttl_timer` | A | yes |
| 86 | 9452 | `register_local_did` | A | yes |
| 87 | 9465 | `is_local_did` | A | yes |
| 88 | 9646 | `evaluate_provenance_quality` | C | n/a |
| 89 | 9757 | `trust_query_score` | C | n/a |
| 90 | 9794 | `trust_verify_attestation` | C | n/a |
| 91 | 9824 | `trust_create_challenge` | C | n/a |
| 92 | 9873 | `trust_verify_response` | C | n/a |
| 93 | 9931 | `verify_participation_requirements` | C | n/a |
| 94 | 9974 | `aggregate_trust_input` | C | n/a |
| 95 | 10115 | `set_economic_policy` | C | n/a |
| 96 | 10132 | `get_economic_policy` | C | n/a |
| 97 | 10158 | `context_export` | A | yes |
| 98 | 10195 | `context_import` | A | yes |
| 99 | 10240 | `provenance_attach` | C | n/a |
| 100 | 10413 | `provenance_check_chain_depth` | C | n/a |
| 101 | 10443 | `provenance_redact_counterparties` | C | n/a |
| 102 | 10471 | `provenance_pseudonymize_counterparties` | C | n/a |
| 103 | 10510 | `provenance_update_source_type` | C | n/a |
| 104 | 10565 | `media_check_capability` | C | n/a |
| 105 | 10585 | `media_initiate_session` | C | n/a |
| 106 | 10624 | `media_activate_session` | C | n/a |
| 107 | 10643 | `media_join_session` | C | n/a |
| 108 | 10667 | `media_end_session` | C | n/a |
| 109 | 10709 | `media_create_offer` | C | n/a |
| 110 | 10722 | `media_create_answer` | C | n/a |
| 111 | 10736 | `media_create_ice_candidate` | C | n/a |
| 112 | 10757 | `media_create_session_end` | C | n/a |
| 113 | 10769 | `media_send_signaling` | C | n/a |
| 114 | 10798 | `media_verify_sender_attribution` | C | n/a |
| 115 | 10899 | `bridge_evaluate_trust` | C | n/a |
| 116 | 10968 | `sync_classify_offline` | C | n/a |
| 117 | 10981 | `sync_classify_offline_custom` | C | n/a |
| 118 | 11006 | `discovery_parse_address` | C | n/a |
| 119 | 11051 | `discovery_create_query` | C | n/a |
| 120 | 11073 | `discovery_normalize_address` | C | n/a |
| 121 | 11086 | `petname_set` | B | yes |
| 122 | 11115 | `petname_remove` | B | yes |
| 123 | 11139 | `petname_set_context` | B | yes |
| 124 | 11172 | `petname_remove_context` | B | yes |
| 125 | 11196 | `petname_resolve_did` | B | yes |
| 126 | 11229 | `petname_resolve_context` | B | yes |
| 127 | 11257 | `petname_get_for_did` | B | yes |
| 128 | 11284 | `petname_get_for_context` | B | yes |
| 129 | 11315 | `handle_register` | B | yes |
| 130 | 11354 | `handle_lookup` | B | yes |
| 131 | 11398 | `handle_deregister` | B | yes |
| 132 | 11434 | `scope_register` | B | yes |
| 133 | 11502 | `scope_lookup` | B | yes |
| 134 | 11535 | `scope_deregister` | B | yes |
| 135 | 11575 | `address_resolve` | B | yes |
| 136 | 11693 | `identity_create_with_agent_key` | B | yes |
| 137 | 11789 | `identity_migrate` | C | n/a |
| 138 | 12004 | `sync_get_policy` | C | n/a |
| 139 | 12108 | `bridge_register` | C | n/a |
| 140 | 12229 | `bridge_create_shadow` | B | yes |
| 141 | 12317 | `context_discover` | C | n/a |
| 142 | 12392 | `sandbox_validate_declaration` | C | n/a |
| 143 | 12446 | `sandbox_check_capability` | C | n/a |
| 144 | 12508 | `evaluate_invitation` | C | n/a |
| 145 | 12591 | `identity_execute_recovery` | C | n/a |
| 146 | 12707 | `identity_execute_custody_migration` | C | n/a |
| 147 | 12857 | `scpid_sign` | C | n/a |
| 148 | 12948 | `scpid_verify` | C | n/a |
| 149 | 13023 | `economy_estimate_cost` | C | n/a |
| 150 | 13050 | `economy_policy_requires_payment` | C | n/a |
| 151 | 13064 | `economy_auto_accept_blocked` | C | n/a |
| 152 | 13080 | `economy_check_policy_lock` | C | n/a |
| 153 | 13094 | `economy_validate_policy_change` | C | n/a |
| 154 | 13119 | `economy_evaluate_formula` | C | n/a |
| 155 | 13135 | `economy_budget_remaining` | B | yes |
| 156 | 13146 | `economy_budget_grant` | B | yes |
| 157 | 13159 | `economy_budget_record_spend` | B | yes |
| 158 | 13180 | `economy_antispam_record` | B | yes |
| 159 | 13197 | `economy_antispam_velocity` | B | yes |
| 160 | 13213 | `economy_antispam_escalated_cost` | B | yes |
| 161 | 13288 | `metadata_record_to_json` | C | n/a |
| 162 | 13355 | `metadata_record_from_json` | C | n/a |
| 163 | 13395 | `template_get_params` | C | n/a |
| 164 | 13410 | `validate_against_template` | C | n/a |
| 165 | 13429 | `validate_context_params` | C | n/a |

## Impl-block methods (27)

| # | Line | Function | Cat | Gate |
|---|------|----------|-----|------|
| 1 | 1378 | `Identity::instance_id` | C | n/a |
| 2 | 1384 | `Identity::did` | C | n/a |
| 3 | 1392 | `Identity::custody_type` | C | n/a |
| 4 | 1416 | `Identity::rotate_key` | B | yes |
| 5 | 1500 | `Identity::has_agent_key` | C | n/a |
| 6 | 1521 | `Identity::get_agent_public_key` | C | n/a |
| 7 | 1544 | `Identity::add_agent_key` | B | yes |
| 8 | 1635 | `Identity::remove_agent_key` | B | yes |
| 9 | 1728 | `Identity::rotate_agent_key` | B | yes |
| 10 | 1885 | `ContextHandle::instance_id` | C | n/a |
| 11 | 1890 | `ContextHandle::context_id` | C | n/a |
| 12 | 1902 | `ContextHandle::state` | C | n/a |
| 13 | 1919 | `ContextHandle::creator_did` | C | n/a |
| 14 | 1962 | `UcanToken::instance_id` | C | n/a |
| 15 | 1968 | `UcanToken::token_data` | C | n/a |
| 16 | 1974 | `UcanToken::token_id` | C | n/a |
| 17 | 1980 | `UcanToken::issuer` | C | n/a |
| 18 | 1986 | `UcanToken::audience` | C | n/a |
| 19 | 1992 | `UcanToken::capabilities` | C | n/a |
| 20 | 2007 | `UcanToken::encoded` | C | n/a |
| 21 | 2089 | `TransportManager::instance_id` | C | n/a |
| 22 | 2097 | `TransportManager::status` | B | yes |
| 23 | 2118 | `TransportManager::is_connected` | B | yes |
| 24 | 2127 | `TransportManager::adapter_count` | B | yes |
| 25 | 2151 | `TransportManager::add_relay` | B | yes |
| 26 | 2218 | `TransportManager::assign_relay_set` | B | yes |
| 27 | 2247 | `TransportManager::reliability_score` | B | yes |

## Category summary

| Category | Free fns | Impl methods | Total |
|----------|----------|--------------|-------|
| A (touches `ContextManager`) | 50 | 0 | 50 |
| B (touches `CoreFields`)     | 27 | 10 | 37 |
| C (pure protocol / getters)  | 88 | 17 | 105 |
| **Total**                    | **165** | **27** | **192** |

**Missing gates:** 0 Category A / 0 Category B — every stateful export routes through the lifecycle gate.
