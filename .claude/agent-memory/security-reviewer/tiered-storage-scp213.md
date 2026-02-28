# Tiered Storage & SCP-213 Context Discovery -- Detail Notes

## Tiered Storage (`crates/scp-core/src/event_log/tiered_storage.rs`) -- SCP-127 Review (2026-02-27)

- HIGH: checkpoint_root invalidated after second migration -- overwrites with partial hot root
- HIGH: Hot log rebuild resets indices to 0-based, breaking global sequence mapping
- MEDIUM: cold_entries linear scan O(n) -- should binary search by sequence
- MEDIUM: No defense-in-depth checks on relay-returned proof (leaf_hash, leaf_index not asserted)
- MEDIUM: leaf_hash sent to untrusted relay in fetch -- info leak
- MEDIUM: hot_log_mut() allows bypassing record_hot_event -- metadata desync
- MEDIUM: Unbounded cold_entries Vec growth
- MEDIUM: now parameter caller-supplied with no validation
- GOOD: Relay root overridden with local checkpoint_root before verification
- GOOD: MaliciousProvider test for forged proof rejection
- GOOD: thiserror for TieredStorageError, no unwrap/expect in lib code
- GOOD: OR semantics for migration thresholds (age, count, bytes)
- GOOD: ColdTierProvider trait is injectable and object-safe

## SCP-213 Context Discovery (`crates/scp-ffi/src/mcp.rs`, `runtime.rs`, `transport.rs`)

- HIGH BUG: `py_context_create` does NOT call `register_known_context` -- KNOWN_CONTEXTS always empty in production; relay probe always returns empty set
- HIGH BUG: Python `mcp.py:687` does `h.context_id` (attribute) on dicts returned from `py_mcp_load_contexts` -- should be `h["context_id"]` -- AttributeError at runtime
- MEDIUM: `_relay_url` param in `py_mcp_load_contexts` is ignored (underscore); uses global relay connection set by `py_transport_connect` instead -- silent mismatch when caller provides different URL
- MEDIUM: `probe_relay_for_known_contexts` calls `rt.block_on()` in a sync pyfunction context -- valid pattern for sync bridge fns but violates ADR-013 doc ("never via block_on from async context"); needs doc clarification
- MEDIUM: relay QUERY returns all blobs for routing_id (no limit=1 support in API) -- may fetch large payloads just to check existence
- MISSING: No integration test for relay-based discovery (acceptance criterion 5 unmet)
- MISSING: `register_known_context` never called from production code paths
- GOOD: graceful fallback to local-only when relay unreachable
- GOOD: client-side-only discovery (no identity leak to relay)
- GOOD: deduplication by context ID
- GOOD: RELAY_CONNECTION uses RwLock with Arc clone -- no arc-swap races
