---
name: project-supervisor-no-trust-repo
description: Supervisor/ContextManager does NOT hold a trust ProtocolRepository/AttestationCache; attestation source is reachable ONLY at the FFI bridge layer. Affects any "compute participation/trust in core" task.
metadata:
  type: project
---

The runtime `Supervisor` (crates/scp-runtime/src/context/supervisor/supervisor.rs) does NOT hold a trust `ProtocolRepository`/`AttestationCache`/`TrustProtocolRepository`. It holds `clock` (`OnceLock<Arc<dyn Clock>>`), `key_resolver` (`OnceLock<KeyResolver>`), `event_log` (`OnceLock<Arc<dyn ContextEventLogProvider>>` — has `event_log_entries` + `event_log_merkle_root`), saga journal, and `mls_storage` (`OnceLock<Arc<dyn OpenMlsStorageAdapter>>` — OpenMLS-only). The raw `Arc<S: Storage>` is ERASED after construction (folded into `DurableProviders` behind `dyn SagaJournal` + `dyn OpenMlsStorageAdapter`; cannot be downcast back without `S`).

**Why:** ADR-049 commit-12 lifted providers onto the Supervisor as erased trait objects; the same-backend invariant is type-enforced via `DurableProviders::from_handle`, which consumes the only `Arc<S>` and never re-exposes it.

**How to apply:** The attestation source for the trust engine is reconstructed at the FFI BRIDGE layer, per-bridge, on demand: each bridge holds its own `StorageProvider`/`ProtocolRepoVariant`, builds `ProtocolRepository::new(storage)` -> `ProtocolRepositoryTrustBridge::new(repo, handle)`, and the shared helper `scp_ffi_common::trust_store::populate_and_aggregate` (crates/scp-ffi/common/src/trust_store.rs) builds `AttestationCache::new(store)` + `IdentityDidPublicKeyResolver` + `scp_identity::cache::SystemClock` and calls `get_verified_attestations`. There is NO operational runtime write path for attestations — they enter the trust engine ONLY as caller-supplied JSON (`cached_attestations_json`) via `aggregate_trust_input` (`crates/scp-ffi/src/trust.rs` `aggregate_with_storage`; NAPI `crates/scp-ffi/napi/src/trust.rs`).

Consequence: every runtime `compute_participation_record` call site (governance_helpers.rs proposer-eligibility, tools/invoke.rs post_tool_invocation_bookkeeping, messaging_helpers.rs record_send_participation, lifecycle_logic.rs post_join_bookkeeping) HONESTLY passes `&[]` for attestations — verifier-relative per spec §7.3.2, not a stub. A "compute participation/trust record in the core/Supervisor" task that needs real `attestation_count` MUST thread attestations IN as a parameter and wire the real source at the bridge layer (NOT `&[]` there). This corrects the common premise "the ContextManager already holds the AttestationCache" — it does not. See [[typed-bindings-use-handles]].
