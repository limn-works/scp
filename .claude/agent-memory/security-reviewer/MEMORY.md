# Security Reviewer Memory

## SCP Codebase Security Patterns

### Adversarial Review (PR#4) -- Black Hat Findings
- See `/tmp/black-hat-review.md` and PR#4 comment for full details
- 10 attack narratives (BLACK-001 through BLACK-010)
- 5 creative abuse scenarios (ABUSE-1 through ABUSE-5)
- Key themes: relay metadata surveillance, missing auth guards, no rate limiting, schema bypass, Sybil weakness

### PR#76 Audit Findings (2026-02-26) -- Initial Review
- See `pr76-findings.md` for full details

### PR#76 Fix Verification (2026-02-26)
- FIXED: `claim_shadow` now verifies both ClaimRequest and Attestation Ed25519 signatures
- FIXED: RFC 6962 domain separation (0x00 leaf, 0x01 interior) consistent across all 4 event_log submodules
- FIXED: `allowed_adapters` enforcement added to `check_and_record()` in spending.rs
- FIXED: `CertificateData` Debug impl redacts private_key_pem
- FIXED: FFI `init_runtime` uses map_err instead of expect -- no panic across FFI
- FIXED: `content_hash()` returns Result instead of unwrap_or_default
- FIXED: `validate_child_ttl` rejects infinite child under finite parent
- FIXED: Standing channel TOCTOU -- lock held across get-or-create
- REMAINING (HIGH): GovernanceAction (shadow.rs) still has no signature field
- REMAINING (HIGH): Duplicate proposal check in SingleAdminEngine placed AFTER construction
- REMAINING (MEDIUM): Attestation canonical hash uses Debug format for type tag
- REMAINING (MEDIUM): shutdown_runtime still blocks GIL for 100ms
- REMAINING (MEDIUM): SHUTDOWN_TIMEOUT const (5s) stale vs actual 100ms
- UNFIXED: CurrencyCode Deserialize bypasses ASCII validation
- UNFIXED: EventLogMetrics proof profile Vecs unbounded
- UNFIXED: PaymentReceipt Debug leaks adapter_proof
- UNFIXED: SenderVelocityTracker unbounded HashMap

### MCP Server (`crates/scp-mcp/src/server.rs`)
- Uses `ContextProvider` trait for testability -- good pattern
- `tools/list` filters by both role (admin_only) and UCAN capability -- good
- `tools/call` validates UCAN before invocation -- good
- FINDING (PR#4): No pre-initialization guard on `handle_request`
- FINDING (PR#4): `resources/read` has no UCAN capability check
- FINDING (PR#4): Schema validation is type-check-only, not full JSON Schema

### Relay Server (`crates/scp-transport/src/native/server.rs`)
- FINDING (PR#4): Zero rate limiting on PUBLISH, SUBSCRIBE, QUERY, DELETE
- FINDING (PR#4): No storage quota -- InMemoryBlobStorage has no capacity limit
- FINDING (PR#4): DELETE is unauthenticated

### UCAN (`crates/scp-core/src/crypto/ucan/`)
- 11-step validation pipeline is thorough -- good
- `SpendingCapability` attenuation validation is correct and thorough
- `allowed_adapters` now enforced in check_and_record
- FINDING (PR#4): `validate_ucan_stateless` skips nonce, revocation, chain, attenuation checks
- FINDING (PR#4): `now_secs()` uses `unwrap_or_default()` -- returns 0 on clock error
- UNFIXED: `CurrencyCode` serde deserialize bypasses ASCII validation

### Shadow Identity (`crates/scp-core/src/bridge/`)
- Capability restriction via `VERIFIED_IDENTITY_CAPABILITIES` -- good
- Shadow capacity limits (10k/bridge, 100k total) -- good
- claim_shadow NOW verifies Ed25519 signatures (both claim + attestation)
- NEW FINDING (HIGH): Canonical hash no field separators -- concatenation collision risk
- NEW FINDING (MEDIUM): did:key:<hex> non-standard, not gated behind cfg(test)
- NEW FINDING (MEDIUM): Shadow governance check only compares shadow_id, no test coverage
- NEW FINDING (MEDIUM): extract_public_key_from_did + hex_decode duplicated in tree.rs
- NEW FINDING (MEDIUM): claim canonical hash binds attestation only by ID, not content hash
- REMAINING (HIGH): `GovernanceAction` has no signature -- still unfixed
- REMAINING (MEDIUM): Attestation canonical hash uses Debug format for type tag
- REMAINING (MEDIUM): attestation.claim.to_string() JSON not canonically ordered

### FFI Bridge -- PyO3 (`crates/scp-ffi/src/`)
- OnceLock for tokio runtime singleton -- correct pattern
- `#![allow(unsafe_code)]` -- correct FFI exception
- init_runtime NOW uses map_err (no panic across FFI)
- shutdown_runtime reduced to 100ms (from 5s) but still blocks GIL
- SHUTDOWN_TIMEOUT const stale (5s) vs actual behavior (100ms)

### FFI Bridge -- UniFFI (`crates/scp-ffi/uniffi/`) -- PR#86 Review (2026-02-26)
- CRITICAL: scp-platform testing feature STILL in production deps (cdylib)
- HIGH: transport_connect accepts ANY URL scheme -- no wss:// enforcement (NAPI/WASM have it)
- MEDIUM: std::sync::Mutex in async context (short holds, but latent deadlock risk)
- MEDIUM: serde_json Error messages may leak struct details
- LOW: identity_load hardcodes CustodyMethod::InMemory regardless of actual custody
- LOW: HANDLE_COUNT uses Ordering::Relaxed -- shutdown race on ARM
- FIXED: ContextHandle::state() now returns error on poisoned mutex (was silently defaulting)
- FIXED: Context IDs now use UUID v4 CSPRNG (was nanosecond timestamp)
- FIXED: runtime() uses tracing::error instead of eprintln
- GOOD: OnceLock runtime pattern, abort on fatal init, Send+Sync on callbacks
- GOOD: ScpError enum with machine-readable codes
- GOOD: OpaqueInMemoryKeyCustody Debug redaction
- GOOD: Handle ref counting with Drop for shutdown ordering
- GOOD: Callback interfaces (KeyCustodyProvider, StorageProvider, PushProvider)

### TLS (`crates/scp-node/src/tls.rs`)
- TLS 1.3 enforced via `with_protocol_versions` -- good
- ACME HTTP-01 challenge router is correct
- CertificateData Debug NOW redacts private_key_pem
- Private key stored via Storage trait at `scp.tls.private_key_pem`
- `zeroize` crate still not used for private key material

### Economy (`crates/scp-core/src/economy/`)
- `Amount(u64)` with `saturating_add` -- no overflow risk
- `PaymentAdapter` trait: authorize/capture two-phase pattern
- UNFIXED: `SenderVelocityTracker` unbounded HashMap growth
- FIXED: `PaymentReceipt` Debug now redacts adapter_proof and signature to byte-length

### Economy Integration (SCP-156 Review, 2026-02-27)
- HIGH: Step 5 missing adapter.verify() -- only checks cost sufficiency, not cryptographic auth validity
- MEDIUM: Dummy PaymentAuthorization (zeroed auth_id) leaked to closures on 3 free paths
- MEDIUM: IntegrationError erased to ContextError::MembershipFailed(string) in ContextManager
- GOOD: Fail-closed on arithmetic overflow (unwrap_or(Amount(u64::MAX)))
- GOOD: VoidFailed preserves both original + void error (Box wrapping)
- GOOD: Integer-only arithmetic throughout (no f64)
- GOOD: allowed_adapters check before authorize()
- Pattern: execute_paid_action combines sender+receiver flows -- needs split for production 2-party use

### Context Nesting (`crates/scp-core/src/context/nesting.rs`)
- content_hash NOW returns Result (no hash collision on serialization error)
- validate_child_ttl NOW rejects infinite child under finite parent
- Standing channel TOCTOU fixed -- lock held across get-or-create

### Governance (`crates/scp-core/src/context/governance/mod.rs`)
- SingleAdminEngine has duplicate proposal check but placed after construction
- GovernanceProposal tracks votes with signed votes (DID + signature)

### FFI Bridge -- WASM (`crates/scp-ffi/wasm/`) -- PR#86 Review (2026-02-26)
- Bridge-stub architecture: no scp-core dependency, delegates real logic to TypeScript SDK
- GOOD: No unwrap/expect/panic in source; workspace clippy deny inherited
- GOOD: CSPRNG context IDs via uuid v4 + getrandom/js
- GOOD: JsKeyCustody and JsStorage extern methods use `catch`
- GOOD: No key material in Rust structs -- keys stay in JS WebCrypto boundary
- GOOD: No scp-platform/scp-testing dependency
- GOOD: Stable error codes matching cross-SDK standard
- FIXED: transport_connect NOW rejects non-wss:// URLs (was HIGH)
- MEDIUM: WasmDIDDocument::from_fields performs zero validation on JS-provided strings
- MEDIUM: context_send claims base64 validation but only checks is_empty()
- MEDIUM: Panic hook leaks file paths and internal state to browser console
- MEDIUM: Missing #![forbid(unsafe_code)] -- no architectural need for unsafe
- MEDIUM: serde_json Error messages may leak struct details when typed deserialization added
- MEDIUM: JsMessageCallback on_message/on_complete lack `catch` -- JS throw = WASM trap

### FFI Bridge -- NAPI (`crates/scp-ffi/napi/`) -- PR#86 Review (2026-02-26)
- CRITICAL: scp-platform testing feature in production deps (cdylib) -- same as UniFFI
- HIGH: unreachable!() in identity_create match arm -- panic across FFI boundary
- MEDIUM: std::sync::Mutex in async context (short holds, latent risk)
- MEDIUM: Missing #![forbid(unsafe_code)]
- MEDIUM: NapiTransportManager::status() silently defaults on poisoned mutex
- LOW: transport_disconnect silently ignores poisoned lock on state update
- LOW: identity_load hardcodes custody_type "in_memory"
- LOW: HANDLE_COUNT uses Ordering::Relaxed
- GOOD: OnceLock runtime pattern, abort on fatal init
- GOOD: OpaqueInMemoryKeyCustody Debug redaction
- GOOD: wss:// validation in transport_connect
- GOOD: Handle ref counting with Drop for shutdown ordering
- GOOD: thiserror + machine-readable error codes

### Tiered Storage (`crates/scp-core/src/event_log/tiered_storage.rs`) -- SCP-127 Review (2026-02-27)
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

### General Patterns
- No `unwrap`/`expect` in lib code -- project standard via clippy deny
- `thiserror` for error types -- consistent across crates
- Rust edition 2024, `#![forbid(unsafe_code)]` on all crates except scp-ffi
- `zeroize` crate not yet used anywhere
- Recurring: `unwrap_or_default()` on clock ops -- systemic pattern
- Pattern: multi-migration checkpoint root management is a subtle invariant -- always test proof verification across 2+ migration cycles
