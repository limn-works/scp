# Security Reviewer Memory

## SCP Codebase Security Patterns

### Adversarial Review (PR#4) -- Black Hat Findings
- See `/tmp/black-hat-review.md` and PR#4 comment for full details
- Key themes: relay metadata surveillance, missing auth guards, no rate limiting, schema bypass, Sybil weakness

### PR#76 Audit Findings (2026-02-26)
- See `pr76-findings.md` for full details (initial review + fix verification)
- UNFIXED: CurrencyCode Deserialize bypasses ASCII; EventLogMetrics Vecs unbounded; SenderVelocityTracker unbounded HashMap

### Production Readiness Commits (2026-03-06)
- See `production-readiness-commits.md` for full details
- 7 commits reviewed: sender key msgpack, HPKE domain sep, deny_unknown_fields, ProtocolRepository named msgpack, dedup TTL, serde rename, conflict pairs
- MEDIUM x2 on 7f341b8 (future timestamp window + missing test); rest CLEAN
- Pre-existing gaps: sender key wire types lack deny_unknown_fields; handle_sender_key_request no timestamp/nonce check; RestoreReadAccess self-conflict missing

### MCP Server (`crates/scp-mcp/src/server.rs`)
- FINDING (PR#4): No pre-initialization guard; `resources/read` no UCAN check; schema validation type-check-only
- GOOD: `tools/list` filters by role + UCAN; `tools/call` validates UCAN before invocation

### Relay Server (`crates/scp-transport/src/native/server.rs`)
- PARTIAL FIX (2026-03-03): Shared PublishRateLimiter + ConnectionTracker across WS/QUIC
- REMAINING (MEDIUM): Total connection limit TOCTOU

### Transport Expansion Audit (2026-03-04) -- QUIC/HTTP3/WebTransport/UDP/CoAP
- See `transport-expansion-audit.md` for full finding list (SEC-001 through SEC-008)

### UCAN (`crates/scp-core/src/crypto/ucan/`)
- 11-step validation pipeline thorough; SpendingCapability attenuation correct
- FINDING: `validate_ucan_stateless` skips nonce, revocation, chain, attenuation
- FINDING: `now_secs()` uses `unwrap_or_default()` -- returns 0 on clock error

### Shadow Identity (`crates/scp-core/src/bridge/`)
- HIGH: GovernanceAction no signature; canonical hash no field separators
- MEDIUM: did:key:<hex> non-standard not gated behind cfg(test)

### FFI Bridge -- PyO3 (`crates/scp-ffi/src/`) -- Audit 2026-02-28
- See `pyo3-audit-20260228.md` for full PR#112 fix list
- SCP-212: invoke_tool, routing ID derivation findings documented there

### FFI Bridge -- UniFFI (`crates/scp-ffi/uniffi/`) -- PR#86 + PR#127
- CRITICAL: scp-platform testing feature in production deps
- HIGH: transport_connect accepts ANY URL scheme; did:key hex not gated

### FFI Bridge -- WASM (`crates/scp-ffi/wasm/`) -- PR#86 + PR#127 R2 + PR#479
- HIGH: did:key hex in production; runtime.rs reimplements scp-core logic
- GOOD: Full 11-step UCAN validation; RED-105 prefix collision protection
- CRITICAL (UNFIXED): compute_event_hash uses SHA-256(0x00||event_type||context_id||timestamp) vs native SHA-256(0x00||MessagePack(full_event)). Merkle roots never match cross-platform. Conformance tests only verify tree structure, not leaf hash computation.
- FIXED (PR#479 815461c0): governance authorization -- initiator_did + member_has_capability + required_capability_for_action for all 24 variants
- FIXED (PR#479 02b47eac): IdentityEntry Zeroize+ZeroizeOnDrop, Zeroizing<[u8;32]>, no Clone. Minor: Debug derived on private struct prints raw bytes via Zeroizing

### FFI Bridge -- NAPI (`crates/scp-ffi/napi/`) -- PR#86 + PR#127
- CRITICAL: ucan_mint uses [0u8; 64] placeholder zero signature
- HIGH: did:key hex not gated behind cfg(test)

### TLS (`crates/scp-node/src/tls.rs`)
- TLS 1.3 enforced; ACME HTTP-01 correct; CertificateData Debug redacts key
- `zeroize` crate still not used for private key material

### Economy
- UNFIXED: SenderVelocityTracker unbounded HashMap growth
- SCP-156: HIGH: Step 5 missing adapter.verify()

### Android Platform Adapter (SCP-110 through SCP-113) -- 2026-02-28
- HIGH: publicKeyFromKeystore takeLast(32) fragile
- See pseudonym HMAC key material inconsistency below

### Pseudonym HMAC Key Material Inconsistency -- HIGH
- InMemoryKeyCustody uses PRIVATE key; spec/ADR-027/Android/WASM say PUBLIC key
- Fix: change InMemoryKeyCustody to verifying_key().to_bytes(); regenerate golden vectors

### Tiered Storage & Context Discovery
- See `tiered-storage-scp213.md` for full details

### Governance Engines (PR#127 R2)
- HIGH: compute_vote_hash omits proposal_id -- cross-proposal vote replay
- MEDIUM: verify_vote() defined but never called in any engine
- GOOD: Deadline guards, duplicate proposal rejection, deterministic IDs

### CI/CD Security (PR#127)
- MEDIUM: pr-review.yml/claude.yml contents:write with untrusted input
- GOOD: cargo-deny, PyPI OIDC Trusted Publishers

### Broadcast Context (`scp-core/src/context/broadcast.rs`)
- REMAINING (MEDIUM): subscribers/authors/block_list unbounded

### Event Log Checkpoint (`scp-core/src/event_log/checkpoint.rs`)
- REMAINING (MEDIUM): CheckpointManager::checkpoints Vec unbounded

### scp-node HTTP Features (SCP-242/245/249) -- 2026-03-02
- HIGH: dev_token logged at INFO plaintext; uses thread_rng() not OsRng
- MEDIUM: No localhost enforcement; unbounded epoch growth; bridge secret in query param

### Persistence Layer (2026-03-03)
- See `persistence-layer-findings.md` for details
- HIGH x3: identity keys not zeroized; MLS bridge bypasses sanitize_key_component; SyncableStorage no auth

### Governance Gaps (closes #266) -- 2026-03-05
- See `governance-gaps-findings.md` for details
- HIGH: validate_projection_ucan structural-only; message_handler Gated check after decryption
- MEDIUM: conflict_resolution missing RestoreReadAccess vs RestoreReadAccess pair (still open)

### UCAN Ceiling Enforcement (#339) -- 2026-03-06
- HIGH: FFI bridges (PyO3/NAPI/UniFFI) pass Some(empty_set) not None for contexts without ceiling -- blocks ALL ucan_mint/delegate
- HIGH: Option<HashSet<String>> on MintParams/DelegateParams is fail-open; all ~70 test sites pass ceiling: None
- MEDIUM: mint_ucan parses capabilities twice (ceiling check + attestation build) -- TOCTOU-class divergence risk
- GOOD: WASM bridge handles empty ceiling correctly (skips when empty); delegate ordering correct (attenuation before ceiling)
- Pattern: empty-collection-wrapped-in-Some vs None -- recurring FFI bridge issue. Always convert empty to None at boundary.

### Production Providers (#385) -- 2026-03-06
- HIGH: encrypt_message skips sender key layer -- only MLS, no ADR-007 sender key encryption. Defeats blocking/content access control.
- HIGH: init_broadcast_key generates broadcast key then discards it, stores unrelated sender key material. Three keys generated, none correct.
- MEDIUM: Merkle hash lacks length prefix on variable-length event name -- collision possible at event/timestamp boundary
- MEDIUM: unwrap_or_default() on SystemTime in event log (recurring pattern)
- MEDIUM: init_broadcast_key and destroy_sender_key acquire broadcast_keys/sender_keys mutexes in opposite order -- deadlock risk
- MEDIUM: validate_key_package only checks "did:" prefix -- no ciphersuite, signature, or credential validation
- GOOD: PoisonError::into_inner consistent; lock scopes minimal; encrypt/decrypt round-trip test real crypto; Merkle chain verification tested

### Iteration 17 (2026-03-07) -- SCP-270, SCP-CAC-001, SCP-CAC-004, SCP-ACR-001
- HIGH: access_keys/wire.rs build_hpke_info lacks length separators -- boundary-shift collision on context_id||member_did
- HIGH: AccessKeyRequest has no nonce/dedup -- replay within 30s freshness window (sender keys have NonceDedup, access keys don't)
- HIGH: validate_request_freshness accepts future timestamps (saturating_sub returns 0)
- MEDIUM: AccessKeyRequest/Response and BlockListEvent lack deny_unknown_fields
- MEDIUM: execute_add_signer nonce fallback "gov-signer-add-0" static on clock failure
- MEDIUM: RemoveSigner token revocation uses substring contains() not exact match
- MEDIUM: BlockListState/event log unbounded growth; append_block_list_event load-modify-store race
- GOOD: AccessKey Zeroize/ZeroizeOnDrop + Debug redacts; store_value_zeroize; CanonicalField::VarBytes in request hash
- GOOD: Exhaustive match arms in governance dispatch (no wildcards)
- GOOD: Unanimity check via set-difference pattern in ExtendTtl and PromoteContext

### General Patterns
- clippy deny unwrap/expect in lib code; thiserror; Rust 2024; #![forbid(unsafe_code)] except scp-ffi
- zeroize inconsistent: store layer yes, identity signing keys and MLS key pairs no
- unwrap_or_default() on clock ops is recurring systemic pattern (also unwrap_or_else with static fallback)
- DashMap shard locks must not cross Python GIL; clone Arc first
- Static DashMap registries lack eviction
- validate_projection_ucan structural-only -- recurring UCAN validation gap
- Signed wire types should have deny_unknown_fields (InnerEnvelope fixed; sender key types + access key types + BlockListEvent still missing)
- handle_sender_key_request has no timestamp freshness or NonceDedup integration
- Access key request also lacks NonceDedup -- both key protocols need nonce replay protection
- Multiple Mutex locks on same struct: enforce consistent acquisition order to prevent deadlock (crypto.rs broadcast_keys vs sender_keys)
- Hash inputs with variable-length fields need length prefixes or domain separators to prevent boundary-shift collisions
- HKDF info strings are NOT the same as canonical hashes -- build_hpke_info concatenates raw bytes without length prefixes (found in access keys; check sender keys too)
- Future timestamp rejection: always check BOTH directions (past staleness AND future clock skew) in freshness validators
- Load-modify-store on shared storage (append_block_list_event pattern) needs atomicity or caller-side serialization

### PR #465 -- scp-chat, scp-demo, UPnP, FFI E2E (2026-03-10)
- See findings below; scp-chat is a demo app, not production, but ships as a standalone binary
- HIGH: /api/send sender_did spoofing (no session-DID binding); WebAuthn missing origin validation; scp-demo /tmp key leakage
- MEDIUM: Hardcoded passphrase; thread_rng for challenges; no input size limits; unbounded members/challenges; error message leakage; testing feature in prod dep
- GOOD: textContent (no innerHTML XSS); TLS key Zeroizing; challenge TTL+GC; scp-testing isolation; gitignore for key files

### Phase 4 SDK Bindings -- BroadcastContent Publish (2026-03-16, re-reviewed)
- WASM ContentPath: FIXED -- is_unicode_formatting_wasm now byte-identical to scp-core (all 6 ranges added)
- WASM MimeType: FIXED -- RFC 7230 tchar enforcement + exactly-one-slash, algorithm-identical to scp-core
- WASM wire format: FIXED -- SCP magic + version + rmp_serde::to_vec_named, wire-compatible with scp-core
- WASM batch limit: FIXED -- MAX_BATCH_ASSETS=10_000, error SCP-CTX-2074 (NAPI has no equivalent limit)
- WASM deploy_id: PASS (algorithm-identical to scp-core)
- REMAINING MEDIUM: NFC normalization -- WASM skips NFC, scp-core applies it. Decomposed Unicode paths differ cross-platform. Fix: add .normalize('NFC') in TS SDK wasm.ts or add unicode-normalization crate to WASM.
- Error codes 2070-2074: clean, no collisions
- PyO3/NAPI/UniFFI: PASS -- all delegate to scp_core::context::{ContentPath,MimeType,validate_deploy_id}
- Pattern: WASM reimplementations of scp-core validators consistently miss defensive checks that the core version has. Always diff WASM vs core line-by-line when reimplementing.
