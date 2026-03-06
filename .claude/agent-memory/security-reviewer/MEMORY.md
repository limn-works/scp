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
- 7 commits reviewed: sender key msgpack, HPKE domain sep, deny_unknown_fields, ProtocolStore named msgpack, dedup TTL, serde rename, conflict pairs
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

### FFI Bridge -- WASM (`crates/scp-ffi/wasm/`) -- PR#86 + PR#127 R2
- HIGH: did:key hex in production; runtime.rs reimplements scp-core logic
- GOOD: Full 11-step UCAN validation; RED-105 prefix collision protection

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

### General Patterns
- clippy deny unwrap/expect in lib code; thiserror; Rust 2024; #![forbid(unsafe_code)] except scp-ffi
- zeroize inconsistent: store layer yes, identity signing keys and MLS key pairs no
- unwrap_or_default() on clock ops is recurring systemic pattern
- DashMap shard locks must not cross Python GIL; clone Arc first
- Static DashMap registries lack eviction
- validate_projection_ucan structural-only -- recurring UCAN validation gap
- Signed wire types should have deny_unknown_fields (InnerEnvelope fixed; sender key types still missing)
- handle_sender_key_request has no timestamp freshness or NonceDedup integration
