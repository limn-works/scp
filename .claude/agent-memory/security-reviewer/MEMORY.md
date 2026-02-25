# Security Reviewer Memory

## SCP Codebase Security Patterns

### Adversarial Review (PR#4) -- Black Hat Findings
- See `/tmp/black-hat-review.md` and PR#4 comment for full details
- 10 attack narratives (BLACK-001 through BLACK-010)
- 5 creative abuse scenarios (ABUSE-1 through ABUSE-5)
- Key themes: relay metadata surveillance, missing auth guards, no rate limiting, schema bypass, Sybil weakness

### MCP Server (`crates/scp-mcp/src/server.rs`)
- Uses `ContextProvider` trait for testability -- good pattern
- `tools/list` filters by both role (admin_only) and UCAN capability -- good
- `tools/call` validates UCAN before invocation -- good
- FINDING (PR#4): No pre-initialization guard on `handle_request` -- all methods accepted before handshake
- FINDING (PR#4): `resources/read` has no UCAN capability check for member/event/tool data
- FINDING (PR#4): Schema validation is type-check-only, not full JSON Schema (ADR-010 specifies `jsonschema` crate)

### Relay Server (`crates/scp-transport/src/native/server.rs`)
- FINDING (PR#4): Zero rate limiting on PUBLISH, SUBSCRIBE, QUERY, DELETE
- FINDING (PR#4): No storage quota -- InMemoryBlobStorage has no capacity limit
- FINDING (PR#4): No connection limit per IP
- FINDING (PR#4): DELETE is unauthenticated -- any client can delete any blob by blob_id
- FINDING (PR#4): `try_send` silently drops messages when channel full (censorship vector)

### TransportManager (`crates/scp-transport/src/manager.rs`)
- Multi-relay fanout via `FuturesUnordered` -- correct async pattern
- LRU + TTL dedup in `MergedStream::is_duplicate()` -- good implementation
- FINDING (PR#4): ADR-012 criterion 7 (multi-relay cross-check/suppression detection) not implemented
- FINDING (PR#4): `send_to_context` is `&mut self` which prevents concurrent sends

### UCAN (`crates/scp-core/src/crypto/ucan/`)
- 11-step validation pipeline is thorough -- good
- Ed25519 signature verification is correct -- good
- FINDING (PR#4): `validate_ucan_stateless` skips nonce, revocation, chain, attenuation checks
- FINDING (PR#4): `InMemoryNonceTracker` is not per-context -- cross-context nonce collisions possible
- FINDING (PR#4): `now_secs()` uses `unwrap_or_default()` -- returns 0 on clock error
- FINDING (PR#4): Nonce tracker has no capacity limit -- memory exhaustion possible

### Identity & DID (`crates/scp-core/src/identity/`)
- Self-certifying DIDs with BEP44 signature verification -- good
- DID cache with TTL staleness detection -- good
- Pseudonyms are deterministic via HMAC-SHA256 -- good for consistency, bad for privacy (no rotation)

### Media Keys (`crates/scp-media/src/keys.rs`)
- MLS exporter usage (RFC 9420 s8) is correct -- label + context domain separation, epoch binding
- FINDING (PR#4): `MediaKeyMaterial.dtls_srtp_keys` is `Vec<u8>` with no zeroization (no `zeroize` dep)
- FINDING (PR#4): `MediaKeyMaterial` derives `Serialize, Deserialize, Debug, Clone` -- key material can leak to logs/disk
- FINDING (PR#4): No minimum key length enforcement -- callers can request 1-byte keys
- FINDING (PR#4): `label` param is caller-controlled, no validation -- domain separation bypass possible

### Signaling (`crates/scp-media/src/signaling.rs`)
- FINDING (PR#4): `sender_did` in `SessionDescription`/`Candidate` is self-asserted, no binding to SCP envelope auth

### Shadow Identity (`crates/scp-core/src/bridge/shadow.rs`)
- Capability restriction via `VERIFIED_IDENTITY_CAPABILITIES` is comprehensive -- good
- Context isolation via `ShadowRegistry` per-context scoping -- good
- FINDING (PR#4): `ShadowRegistry` has no capacity limit on shadows/events Vecs
- FINDING (PR#4): `GovernanceAction` has no signature -- any caller can forge governance actions
- FINDING (PR#4): `upgrade_shadow_role` allows downgrades despite the name -- audit trail confusion

### FFI Bridge (`crates/scp-ffi/src/lib.rs`)
- OnceLock for tokio runtime singleton -- correct pattern
- atexit registration for shutdown coordination -- correct Python/Rust lifecycle
- `#![allow(unsafe_code)]` (not forbid) -- correct FFI exception per rust.md
- FINDING (PR#4): `init_runtime` uses `expect()` -- panic across FFI boundary risk
- FINDING (PR#4): `shutdown_runtime` blocks GIL for full 5s unconditionally

### MCP Transports (`crates/scp-mcp/src/stdio.rs`, `sse.rs`)
- FINDING (PR#4): SSE has no auth, no body size limit, no rate limiting (HIGH)
- FINDING (PR#4): SSE shares single McpServer across all connections -- no session isolation (HIGH)
- FINDING (PR#4): SSE broadcast silently drops messages for lagged receivers
- FINDING (PR#4): stdio has no line size limit -- unbounded memory allocation
- FINDING (PR#4): Duplicated JSON-RPC parsing between stdio and SSE
- FINDING (PR#4): Notification handling via synthetic request with dummy ID 0

### MCP Client (`crates/scp-mcp/src/client.rs`)
- Trait-based McpTransport abstraction -- good testability
- Provenance wrapping (ExternalToolProvenance) -- enforces provenance-everywhere
- AtomicI64 for request IDs -- correct lock-free pattern
- FINDING (PR#4): SystemTimestamp::now_millis returns 0 on clock error
- FINDING (PR#4): McpClient not Send+Sync -- design limitation for async
- NOTE: TransportConfig::Stdio stores command string -- flag for injection review when subprocess spawning added

### General Patterns
- No `unwrap`/`expect` in lib code -- project standard enforced via clippy deny
- `thiserror` for error types -- consistent across crates
- Rust edition 2024, `#![forbid(unsafe_code)]` on all crates
- No `std::sync::Mutex` allowed -- but `ContextManager` violates this (`manager.rs:12`)
- Key material hygiene: `zeroize` crate not yet used anywhere in `scp-media`
- Recurring: `unwrap_or(0)`/`unwrap_or_default()` on clock ops -- systemic across UCAN and MCP client
