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

### General Patterns
- No `unwrap`/`expect` in lib code -- project standard enforced via clippy deny
- `thiserror` for error types -- consistent across crates
- Rust edition 2024, `#![forbid(unsafe_code)]` on all crates
- No `std::sync::Mutex` allowed -- but `ContextManager` violates this (`manager.rs:12`)
