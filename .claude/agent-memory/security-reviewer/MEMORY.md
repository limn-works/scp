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
- FIXED: claim_shadow Ed25519 sigs, RFC 6962 domain separation, allowed_adapters, CertificateData redaction, FFI expect() removal, content_hash Result, validate_child_ttl, standing channel TOCTOU
- REMAINING (HIGH): GovernanceAction (shadow.rs) no signature field; SingleAdminEngine duplicate check after construction
- REMAINING (MEDIUM): Attestation canonical hash uses Debug format for type tag; shutdown_runtime blocks GIL 100ms; SHUTDOWN_TIMEOUT const stale
- UNFIXED: CurrencyCode Deserialize bypasses ASCII; EventLogMetrics Vecs unbounded; SenderVelocityTracker unbounded HashMap

### MCP Server (`crates/scp-mcp/src/server.rs`)
- `tools/list` filters by role + UCAN capability -- good
- `tools/call` validates UCAN before invocation -- good
- FINDING (PR#4): No pre-initialization guard on `handle_request`
- FINDING (PR#4): `resources/read` has no UCAN capability check
- FINDING (PR#4): Schema validation is type-check-only, not full JSON Schema

### Relay Server (`crates/scp-transport/src/native/server.rs`)
- FINDING (PR#4): Zero rate limiting; no storage quota; DELETE unauthenticated

### UCAN (`crates/scp-core/src/crypto/ucan/`)
- 11-step validation pipeline thorough; SpendingCapability attenuation correct
- FINDING (PR#4): `validate_ucan_stateless` skips nonce, revocation, chain, attenuation
- FINDING (PR#4): `now_secs()` uses `unwrap_or_default()` -- returns 0 on clock error
- UNFIXED: `CurrencyCode` serde deserialize bypasses ASCII validation

### Shadow Identity (`crates/scp-core/src/bridge/`)
- REMAINING (HIGH): `GovernanceAction` has no signature
- REMAINING (MEDIUM): Attestation canonical hash uses Debug format; attestation.claim JSON not canonically ordered
- NEW FINDING (HIGH): Canonical hash no field separators -- concatenation collision risk
- NEW FINDING (MEDIUM): did:key:<hex> non-standard, not gated behind cfg(test); shadow governance check only compares shadow_id

### FFI Bridge -- PyO3 (`crates/scp-ffi/src/`) -- Audit 2026-02-28
- See `pyo3-audit-20260228.md` for full PR#112 fix list
- HIGH: expect() panic across FFI in py_context_create (line 457) -- unguarded clock call
- REMAINING (MEDIUM): docker/podman in default allowlist
- TRACKED (TODO #106): validate_capability always Ok(()) -- defense-in-depth gap
- TRACKED: registries unbounded (#108), recursion depth (#110), clock drift (#107)
- SCP-212 (2026-02-28): invoke_tool dispatches to registered ToolHandler closures
  - HIGH: No ToolInvokedEvent appended to event_log -- ADR-010 spec gap (no audit trail)
  - HIGH: mcp_register_tool_handler Rust fn not wrapped in Python SDK (mcp.py) -- unreachable to SDK users
  - MEDIUM: DashMap shard lock held during Python handler execution -- free-threaded Python shard starvation risk; fix by cloning handler Arc before entering with_context
  - MEDIUM: No timeout on Python handler call -- blocking handler can starve tokio runtime
  - BUG: Redundant second tool_registry.get() in output-schema validation; make unconditional (fail-closed)
  - GOOD: Callable check at registration; tool-existence gate before handler stored; input+output schema validation

### FFI Bridge -- UniFFI (`crates/scp-ffi/uniffi/`) -- PR#86
- CRITICAL: scp-platform testing feature in production deps (cdylib)
- HIGH: transport_connect accepts ANY URL scheme -- no wss:// enforcement
- MEDIUM: std::sync::Mutex in async context; serde_json errors may leak struct details

### FFI Bridge -- WASM (`crates/scp-ffi/wasm/`) -- PR#86
- FIXED: transport_connect now rejects non-wss:// URLs
- MEDIUM: WasmDIDDocument::from_fields no validation; context_send base64 check is_empty() only; panic hook leaks file paths; Missing #![forbid(unsafe_code)]; JsMessageCallback lacks catch

### FFI Bridge -- NAPI (`crates/scp-ffi/napi/`) -- PR#86
- CRITICAL: scp-platform testing feature in production deps (cdylib)
- HIGH: unreachable!() in identity_create -- panic across FFI
- MEDIUM: std::sync::Mutex in async context; missing #![forbid(unsafe_code)]; status() silently defaults on poisoned mutex

### TLS (`crates/scp-node/src/tls.rs`)
- TLS 1.3 enforced; ACME HTTP-01 correct; CertificateData Debug redacts key
- `zeroize` crate still not used for private key material

### Economy
- UNFIXED: SenderVelocityTracker unbounded HashMap growth
- SCP-156: HIGH: Step 5 missing adapter.verify() -- no cryptographic auth validity check
- SCP-156: MEDIUM: Dummy PaymentAuthorization (zeroed auth_id) on 3 free paths; IntegrationError erased to string
- SCP-160 tests: TestAdapter::verify_authorization() no-op; Invariant 7 test self-referential

### Tiered Storage & Context Discovery
- See `tiered-storage-scp213.md` for full finding details (SCP-127, SCP-213)
- SCP-127: HIGH x2 (checkpoint_root clobbered, index reset); MEDIUM x5
- SCP-213: HIGH BUG x2 (register_known_context never called; `h.context_id` AttributeError)

### General Patterns
- No `unwrap`/`expect` in lib code -- project standard via clippy deny
- `thiserror` for error types; Rust edition 2024; `#![forbid(unsafe_code)]` on all crates except scp-ffi
- `zeroize` crate not yet used anywhere; `unwrap_or_default()` on clock ops is a recurring systemic pattern
- FfiBridgeProvider reimplementing scp-core logic instead of delegating silently drops spec obligations (event log, timeout, request_id) -- always prefer delegation
- DashMap shard locks must not be held across Python GIL acquisition -- clone Arc before entering with_context
- New PyO3 Rust functions must also be wrapped in the Python SDK layer or they are unreachable to SDK users
- Test adapters that return hardcoded values weaken invariant tests; duplicated canonical hash logic in test helpers diverges from production
