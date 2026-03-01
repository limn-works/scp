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
- Routing ID derivation (2026-02-28): FIXED -- now uses HMAC-SHA256(per-identity random secret, context_id || "scp-pseudonym") instead of SHA-256(context_id). Previous version had no unlinkability.
  - MEDIUM: Routing secret not zeroized; IDENTITY_ROUTING_SECRETS DashMap grows unboundedly; no eviction on identity close
  - MEDIUM: HMAC domain separation uses concatenation without length prefix (consistent with scp-core spec; both should fix)
  - GOOD: OsRng for secret generation; error handling on HMAC init; interim design matches scp-core pseudonym.rs pattern

### FFI Bridge -- UniFFI (`crates/scp-ffi/uniffi/`) -- PR#86 + PR#127
- CRITICAL: scp-platform testing feature in production deps (cdylib)
- HIGH: transport_connect accepts ANY URL scheme -- no wss:// enforcement
- HIGH: did:key: hex format not gated behind cfg(test) in BridgeDidResolver
- MEDIUM: std::sync::Mutex in async context; serde_json errors may leak struct details
- MEDIUM: generate_nonce uses thread_rng() instead of OsRng (diverges from NAPI)
- MEDIUM: custody_type() returns Hardware as silent default on lock contention

### FFI Bridge -- WASM (`crates/scp-ffi/wasm/`) -- PR#86 + PR#127
- FIXED (PR#127): ucan_validate now has Ed25519 signature verification via verify_strict
- REMAINING (MEDIUM): ucan_mint returns unsigned tokens (metadata-only, no Ed25519 signing) -- SCP-218 scope
- HIGH: runtime.rs reimplements scp-core logic (Merkle tree, schema, tool registry) -- divergence risk
- MEDIUM: context_send base64 check is_empty() only; panic hook leaks file paths
- MEDIUM: Context IDs use UUID format not crypto-random hex per spec 18.4.1
- MEDIUM: compute_revocation_cid uses unwrap_or_default() on serde_json -- silent CID collision on serialize failure

### FFI Bridge -- NAPI (`crates/scp-ffi/napi/`) -- PR#86 + PR#127
- CRITICAL: ucan_mint uses [0u8; 64] placeholder zero signature
- HIGH: did:key: hex format not gated behind cfg(test) in BridgeDidResolver
- MEDIUM: Context IDs use UUID format not crypto-random hex per spec 18.4.1
- MEDIUM: std::sync::Mutex in async context; missing #![forbid(unsafe_code)]

### TLS (`crates/scp-node/src/tls.rs`)
- TLS 1.3 enforced; ACME HTTP-01 correct; CertificateData Debug redacts key
- `zeroize` crate still not used for private key material

### Economy
- UNFIXED: SenderVelocityTracker unbounded HashMap growth
- SCP-156: HIGH: Step 5 missing adapter.verify() -- no cryptographic auth validity check
- SCP-156: MEDIUM: Dummy PaymentAuthorization (zeroed auth_id) on 3 free paths; IntegrationError erased to string
- SCP-160 tests: TestAdapter::verify_authorization() no-op; Invariant 7 test self-referential

### Android Platform Adapter (SCP-110, SCP-111, SCP-112, SCP-113) -- 2026-02-28
- AndroidKeyCustody.kt: HIGH CRYPTO BUG: derivePseudonym uses publicKey() as HMAC key -- correct per ADR-027 amendment, BUT InMemoryKeyCustody (Rust) still uses private key bytes. Cross-platform mismatch. See below.
- AndroidKeyCustody.kt: HIGH BUG: publicKeyFromKeystore takeLast(32) is fragile -- assumes SubjectPublicKeyInfo header is exactly 12 bytes
- AndroidKeyCustody.kt: MEDIUM: softwareKeys ConcurrentHashMap uses keyHandle.id as key but dispatches on custodyType field
- AndroidDeviceAttestation.kt: MEDIUM LEAKAGE: catch block passes e.message to ScpException
- dhAgree: no validation that peerPublic is exactly 32 bytes
- AndroidStorage.kt (SCP-113): FIXED in 0b14afe: setRandomizedEncryptionRequired(false), passphrase ByteArray zeroing, SQL LIKE escaping, deletePrefix transaction, error message sanitization, store/retrieve->set/get rename
  - REMAINING: JVM String immutability limits passphrase zeroing (documented, accepted risk)
  - REMAINING: InMemoryStorageProvider tests don't exercise SQLCipher code paths (documented in test header)

### Pseudonym HMAC Key Material Inconsistency -- HIGH (discovered 2026-02-28)
- InMemoryKeyCustody (key_custody.rs line 333) uses `signing_key.to_bytes()` (PRIVATE key) as HMAC key
- ADR-006 (phase-1.md line 200), ADR-027 (phase-6.md lines 173-177), traits.rs (line 340), WASM custody.rs (line 97), 09-security-model.md all say PUBLIC key bytes
- Android adapter uses publicKey() (correct per ADR-027 amendment)
- Golden vector test (key_custody.rs line 638) uses private seed bytes -- self-consistent but wrong
- Fix: change InMemoryKeyCustody to use `signing_key.verifying_key().to_bytes()` and regenerate golden vectors
- This breaks cross-platform pseudonym determinism until fixed

### Tiered Storage & Context Discovery
- See `tiered-storage-scp213.md` for full finding details (SCP-127, SCP-213)
- SCP-127: HIGH x2 (checkpoint_root clobbered, index reset); MEDIUM x5
- SCP-213: HIGH BUG x2 (register_known_context never called; `h.context_id` AttributeError)

### Kotlin SDK (`bindings/kotlin/scp-sdk-kotlin/`)
- CoroutineBridge awaitClose uses runBlocking(ioDispatcher) -- safe for Dispatchers.IO but deadlock risk on single-threaded test dispatchers
- callbackFlow subscribe/unsubscribe pattern is correct; trySend with overflow detection is good

### Governance Engines (PR#127 -- `scp-core/src/context/governance/`)
- HIGH: SignedVote.signature always Vec::new() -- votes never signed or verified
- HIGH: compute_proposal_id concatenation without length prefixes -- collision risk
- GOOD: Deadline guards on approve/reject/withdraw in all engines (multisig, unanimity, majority)
- GOOD: Duplicate proposal rejection; deterministic proposal IDs; early resolution rules correct
- GOOD: All engines are Send + Sync; GovernanceEngine trait is object-safe
- mls_integration.rs: clean separation of governance/MLS concerns; epoch coordinator correct

### CI/CD Security (PR#127 -- `.github/workflows/`)
- MEDIUM: pr-review.yml grants contents:write with Claude agent reading untrusted diffs
- MEDIUM: claude.yml grants contents:write triggered by any @claude comment (no collaborator check)
- MEDIUM: release.yml uses --allow-dirty for cargo publish
- MEDIUM: build-matrix.yml uses curl|sh for wasm-pack install
- GOOD: build-matrix.yml uses permissions: contents: read (minimal)
- GOOD: rust-deny job runs cargo-deny for supply chain security
- GOOD: PyPI uses OIDC Trusted Publishers (no stored token)

### Broadcast Context (`scp-core/src/context/broadcast.rs`) -- PR#127
- MEDIUM: validate_messages_read_ucan checks aud + att only -- no expiry, signature, revocation, or chain verification
- MEDIUM: subscribers/authors/block_list HashMaps unbounded -- Sybil risk on open broadcast contexts
- GOOD: Wildcard UCAN rejection (RED-012); epoch overflow via checked_add; per-author key isolation

### Event Log Checkpoint (`scp-core/src/event_log/checkpoint.rs`) -- PR#127
- HIGH: compute_checkpoint_canonical_hash lacks length prefixes and domain separator
- MEDIUM: current_timestamp() uses unwrap_or(0) on clock failure -- zero-timestamp checkpoints
- MEDIUM: CheckpointManager::checkpoints Vec unbounded growth
- GOOD: Cross-checkpoint verification; pruned inclusion proofs; RFC 6962 interior node hashing

### PyO3 UCAN Bridge (PR#127)
- GOOD: Full 11-step ADR-016 pipeline via scp-core delegation with real Ed25519 signing
- GOOD: MintParams uses real KeyCustody; build_proof_resolver indexes by CID
- GOOD: Tool handler cloned (Arc) before execution -- DashMap shard lock no longer held

### General Patterns
- No `unwrap`/`expect` in lib code -- project standard via clippy deny
- `thiserror` for error types; Rust edition 2024; `#![forbid(unsafe_code)]` on all crates except scp-ffi
- `zeroize` crate not yet used anywhere; `unwrap_or_default()` on clock ops is a recurring systemic pattern
- Inner envelope now uses domain-separated length-prefixed canonical hash -- gold standard pattern for other hash functions to follow
- FfiBridgeProvider reimplementing scp-core logic instead of delegating silently drops spec obligations (event log, timeout, request_id) -- always prefer delegation
- DashMap shard locks must not be held across Python GIL acquisition -- clone Arc before entering with_context
- New PyO3 Rust functions must also be wrapped in the Python SDK layer or they are unreachable to SDK users
- Test adapters that return hardcoded values weaken invariant tests; duplicated canonical hash logic in test helpers diverges from production
- Android Keystore AES-GCM requires setRandomizedEncryptionRequired(false) for deterministic IV usage -- default is true and will throw InvalidAlgorithmParameterException
- SQL LIKE prefix matching without wildcard escaping (% and _) is a recurring KV store risk; prefer ESCAPE clause or range queries (>= and <)
- Static DashMap registries in scp-ffi (CONTEXT_REGISTRY, KNOWN_CONTEXTS, IDENTITY_ROUTING_SECRETS) all lack eviction -- unbounded growth pattern
- Kotlin runBlocking in callbackFlow awaitClose is the correct fix for non-suspend lambda but requires multi-threaded dispatcher
