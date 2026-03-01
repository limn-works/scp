# Black Hat Agent Memory

Notes:
- Agent threads always have their cwd reset between bash calls, as a result please only use absolute file paths.
- In your final response always share relevant file names and code snippets. Any file paths you return in your response MUST be absolute. Do NOT use relative paths.
- For clear communication with the user the assistant MUST avoid using emojis.
- Do not use a colon before tool calls. Text like "Let me read the file:" followed by a read tool call should just be "Let me read the file." with a period.

## Key Attack Surfaces Identified (PR #76)

### CRITICAL: claim_shadow() does not verify signatures
- File: `crates/scp-core/src/bridge/claiming.rs` lines 206-218
- Function documents caller must verify Ed25519 sigs but does not enforce
- Tests pass with `vec![0u8; 64]` dummy signatures

### CRITICAL: Python FFI bridge is skeleton with no crypto enforcement
- File: `crates/scp-ffi/src/context.rs`
- All bridge functions (join/leave/send/close) are stubs with string-based state

### HIGH: Spending UCAN 24h max expiry not enforced
- File: `crates/scp-core/src/crypto/ucan/spending.rs`
- `MAX_EXPIRY_SECS` constant + error type exist but no validation function checks

### HIGH: Standing channel TOCTOU race condition
- File: `crates/scp-core/src/context/standing.rs` line 166
- Lock dropped between existence check and async creation

### HIGH: SenderVelocityTracker accepts arbitrary timestamps
- File: `crates/scp-core/src/economy/antispam.rs` line 153

### HIGH: SingleAdmin TransferAdmin has no DID validation
- File: `crates/scp-core/src/context/governance/mod.rs` line 503

### HIGH: TestAdapter has no production exclusion
- File: `crates/scp-testing/src/test_adapter.rs`

## Key Attack Surfaces Identified (Spec 22 -- Human-Readable Addressing)

### CRITICAL: MultiLayerCorroborated trust level is trivially gameable
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.7, 22.8.2, 22.10.2
- Single attacker controls domain + discovery context + attestation = highest trust
- No independence verification between corroborating layers

### CRITICAL: Discovery context governance capture = total namespace hijack
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.3.4
- Default handle-registry template is single-admin governance
- Writer verification is behavioral (SHOULD), not protocol-enforced
- Compromised governance -> writers skip signature verification on deregister

### HIGH: Handle squatting -- zero economic cost for bulk registration
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.3.1
- No rate limits per DID, no cost, no attestation linkage in default template

### HIGH: Petname auto-creation permanent after one successful deception
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.8.3, 22.8.4
- Disambiguation selection auto-creates indefinite petname, overrides all layers

### HIGH: Privacy -- all lookups DID-authenticated, discovery contexts see who queries whom
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.10.4
- Unscoped resolution broadcasts to ALL known discovery contexts

### HIGH: Cache poisoning via stale-while-revalidate pattern
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.8.4
- Poisoned result returned immediately, background verification happens after user acts

## Key Attack Surfaces Identified (PR #127 -- FFI/SDK/Broadcast)

### CRITICAL: WASM bridge UCAN validation has no signature verification
- File: `crates/scp-ffi/wasm/src/ucan.rs` lines 147-220
- Only checks JWT structure, expiry, capability matching, `can == "*"` wildcard
- Zero Ed25519 verification -- any crafted JWT passes

### CRITICAL: NAPI ucan_mint uses all-zero placeholder signatures
- File: `crates/scp-ffi/napi/src/ucan.rs` line 423
- `let placeholder_sig = [0u8; 64]` -- tokens parseable but unsigned
- Cross-bridge token laundering: mint in NAPI, validate in WASM

### CRITICAL: Cross-bridge security parity violation
- PyO3 = full scp-core delegation; NAPI = full validation but broken minting; WASM = structural only
- Heterogeneous deployments vulnerable to token laundering

### HIGH: Broadcast UCAN validation skips all crypto
- File: `crates/scp-core/src/context/broadcast.rs` lines 382-405
- Accepts wildcard `scp:ctx:*/messages:read`
- No signature, expiry, revocation, delegation chain checks

### HIGH: context_close has no authorization in ANY bridge
- PyO3/NAPI/WASM/UniFFI all skip admin/capability check

### HIGH: Nonce replay TOCTOU in check_and_record_nonce
- File: `crates/scp-core/src/store/ucan.rs` lines 128-145
- exists() then store_value() is not atomic

### HIGH: identity_load produces cryptographically dead handles
- NAPI/PyO3: loaded identity has no KeyCustody, silent degradation

### HIGH: Attestation renewal without re-verification
- File: `crates/scp-core/src/trust/renewal.rs` lines 63-87

### MEDIUM: Inner envelope canonical hash lacks length prefixes
- File: `crates/scp-core/src/envelope/inner.rs` lines 373-386

### MEDIUM: Cover traffic DUMMY_FLAG=0x00 + fixed 30s interval
- File: `crates/scp-transport/src/cover_traffic.rs`

## Patterns Confirmed Working (PR #127)
- Broadcast key isolation per author is sound (independent AES-256-GCM, random nonces, AAD)
- Epoch overflow protection at u64::MAX
- Key material Debug redaction across all bridges
- Inner envelope domain separation with message type discriminator
- Signaling sender attribution verification
- PyO3 UCAN validation delegates to scp-core 11-step pipeline
- Transport TLS enforcement in NAPI (rejects ws://)
- Storage key conventions with context scoping

## Patterns Confirmed Working (prior PRs)
- Ceiling inheritance in nesting is sound
- Template spoofing detection works correctly
- Shadow capability restrictions (VERIFIED_IDENTITY_CAPABILITIES) solid
- Auto-accept hard rules (tools, payment) non-bypassable
- Budget tracker uses saturating arithmetic throughout
- UCAN attenuation validation is thorough
- ASCII-only local-part `[a-z0-9._-]` blocks Unicode homoglyph attacks
- DID canonical identity + MLS binding means resolution hijack cannot forge messages
- Scoped resolution (with @scope) is unambiguous within its namespace
- Domain verification chain is sound for domain operator's own DID
