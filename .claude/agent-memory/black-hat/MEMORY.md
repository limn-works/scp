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

### HIGH: Handle squatting -- zero economic cost for bulk registration
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.3.1

### HIGH: Petname auto-creation permanent after one successful deception
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.8.3, 22.8.4

### HIGH: Privacy -- all lookups DID-authenticated
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.10.4

### HIGH: Cache poisoning via stale-while-revalidate
- File: `.docs/specs/22-human-readable-addressing.md` Section 22.8.4

## Key Attack Surfaces -- PR #127 Second Pass (post-fix)

### CRITICAL: WASM bridge UCAN validation still missing 6/11 steps
- File: `crates/scp-ffi/wasm/src/ucan.rs`
- Ed25519 sig verification ADDED but steps 3-5, 7-9 still missing
- Self-signed DIDs pass: attacker encodes own pubkey in DID, signs with own key
- No root issuer check, no audience check, no delegation chain, no nonce tracking

### HIGH: context_close auth bypass on NAPI/WASM/UniFFI (UNFIXED)
- PyO3 fixed (checks ContextClose capability)
- NAPI: `crates/scp-ffi/napi/src/context.rs` line 430 `let _ = identity_did`
- WASM: `crates/scp-ffi/wasm/src/context.rs` line 579 `let _ = identity_did`
- UniFFI: `crates/scp-ffi/uniffi/src/bridge.rs` line 1704 `let _ = identity`

### HIGH: Broadcast UCAN validation still skips all crypto
- File: `crates/scp-core/src/context/broadcast.rs` lines 423-442
- Wildcard rejection added (RED-012) but no sig/expiry/issuer/chain checks
- Forged UcanToken struct with correct `aud` + `att` string bypasses

### HIGH: NAPI/UniFFI mint zero-signature tokens with no unsigned indicator
- NAPI: `crates/scp-ffi/napi/src/ucan.rs` line 432 `[0u8; 64]`
- UniFFI: `crates/scp-ffi/uniffi/src/bridge.rs` line 2181 `[0u8; 64]`
- No `is_signed` field, tokens appear production-ready

### MEDIUM: Nonce replay TOCTOU -- substantially improved
- File: `crates/scp-core/src/store/ucan.rs` lines 236-267
- Post-write re-verification added, in-memory path serialized by DashMap
- Residual risk only during crash recovery window

### MEDIUM: Cover traffic size/timing distinguishability
- File: `crates/scp-transport/src/cover_traffic.rs`
- Fixed 30s interval + fixed 1024-byte size = distinguishable pattern

### MEDIUM: Attestation renewal re-verifies internal fields only
- File: `crates/scp-core/src/trust/renewal.rs` lines 93-125
- Fix added verify_attestation call (good), but external evidence not re-fetched

## Patterns Confirmed Working (PR #127)
- Broadcast key isolation per author sound (AES-256-GCM, random nonces)
- Epoch overflow protection at u64::MAX
- Key material Debug redaction across all bridges
- scp-core 11-step UCAN pipeline thorough when invoked (NAPI/UniFFI/PyO3)
- NAPI TLS enforcement (rejects ws://)
- Nonce replay (in-memory path) serialized by DashMap entry locks
- Heartbeat suppression detection sound
- Broadcast wildcard rejection (RED-012)
- PyO3 context_close authorization check
- Merkle checkpoint equivocation detection

## Patterns Confirmed Working (prior PRs)
- Ceiling inheritance in nesting is sound
- Template spoofing detection works correctly
- Shadow capability restrictions (VERIFIED_IDENTITY_CAPABILITIES) solid
- Auto-accept hard rules (tools, payment) non-bypassable
- Budget tracker uses saturating arithmetic throughout
- UCAN attenuation validation is thorough
- ASCII-only local-part blocks Unicode homoglyph attacks
- DID canonical identity + MLS binding = resolution hijack cannot forge messages
