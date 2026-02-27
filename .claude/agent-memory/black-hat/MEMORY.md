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

## Patterns Confirmed Working
- Ceiling inheritance in nesting is sound
- Template spoofing detection works correctly
- Shadow capability restrictions (VERIFIED_IDENTITY_CAPABILITIES) solid
- Auto-accept hard rules (tools, payment) non-bypassable
- Budget tracker uses saturating arithmetic throughout
- UCAN attenuation validation is thorough
