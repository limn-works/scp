# White Hat Agent Memory

## PR #127 Defense-in-Depth Review (2026-03-01)

### Fixed Since Prior Review
- WASM Ed25519 verification now implemented (wasm/src/ucan.rs L402-452 verify_token_signature)
- SenderKey and BroadcastKey now derive Zeroize+ZeroizeOnDrop
- WASM revocation CID now uses compute_revocation_cid(WasmUcanPayload) matching scp-core

### P0 Current Findings
- UniFFI ucan_revoke stores raw token_id string, NOT content-hash CID (bridge.rs L2220-2226) -- revocations invisible to validate step 10

### P1 Current Findings
- NAPI proof resolver uses compute_revocation_cid instead of compute_cid for proof chain (napi/src/ucan.rs L308) -- CID mismatch with PyO3
- Broadcast validate_messages_read_ucan skips signature/expiry/revocation checks (broadcast.rs L423-442)
- WASM ucan_mint silently drops non-string capabilities via filter_map (wasm/src/ucan.rs L317-327)
- spending.rs uses unwrap_or_default for system clock (L676, L709, L785) -- should return Err like mint.rs
- HeartbeatConfig.suppression_threshold_multiplier f64 no NaN/Infinity validation (heartbeat.rs L54)
- Storage keys use unsanitized context_id/token_id strings (store/ucan.rs L49-74)
- NAPI/UniFFI ucan_mint use [0u8; 64] placeholder signature (SCP-214 scope)
- WASM missing 5 of 11 validation steps (SCP-218 scope)

### Well-Defended
- scp-core 11-step validate_ucan pipeline with verify_strict Ed25519
- RevocationPending treated as revoked (fail-closed state machine)
- Broadcast key independence (fresh OsRng per epoch, not HKDF)
- Debug redaction on SenderKey and BroadcastKey
- NAPI/PyO3/UniFFI all delegate validate to scp-core pipeline
- PyO3 real Ed25519 signing via retained KeyCustody
- Epoch overflow checked_add on all paths
- AES-256-GCM nonces from OsRng
- Cover traffic constant-rate invariant (dummies never suppressed)
- Delegation chain cycle detection with depth limit (32)
- Nonce defense-in-depth (in-memory primary + ProtocolStore persistence)

## PR #76 Security Review (2026-02-26)

### Critical Findings
- claim_shadow() does NOT verify Ed25519 signatures (claiming.rs L207-218) - caller responsibility
- BudgetTracker in spending.rs is not thread-safe for concurrent async access
- StandingChannelManager has TOCTOU race between lock drop (L165) and re-acquire (L173)
- check_and_composition accepts bare Amount from caller - cost should be derived from CostSchedule
- SenderVelocityTracker has unbounded HashMap growth (Sybil DID exhaustion)
- ParentGovernanceConfig::content_hash uses unwrap_or_default on JSON serialization
- VERIFIED_IDENTITY_CAPABILITIES is string-based, not type-system enforced
- RateLimitTracker resets on SDK restart (not persisted)
- TestAdapter has no production/test boundary enforcement

### Well-Defended Areas
- Invitation pipeline: sequential evaluation with fail-through to PromptAgent
- Spending attenuation: each field checked independently, delegation only narrows
- MLS group_context extension: cryptographic binding of parent lineage
- Shadow default-deny: observer role + explicit capability blocklist
- Saturating arithmetic throughout economy module
- PyO3 bridge: no KeyHandle exposure across GIL, frozen classes

### Key Architecture Notes
- Governance engines: only SingleAdminEngine implemented, Threshold/Majority/Unanimity are stubs
- FFI bridge UCAN functions are stubs returning errors (correct fail-closed)
- Anti-spam tracks per-DID independently (Sybil deterrent)
- Standing channels use deterministic SHA-256 IDs from sorted DID pairs

## Recurring Patterns
- TOCTOU races in check-then-act patterns (nonce replay, standing channels, budget)
- Missing zeroization on crypto key material
- WASM bridge diverges from scp-core (re-implements rather than delegates)
- unwrap_or_default on serialization hides failures with known-constant fallbacks
