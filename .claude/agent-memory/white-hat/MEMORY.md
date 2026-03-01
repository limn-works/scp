# White Hat Agent Memory

## PR #127 Security Review (2026-03-01)

### P0 Findings
- WASM ucan_validate (wasm/src/ucan.rs L147-220) skips Ed25519 signature verification entirely
- WASM compute_token_cid hashes raw string, scp-core compute_revocation_cid hashes JSON payload -- revocation CID mismatch
- WASM ucan_revoke hashes token_id not full JWT payload -- third CID variant
- No zeroization on SenderKey, BroadcastKey, SenderKeyStore (Clone derived, no Drop+Zeroize)
- check_and_record_nonce (store/ucan.rs L128-145) has TOCTOU race

### P1 Findings
- NAPI ucan_mint uses [0u8; 64] placeholder signature (napi/src/ucan.rs L423) -- stub for SCP-214
- HeartbeatConfig.suppression_threshold_multiplier is f64, no NaN/Infinity validation
- WASM ucan_mint silently drops non-string capabilities via filter_map
- Storage keys use unsanitized DID/context_id strings (potential traversal)
- WASM runtime re-implements scp-core logic (divergence risk caused revocation CID mismatch)

### Well-Defended
- RevocationPending treated as revoked (fail-closed revocation state machine)
- Inner envelope MessageType discriminator prevents type-flipping
- Broadcast key independence (fresh random per epoch, not HKDF)
- Debug redaction on SenderKey and BroadcastKey
- NAPI full 11-step validate_ucan pipeline with real Ed25519
- PyO3 real Ed25519 signing via KeyCustody
- Epoch overflow checked with checked_add
- AES-256-GCM nonces from OsRng
- ProtocolStore version envelope rejects future versions
- Signaling sender attribution verification

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
