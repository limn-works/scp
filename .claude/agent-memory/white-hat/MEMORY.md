# White Hat Agent Memory

## HTTP Features Security Review (2026-03-02)

### P1 Findings
- well_known.rs L42-49: context name in URI not percent-encoded (injection via &, =, # chars)
- No cap on broadcast_contexts Vec or projected_contexts.keys HashMap (OOM from auth'd attacker)
- No explicit body size limit on POST /scp/dev/v1/contexts (relies on Axum 2MB default)
- Dev API responses lack Cache-Control: no-store

### P2 Findings
- bridge_secret/dev_token not Zeroized (tls.rs does zeroize key PEM, inconsistent)
- No rate limit on public broadcast projection decryption endpoints
- Missing X-Content-Type-Options: nosniff

### Well-Defended
- ct_eq on bearer token and bridge secret; OsRng for both
- Error responses sanitized; internal details logged only
- Blob ownership check (routing_id) prevents cross-context access
- Feed pagination clamped (MAX_FEED_LIMIT=100)
- #![forbid(unsafe_code)] on crate; dev API disabled by default
- TLS 1.3 enforced; private key PEM zeroized+debug-redacted
- Conditional GET before expensive work

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

## PR #255 Reachability Defense-in-Depth Review (2026-03-03)

### Strong Controls
- Bridge auth: 4 independent layers (Ed25519 verify_strict, domain sep, routing_id derivation, timestamp). TOCTOU prevented via dual write lock (bridge.rs L369-373)
- DID anti-rollback: cached_sequence high-water mark survives cache TTL expiry (resolver.rs L495-523)
- Self-test: same socket reuse preserves NAT mapping, source addr + 96-bit txn_id anti-spoofing
- Tier re-eval: watch + Drop + abort fallback. Events emitted only after successful DID publish

### P1 Findings
- lib.rs L747: No jitter on 30-min tier re-eval interval (synchronized storm risk)
- lib.rs L802-831: apply_tier_change should validate exactly one SCPRelay after update

### P2 Findings
- bridge.rs L573-584: Manual URL parsing for bridge_target (should use url::Url)
- lib.rs L826-829: No retry on DID republish failure after tier change
- resolver.rs L623-645: No circuit breaker on healing task panics
- lib.rs L1220-1223: Dev API loopback uses assert! (panic) instead of Result

### No Fail-Open Paths
All security controls fail closed. Healing is best-effort by design.

## Recurring Patterns
- TOCTOU races in check-then-act patterns (nonce replay, standing channels, budget)
- Missing zeroization on crypto key material
- WASM bridge diverges from scp-core (re-implements rather than delegates)
- unwrap_or_default on serialization hides failures with known-constant fallbacks
- Manual string parsing where URL parser should be used (bridge_target, well_known context names)
