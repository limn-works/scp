# White Hat Agent Memory

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
