# Governance Gaps Security Audit (closes #266) -- 2026-03-05

## Scope
18 files, ~3,689 lines added. Three features:
1. Projection auth (UCAN Bearer on gated broadcast endpoints)
2. Metadata visibility (per-field MetadataVisibilityPolicy)
3. Broadcast bans (MemberBan ceiling gates RevokeReadAccess/RestoreReadAccess)

## Findings

### HIGH: validate_projection_ucan skips Ed25519 signature verification
- File: projection.rs:261-305
- parse_ucan() only checks JWT structure + header fields (alg=EdDSA, ucv=0.10.0)
- No sig verify, no expiry, no nbf, no delegation chain, no revocation, no nonce
- Test build_test_ucan uses [0u8; 64] signature -- passes
- Fix: verify Ed25519 sig + check exp at minimum

### HIGH: Per-author Gated override checked after decryption
- File: projection.rs:782-883 (message_handler)
- When default=Public, pre-auth skipped, blob fetched+decrypted, then per-author check
- Timing oracle reveals which authors have Gated overrides
- Fix: pre-check strictest possible rule before any I/O

### MEDIUM: Feed endpoint ignores per-author overrides
- File: projection.rs:615-621
- effective_projection_rule called with None author_did
- Gated authors' content served openly through feed
- Fix: filter or require auth if any override is Gated

### MEDIUM: RevocationScope ignored
- File: manager.rs:1604 (_scope parameter)
- Full and FutureOnly produce identical behavior in broadcast
- API misleads callers into thinking Full is retroactive
- Fix: reject Full for broadcast or document equivalence

### MEDIUM: governance_unban_subscriber accepts non-banned DIDs
- File: broadcast.rs:700-704
- No check if DID is on any block list
- Meaningless proposals consumed + misleading events emitted
- Fix: return error if DID not on any block list

### MEDIUM: conflict_resolution missing RestoreReadAccess x RestoreReadAccess
- File: conflict_resolution.rs:315-340
- RevokeReadAccess x RevokeReadAccess handled
- RevokeReadAccess x RestoreReadAccess handled (both directions)
- RestoreReadAccess x RestoreReadAccess NOT handled
- Fix: add the missing match arm

### MEDIUM: No expiry check on UCAN in projection
- File: projection.rs:275-305
- Subsumed by the HIGH finding but worth tracking separately
- Even with sig verification added, expired tokens would still work

## Positive Patterns
- BLACK-HTTP-005: routing_id cross-check before conditional GET (correct ordering)
- Cache-Control: private for gated content (both feed and per-message)
- Proposal replay protection: executed_proposals checked inside lock, persisted
- KeyRequestDecision::Grant uses Zeroizing<[u8; 32]>; Debug redacts key
- Uniform DENY_REASON in handle_key_request prevents block list status leakage
- MemberBan ceiling enforcement inside lock scope (cannot bypass)
- filter_field returns None unconditionally for MemberOnly
- Bearer token extraction case-insensitive per RFC 7235
- Epoch overflow via checked_add on all key rotation paths
- governance_ban_subscriber rotates ALL authors (complete key rotation)
