# White Hat Agent Memory

## Governance-Gaps Feature Review (2026-03-05)

### P1 Findings
- broadcast.rs governance_ban_subscriber L660-683: partial mutation on epoch overflow (authors 1..N mutated, N+1..end not). Fix: pre-validate all epochs before mutating.
- projection.rs validate_projection_ucan L275-305: structural-only (parse_ucan not validate_ucan) -- no signature/expiry/revocation check. Bearer token forgery trivial.

### P2 Findings
- projection.rs L822-829: conditional GET before per-author override auth leaks blob existence for gated authors
- projection.rs L296/L356: AuthorChoice resolves to Gated silently, no mechanism
- projection.rs L224-241: override DIDs not validated against registered authors

### Well-Defended
- Ceiling-gated governance: MemberBan check + replay + active check + mutation all under single Mutex (no TOCTOU)
- Template ceilings by construction: encrypted=MemberBan, broadcast=no MemberBan
- filter_field: total function, exhaustive match, every operational field routed through it
- validate_projection_policy at registration time in enable_broadcast_projection
- Key request DENY_REASON uniform for all deny paths (no block list leak)
- Cache-Control tracks effective auth rule by construction
- Cross-context blob oracle prevented (routing_id check before conditional GET)

## HTTP Features Security Review (2026-03-02)

### P1 Findings
- well_known.rs L42-49: context name in URI not percent-encoded (injection via &, =, # chars)
- No cap on broadcast_contexts Vec or projected_contexts.keys HashMap (OOM from auth'd attacker)
- No explicit body size limit on POST /scp/dev/v1/contexts (relies on Axum 2MB default)
- Dev API responses lack Cache-Control: no-store

### P2 Findings
- bridge_secret/dev_token not Zeroized (tls.rs does zeroize key PEM, inconsistent)
- Missing X-Content-Type-Options: nosniff

### Well-Defended
- ct_eq on bearer token and bridge secret; OsRng for both
- Error responses sanitized; internal details logged only
- Blob ownership check (routing_id) prevents cross-context access
- Feed pagination clamped (MAX_FEED_LIMIT=100)
- #![forbid(unsafe_code)] on crate; dev API disabled by default
- TLS 1.3 enforced; private key PEM zeroized+debug-redacted

## PR #127 Defense-in-Depth Review (2026-03-01)

### P0 Current Findings
- UniFFI ucan_revoke stores raw token_id string, NOT content-hash CID (bridge.rs L2220-2226)

### P1 Current Findings
- NAPI proof resolver uses compute_revocation_cid instead of compute_cid for proof chain
- Broadcast validate_messages_read_ucan skips signature/expiry/revocation checks
- WASM ucan_mint silently drops non-string capabilities via filter_map
- spending.rs uses unwrap_or_default for system clock -- should return Err
- HeartbeatConfig.suppression_threshold_multiplier f64 no NaN/Infinity validation
- Storage keys use unsanitized context_id/token_id strings
- NAPI/UniFFI ucan_mint use [0u8; 64] placeholder signature
- WASM missing 5 of 11 validation steps

### Well-Defended
- scp-core 11-step validate_ucan pipeline with verify_strict Ed25519
- RevocationPending treated as revoked (fail-closed state machine)
- Broadcast key independence (fresh OsRng per epoch, not HKDF)
- Debug redaction on SenderKey and BroadcastKey
- Epoch overflow checked_add on all paths
- AES-256-GCM nonces from OsRng
- Cover traffic constant-rate invariant
- Delegation chain cycle detection with depth limit (32)

## PR #76 Security Review (2026-02-26)

### Critical Findings
- claim_shadow() does NOT verify Ed25519 signatures - caller responsibility
- BudgetTracker in spending.rs not thread-safe for concurrent async
- StandingChannelManager TOCTOU race between lock drop and re-acquire
- SenderVelocityTracker unbounded HashMap growth (Sybil DID exhaustion)

### Well-Defended
- Invitation pipeline: sequential evaluation with fail-through
- Spending attenuation: each field checked independently
- MLS group_context extension: cryptographic binding of parent lineage
- Shadow default-deny: observer role + explicit capability blocklist
- Saturating arithmetic throughout economy module

## PR #255 Reachability Review (2026-03-03)

### Strong Controls
- Bridge auth: 4 independent layers. TOCTOU prevented via dual write lock
- DID anti-rollback: cached_sequence high-water mark survives cache TTL expiry
- Self-test: same socket reuse preserves NAT mapping, source addr + 96-bit txn_id anti-spoofing
- Tier re-eval: watch + Drop + abort fallback. Events emitted only after successful DID publish

### P1 Findings
- lib.rs L747: No jitter on 30-min tier re-eval interval
- lib.rs L802-831: apply_tier_change should validate exactly one SCPRelay

## Economy/Consequences Feature Review (2026-03-31)

### P0 Findings
- validate_governance_action_strings + reject_html_special_chars + all user-string validators DELETED from FFI common. No input-side length/content validation on role names, context names, descriptions, reasons, payment adapter refs. Output-escaping is NOT replacement.
- check_and_composition now allows (None, None, Amount::ZERO) -- any caller can bypass AND-composition for "free" actions without any UCAN proof.

### P1 Findings
- send_sequence wrapping_add(1) -- wraps to 0 after u64::MAX, all subsequent messages rejected as replays
- SenderKeyStore::set() remains pub, bypasses epoch monotonicity
- system_assign_role is pub (not pub(crate)), bypasses RoleAssign capability
- Escrow capture failure keeps budget deducted but no payment captured
- html_escape_json doesn't escape double-quote (inconsistent with html_escape_event_string)
- EpochNotMonotonic error leaks sender_did + epoch values
- request_nonce: [0u8;16] in rotated sender key distributions may trigger nonce dedup

### Well-Defended
- Epoch poisoning defense (MAX_EPOCH_ADVANCE=1000 + set_checked monotonicity)
- Blocked DID check on sender key requests
- Management message 64KiB size limits (both send+receive)
- Join economy ordering: sybil -> budget -> payment -> crypto
- Cost evaluation overflow fails closed (tested)
- Asymmetric timestamp freshness (300s past, 30s future)
- HTML escaping on all event output strings across all 4 FFI bridges

## Recurring Patterns
- TOCTOU races in check-then-act patterns (nonce replay, standing channels, budget)
- Missing zeroization on crypto key material
- WASM bridge diverges from scp-core (re-implements rather than delegates)
- unwrap_or_default on serialization hides failures
- Manual string parsing where URL parser should be used
- Projection UCAN validation is structural-only (parse not validate) -- recurring weakness
- Input validation removals justified by output escaping -- defense regression pattern
