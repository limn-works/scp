# White Hat Agent Memory

## Topic files
- [PR #2415 custody derived-not-declared](custody-derived-not-declared-2415.md) — serde/`pub service` bypass the "no field to write it in" claim; fail-closed is per-arm convention in 3 factories; no verifier, no detection.

## TS SDK fail-closed test-seam Review (2026-06-20, branch fix/sdk-coverage-fail-closed-and-parity)

### Defense architecture (TS bridge-swap hardening)
- Two dangerous seams: `__setBridgeForTests` (bridge.ts:832) and `__constructScpWithNativeForTests` (scp.ts:2837). BOTH gated by `assertTestEnvironment` BEFORE the mutating op (`_nativeBridgeForScp.set` / `new SCP({NATIVE_OVERRIDE})`). Correct fail-closed ordering.
- `_IS_TEST_ENVIRONMENT` frozen at IMPORT time (IIFE), so runtime `process.env` mutation post-import cannot flip it — defeats late-stage env-poisoning. Strong.
- `Object.hasOwn` on NODE_ENV/BUN_TEST defeats `Object.prototype.NODE_ENV="test"` pollution. Tested (test-guard.test.ts:57).
- BUN_TEST requires `!== undefined && .length > 0` — empty-string no longer elevates trust. Tested.
- UCAN error regexes prefix-anchored `/^\[SCP-PERM-\d+\]/` (trust.ts:457,461,507) — embedded-substring forgery in a benign message body can't spoof classification.
- `_nativeBridgeForScp` WeakMap has only 3 writers: getBridge (legit lazy init), getBridgeSync (read), __setBridgeForTests (guarded). NATIVE_OVERRIDE is module-private `unique symbol`, only reachable via guarded factory. No unguarded injection path.
- package.json exports map is `"."` only — no subpath, so `import "@limn-works/scp-ts/internal/test-guard"` deep-import is blocked by Node/bundler resolution.

### PERM-3030 re-raise (HEAD 57840faab, verified round 4)
- PERM-3030 = HandleAffinityError (handle issued by a DIFFERENT SCP instance; caller misuse). Mapped to ScpPyError::UcanError w/ code PERM_3030 in error.rs:737-744. Re-raised (trust.py:770, trust.ts:461) BEFORE __classifyUcanError so a programming bug isn't absorbed into a false all-false trust verdict. Correct posture: a cross-instance handle error is not a UCAN-validity signal about the subject.
- FORWARD-COMPAT (fail-closed): re-raise is prefix-gated on "[SCP-PERM-3030]". If that code string ever changes, the re-raise stops firing and the message falls into __classifyUcanError → no prefix bucket matches a handle-affinity string → returns "unknown" → _PASSED_BEFORE["unknown"]=empty set → ALL SIX CapabilityValidation fields=false. So a format drift degrades to a conservative all-false (denies), never a spurious pass. The dict .get(cat, set()) default is also empty=fail-closed.
- evaluateTrust no-token path: CapabilityValidation defaults ALL false (no fabricated pass). Optimistic-flip (all true) only entered when capabilityTokens non-empty AND each ucan_validate returns w/o exception (= all 11 ADR-016 steps passed). No trust-escalation introduced.

### Coverage gate (HEAD 57840faab)
- Gate is DEFENSE-IN-DEPTH, not primary guarantee (matrix/wrapper presence is). Fail-closed: true-without-symbol = ERROR unless coverage_exemptions reason recorded.
- ALIASES = positive closed whitelist (domain,op)->{sdk:[exact symbols]}. Suffix/substring matching REMOVED (was ~23 fabricated-name bypass) — only exact match on aliases + domain-prefixed variants. Sound. test_bare_name_does_not_satisfy_domain_prefixed_op asserts the bypass is closed.
- coverage_exemptions escape hatch BOUNDED by all-exempted guard (L1615-1627): error if every true-SDK is exempted AND none statically verified → at least one SDK must be ground-truth verified. Cannot become unbounded prose bypass.
- Gate green (223 ops, 0 errors, 1 coverage-exempt: Kotlin add_relay_url, generated UniFFI not git-tracked — legit). Self-test suite 11/11 pass.

### Residual (acknowledged, low severity)
- NODE_ENV="development" intentionally permits the bridge-swap seam (dev builds need it). Defense relies on deploy hygiene, not code.
- assertTestEnvironment is the SOLE layer gating the seam (single gate). Frozen-constant + import-time eval makes it strong. Acceptable — exported test helpers are inherently single-gate.
- VERDICT (round 4, 57840faab): APPROVED. Defenses robust, defense-in-depth, fail-closed by construction. No new actionable findings.
- VERDICT (round 5, HEAD 341df72cc): APPROVED. 4 commits since 57840faab are docstring/cosmetic only — ZERO behavioral change to the 4 security surfaces. Re-verified live: gate green (223 ops, 0 errors, 1 legit kotlin add_relay_url coverage-exempt), self-test 11/11. NATIVE_OVERRIDE module-private unique symbol (scp.ts:486), only via guarded __constructScpWithNativeForTests (assertTestEnvironment BEFORE new SCP, L2904). _nativeBridgeForScp.set 2 writers: lazy-init createNativeBridge (no caller value, L804) + guarded __setBridgeForTests (L837 gate before L838). exports map "."-only, internal/ deep-import blocked. PERM-3030 re-raise prefix-anchored BEFORE classify (trust.py:770, trust.ts:461); evaluateTrust no-token path defaults ALL-FALSE, optimistic-flip only on non-empty tokens. No trust-escalation path.

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
- ContextManager standing context (contact graph, manager/standing.rs) TOCTOU race between lock drop and re-acquire
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

## Branch claude/complete-pr-work-review-0TQtO Review (2026-04-04)

### P1 Findings
- VALID_SUSPENSION_CAPABILITIES covers only MessagesRead/Write (6 aliases). 19 other Capability variants (ToolInvoke, GovernancePropose, MemberRemove, etc.) cannot be suspended via consequence rules -- Suspend silently logs unknown and skips.
- Standing context ID changed from 8-byte truncated hash to full 32-byte hash (good), but old standing contexts using truncated IDs will not be found on reconnect (no migration path).
- SuspendAll is app-layer only (role_state.suspend_all). No automatic MLS removal or sender key rotation. Comment says "dispatch RemoveMember governance action" but no code actually dispatches it. Gap between Suspend (app) and RemoveMember (crypto) layers.
- enforce_assign_role returns bool but does not escalate on false except in the outer loop. If role doesn't exist, enforce_assign_role returns false -> SuspendAll escalation is correct, but the role existence isn't validated at rule creation time.

### P2 Findings
- event_log_entries_for_consequences estimated timestamps (1-second spacing) are approximations. High-throughput senders could have multiple events within same second, collapsing their timestamps and potentially under-counting velocity.
- cooldown_until HashMap unbounded -- one entry per rule_index forever. No eviction of stale cooldowns.

### Well-Defended
- Consequence TOCTOU guard: membership check inside enforce loop, break on member departure
- Fail-closed on participation record computation failure (denies proposal)
- Budget rollback uses reverse_spend (decrements spent) not grant (inflates limit)
- Cost evaluation overflow returns Err, not Ok(None) -- fail-closed
- threshold=0 rejected at validation time
- Escrow pattern: authorize -> action -> capture/void with proper rollback
- H7: capability check BEFORE budget deduction prevents budget leak on permission failure
- M4: velocity recorded BEFORE economy enforcement for accurate pricing
- Nonce replay prevention on spending UCANs

## Session Changes Review (2026-04-14, PRs #1629-#1642, #1649)

### Round 2 NaN/bool findings CLOSED by #1649 (verified round 3)
- TS: Number.isFinite guards at all 4 sites (constructor L621, revoked() L518, _fromBridgeValue L552, _fromRecord L717)
- Python: _parse_finite_int with explicit bool reject; __post_init__ guards on both RevocationStatus and IdentityAttestation; _from_dict also calls _parse_finite_int
- Swift/Kotlin: NaN-immune via UniFFI UInt64/ULong typing

### Carried P1/P2 (pre-existing, not regressions from #1649)
- **P1 py_handle_register + napi handle_register**: No validation on handle/description/tags (discovery.rs:654-694, napi/discovery.rs:464-498). Validators exist but aren't called. Same "input-side absent, output escape only" defense regression pattern as 2026-03-31.
- **P2 MAX_HANDLE_ENTRIES=10K global, no per-DID cap** (handles.rs:39).
- **P2 Empty-reason whitespace-control bypass** (validate.rs:610): `if !r.trim().is_empty()` — `\t\n\r` are both whitespace and control chars so trim removes them, empty check passes, validation skipped. Non-whitespace controls (\0) still caught.

### P2 Findings
- **Handle registry namespace-DoS**: MAX_HANDLE_ENTRIES=10K is global. No per-DID sub-cap. One authenticated member can claim all entries.
- **MAX_HANDLE_ENTRIES hardcoded const**: not configurable per context.
- **No rate limit** on handle registrations per DID per time window.

### Well-Defended
- HandleRegistry::register: contains->cap->insert under &mut self is race-free by type system
- OwnershipMismatch check BEFORE conflict check (no existence leak to unauthorized callers)
- validate_data_dir: empty/>4096/null-bytes/.. all covered; 0o700 mode on Unix
- Error codes ATTEST 9001/9006/9010-9018 non-overlapping (grep confirmed)
- chars().enumerate() uses code-point position (correct for UTF-8)
- Empty-reason skip `if !r.is_empty()` NOT a bypass: required reasons still rejected via validate_non_empty
- MissingPassphrase: fail-closed, no env fallback, user_message=Display (nothing sensitive to strip)

## PR #1628 BridgeInstance Consolidation Review (2026-04-14)

### P1 Findings
- economy_budgets, economy_antispam, bridge_state DashMaps have NO capacity bounds (known_contexts/rate_limiters do). OOM from authenticated attacker.
- Economy accessors (with_economy_budget[_mut], with_economy_antispam) re-create entries after shutdown via entry().or_default() -- fail-open zombie state.
- bridge_state() returns raw &DashMap -- no lifecycle guard, no capacity enforcement.
- ensure_bridge_instance uses placeholder DID ("did:unknown:*") -- immutable, indistinguishable from real DID by callers of local_did().

### P2 Findings
- did_resolver (OnceLock) never cleared during shutdown -- resources retained until process exit.
- set_did_resolver silently ignores duplicate calls (no warning, unlike init_context_manager).
- known_contexts(), rate_limiters(), bridge_state() are pub (should be pub(crate)) -- bypass capacity enforcement.

### Well-Defended
- Shutdown ordering: AtomicBool::swap(true, SeqCst) FIRST, then cleanup. Idempotent.
- Suspend ordering: flag BEFORE transport teardown; reverted on failure.
- Shutdown hooks: catch_unwind on each, immediate execution if registered post-shutdown.
- Error messages sanitized (no architecture leakage in Display impls).
- All 3 bridges register shutdown hooks correctly; all scp_shutdown uses catch_unwind.
- Transport Arc pattern for async safety (RwLock<Option<Arc>>>, strong_count check for mut).
- remove_ffi_state cleans up known_context + bridge_state + economy_state per context.

## Recurring Patterns
- TOCTOU races in check-then-act patterns (nonce replay, standing channels, budget)
- Missing zeroization on crypto key material
- WASM bridge diverges from scp-core (re-implements rather than delegates)
- unwrap_or_default on serialization hides failures
- Manual string parsing where URL parser should be used
- Projection UCAN validation is structural-only (parse not validate) -- recurring weakness
- Input validation removals justified by output escaping -- defense regression pattern
