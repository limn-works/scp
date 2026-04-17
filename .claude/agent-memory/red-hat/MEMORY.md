# Red Hat Agent Memory

## PR #127 Reassessment (2026-03-01, post-fixes)
After commit 54b8096 ("close 6 remaining gaps"), reassessed all chains.

### Fixed (closed)
- RED-101 partially fixed: WASM now has Ed25519 sig verification (verify_token_signature). Still missing 5/11 checks (delegation chain, root issuer, audience, attenuation, nonce, ceiling).
- RED-018/custody_type: UniFFI fallback changed from Hardware to InMemory.
- Inner envelope: u32 length prefixes added for field-boundary collision prevention.

### Still Open
- **RED-101 (HIGH, downgraded from CRITICAL)**: WASM validation still missing 5/11 ADR-016 checks: delegation chain, root issuer, audience, attenuation enforcement, nonce replay, ceiling. Self-signed tokens now rejected (sig verified), but tokens can be used cross-context via missing audience check.
- **RED-102 (HIGH)**: NAPI/UniFFI still mint `[0u8; 64]` placeholder signatures (napi/ucan.rs:432). Tokens structurally valid but fail Ed25519 verification in any bridge with sig checking.
- **RED-103 (CRITICAL)**: Broadcast gated subscription still uses stub `roles::UcanToken` with NO signature/expiry. validate_messages_read_ucan still only checks aud+att string match.
- **RED-105 (HIGH)**: WASM wildcard bypass still present (wasm/ucan.rs:234). `starts_with(&context_prefix)` without trailing `/` delimiter. Token for `scp:ctx:a` matches `scp:ctx:abc`.
- **RED-106 (MEDIUM)**: SSE notification->request conversion still uses hardcoded `id: 0`.
- **RED-107 (HIGH)**: SSE endpoints still have no authentication.
- **RED-108 (MEDIUM)**: block_subscriber still doesn't remove from subscribers HashMap. can_read() still returns true for blocked subscribers.
- **RED-109 (MEDIUM)**: Handle context target squatting still possible -- any DID registers handles pointing to any context.
- **RED-110 (MEDIUM)**: Cover traffic fixed 1024-byte payloads still distinguishable from real messages.
- **RED-111 (HIGH, upgraded)**: NAPI proof resolver uses `compute_revocation_cid` to key proofs (bare hex CID), but scp-core validation pipeline expects `compute_cid` format (bafyrei-prefixed JWT hash CID) in `prf` field. Delegation chains through NAPI are silently broken. PyO3 and UniFFI use correct `compute_cid`.

## PR #255 Reachability Assessment (2026-03-03)
- **RED-204 (HIGH)**: BRIDGE_REGISTER replay within 60s window. No nonce/connection binding. Fix: add nonce to signed payload.
- **RED-206 (MEDIUM)**: No debounce on tier re-evaluation. NetworkChangeDetector flooding causes STUN/DID publish storm.
- **RED-208 (MEDIUM)**: apply_tier_change publishes DID without verifying new URL reachability.
- **RED-201/202 (MEDIUM)**: STUN spoofing (on-path). Known limitation. 96-bit txn ID protects remote.
- Controls that hold: Ed25519 verify_strict bridge auth, TOCTOU-safe BridgeRegistry, anti-rollback cached_seq, healing fresher-wins.

## Governance-Gaps PR Assessment (2026-03-05)
- **RED-301 (CRITICAL->FIXED)**: validate_projection_ucan now does full 7-step validation (parse, temporal, capability, audience, sig, revocation, cache). Fixed.
- **RED-302 (HIGH->FIXED)**: Feed endpoint per-author override filtering added (messages.retain loop). Fixed.
- **RED-303 (HIGH)**: Post-ban projection access. ProjectedContext has its OWN key copy. propagate_ban_keys exists but requires external caller to invoke it.
- **RED-304 (MEDIUM)**: Metadata oracle distinguishable (metadata_visibility policy exposed).
- **RED-305 (LOW)**: CDN cache poisoning prevented (Cache-Control: private). Holds.

## Projection UCAN Reassessment (2026-03-16, round 2 post-fixes)
- **RED-401 (HIGH->FIXED)**: Structural fallback bypass closed. Three-way match: non-empty keys->full validation, empty keys->hard 401, None->structural (dead code, unreachable). Tests confirm gated+empty keys rejects and open+per-author-gated+empty keys filters.
- **RED-402 (MEDIUM->FIXED)**: Wildcard capability rejected. Both full and structural paths now require `cap.context_id().is_some()`. Wildcard CapabilityUri has context_id=None, so is_some() returns false. Tests confirm.
- **RED-403 (MEDIUM)**: No delegation chain verification in projection. validate_projection_ucan checks 7 of 11 steps. Missing: delegation chain (step 3), root issuer (step 4), attenuation (step 7), ceiling (step 8), nonce (step 9). A member can issue tokens beyond their granted scope.
- **RED-404 (LOW->CONFIRMED SAFE)**: Global cache not context-scoped. Cache key is SHA-256(JWT). Pre-cache checks (capability + audience) run BEFORE cache lookup. Audience includes routing_id (unique per context). Cross-context cache reuse impossible.
- **Latent risk**: Dead `None` arm in check_projection_auth (line 883) provides structural-only validation without audience/sig/revocation. Unreachable today (all callers pass Some). Recommend replacing with hard 401 or unreachable!().

## PR #1606 Assessment (2026-03-31) - Epoch/Sequence AAD + SCPM Management + Buffer Bounds
- **RED-501 (LOW)**: SCPM magic prefix collision with epoch header bytes requires epoch ~6 quintillion. Unreachable. MLS credential binding prevents cross-identity sender key injection via management messages.
- **RED-502 (MEDIUM)**: E2eCryptoProvider hardcodes epoch=0, sequence=0 (fullstack/crypto.rs:863). H2 AAD binding untested in E2E. Fix: wire real counters.
- **RED-503 (LOW)**: `#[serde(default)]` on send_sequence means old snapshots restore to 0. Safe because GCM nonce is random (OsRng), not counter-derived. Latent risk if nonce strategy changes.
- **RED-504 (MEDIUM)**: Buffer capacity > 3601 causes timestamp estimation to exceed 3600s bounds, silently dropping valid events. Governance evasion in large-buffer contexts. Fix: clamp estimation range.
- **RED-505 (LOW)**: 300s freshness window for access key requests. Replay harmless due to HPKE wrapping to requester's pubkey.
- Controls that hold: MLS credential binding, SCPM collision resistance, epoch monotonicity on sender key store, random GCM nonces, HPKE key wrapping.
- **RED-601 (LOW)**: Epoch ratcheting 999/step possible but infeasible to reach u64::MAX (~585M years). Check uses STORED epoch. Defense holds.
- **RED-602 (LOW)**: Post-snapshot empty recv_sequence_tracker. MLS primary replay protection survives restore. Belt-and-suspenders only.
- **RED-603 (LOW)**: Asymmetric freshness (300s past/30s future) is sound. Pre-existing gap: NonceDedup not wired for access keys.
- **RED-606 (MEDIUM)**: E2eCryptoProvider missing epoch poisoning, recv_tracker, mgmt size limit. New defenses untested in integration.

## PR Branch `complete-pr-work-review-0TQtO` Assessment (2026-04-01, round 1)
- **RED-701 (HIGH)**: NAPI/UniFFI catch-all event formatters lack HTML escaping.
- **RED-702 (MEDIUM)**: Spending UCAN replay. No nonce dedup.
- **RED-705 (MEDIUM)**: system_assign_role bypasses RoleAssign for consequence engine.
- **RED-706 (HIGH)**: evaluate_sybil_resistance() stub. Standing score gaming via Sybil.

## PR Branch `complete-pr-work-review-0TQtO` Assessment (2026-04-04, round 2 - governance/economy focus)
- **RED-801 (CRITICAL)**: WASM `member_has_capability` ignores `suspended_capabilities` map. Suspension is cosmetic. `send_message` has inline check but governance propose/vote uses `member_has_capability` which never queries suspension state.
- **RED-802 (HIGH)**: WASM `dispatch_revoke` never inserts into `read_exclusion_list`. CEK wrapping exclusion is dead code for Revoke actions.
- **RED-803 (HIGH)**: `check_and_composition` silently discards `action_ucan` (`let _ = action_ucan`). Callers passing None for action_ucan succeed for free actions. AND-composition broken: spending UCAN alone is sufficient.
- **RED-804 (MEDIUM)**: WASM nonce tracker uses HashMap with f64 timestamps (JS precision). 10K cap with TTL eviction. Reset on context import loses all nonces -- full replay window opens.
- **RED-805 (MEDIUM)**: `rollback_last` on velocity tracker always pops the LAST timestamp regardless of which message failed. Concurrent senders can roll back the wrong sender's velocity.

## PRs #1629-#1642 Assessment (2026-04-14, error taxonomy + NaN guards)
- **RED-901 (MEDIUM)**: ATTEST codes 9015-9017 are Swift-unique, 9018 is WASM-unique. Single ScpError with embedded code fingerprints SDK. Any caller receiving ScpError learns bridge family.
- **RED-902 (LOW)**: Python IdentityAttestation.__post_init__ (identity.py:746-749) does raw int() without _parse_finite_int. _from_dict path is hardened, dataclass-construction path is not.
- **RED-903 (LOW)**: HandleRegisterStatus serde rename from "lowercase" to "snake_case" in PR #1632 is a breaking wire-format change with no alias. Older persisted forms ("ownershipmismatch") fail to deserialize.
- **RED-904 (LOW)**: HandleRegistry.next_entry_id is monotonic and never resets. Observers derive registration churn rate. Capacity check ordering is correct (no counter bump on fail).
- **RED-905 (LOW)**: MissingPassphrase → VALID-7004 (UniFFI only). Combined with pre-existing CustodyError("decryption failed (wrong passphrase?)") vs Io differential, gives 3-way oracle for identity file state.
- **RED-906 (LOW)**: NaN guard in TS uses Number.isFinite but not Number.isSafeInteger. Unsafe-integer verified_at (>=2^53) silently truncates on re-serialize, causing cross-peer signature consistency failure.

## Key Attack Patterns for This Codebase
- **Bridge parity gap**: WASM bridge cannot depend on scp-core (tokio incompatibility), so it re-implements validation partially. ALWAYS check WASM bridge when core validation changes.
- **Two UcanToken types**: `roles::UcanToken` (stub, no sig/expiry) vs `crypto::ucan::UcanToken` (full, has sig/encoded). Broadcast uses the stub. Any code accepting the stub has no sig verification.
- **CID computation divergence**: `compute_cid` (JWT hash + bafyrei prefix) vs `compute_revocation_cid` (payload JSON hash, hex). PyO3/UniFFI use `compute_cid` for proofs (correct); NAPI uses `compute_revocation_cid` (wrong). Cross-bridge delegation chains break.
- **Zero-signature tokens**: NAPI and UniFFI bridges mint `[0u8; 64]` placeholder sigs. These pass structural parsing but fail Ed25519 verification.
- **SSE broadcast model**: All SSE clients receive all responses. No per-session isolation.
- **Wildcard prefix matching**: `starts_with` on context_id without delimiter allows cross-context access for IDs sharing a prefix.
- **"Caller is responsible" pattern**: Still present from PR #76. claim_shadow, upgrade_shadow_role defer sig verification.
- **Output escaping parity gap**: Input-side HTML rejection removed (validate.rs). Output-side escaping added but only PyO3 catch-all is consistent. NAPI/UniFFI catch-all arms unescaped. Any new event variant auto-falls through unescaped.
- **Stub sybil resistance**: evaluate_sybil_resistance() passes unconditionally. Any standing-based feature is Sybil-vulnerable until implemented.
- **system_assign_role bypass**: Consequence engine can demote/ban without governance vote. No appeal, no cooldown, no rate limit.
- **Replay without nonce**: BRIDGE_REGISTER uses timestamp-only replay protection (60s window). No nonce, no connection binding. Captured frames are replayable within window.
- **Unbounded event-driven loops**: tier re-evaluation loop has no debounce. Any channel sender can trigger unlimited STUN probes + DID publishes.
- **Structural fallback bypass (FIXED)**: check_projection_auth now hard-rejects empty member_keys with 401. Dead `None` arm remains but is unreachable. Latent risk only.

## Critical Files
- `crates/scp-ffi/wasm/src/ucan.rs` -- Missing 5 validation steps (RED-101), wildcard bypass (RED-105)
- `crates/scp-core/src/context/broadcast.rs` -- Governance ban + block_subscriber
- `crates/scp-core/src/context/roles.rs` -- Stub UcanToken struct (no signature field)
- `crates/scp-ffi/napi/src/ucan.rs` -- Zero-sig mint (RED-102), wrong proof CID function (RED-111)
- `crates/scp-mcp/src/sse.rs` -- No auth (RED-107), notification confusion (RED-106)
- `crates/scp-core/src/discovery/handles.rs` -- Context target squatting (RED-109)
- `crates/scp-transport/src/relay/bridge.rs` -- Replay within 60s window (RED-204)
- `crates/scp-node/src/lib.rs` -- No debounce on re-eval loop (RED-206), no post-change self-test (RED-208)
- `crates/scp-node/src/projection.rs` -- RED-401 FIXED, RED-402 FIXED, missing delegation/attenuation/ceiling/nonce (RED-403), dead structural None arm (latent)

## PR #1628 BridgeInstance Type-Erasure Assessment (2026-04-14)
- **RED-901 (HIGH)**: Post-shutdown bridge_instance() returns Ok with warn, not Err. All 3 bridges. Zombie operations possible.
- **RED-902 (MEDIUM)**: storage_provider/protocol_repository OnceLock fields NEVER cleared on shutdown. AES-256 key persists.
- **RED-903 (NON-ISSUE)**: Type confusion via downcast impossible. Rust TypeId prevents. Returns None on mismatch.
- **RED-904 (NON-ISSUE)**: clear_fn cannot be replaced (OnceLock write-once). Cannot be suppressed (called unconditionally in shutdown).
- **RED-905 (LOW)**: Mutex poisoning in shutdown_hooks skips all bridge-specific hooks. Narrow prerequisite.
- **RED-906 (MEDIUM)**: UniFFI identity custody NOT in BridgeInstance (separate OnceLock). Weaker cleanup vs PyO3/NAPI.
- **RED-907 (MEDIUM)**: Post-shutdown re-registration possible. register_identity() has no is_shutdown() check.
- Fix priority: (1) bridge_instance() should reject post-shutdown with Err, (2) clear storage_provider/protocol_repository, (3) UniFFI identity into BridgeInstance.
