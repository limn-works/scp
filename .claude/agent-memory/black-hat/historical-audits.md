# Historical Audit Findings

Older audit findings moved from MEMORY.md for space. Still valid unless superseded.

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
- Single attacker controls domain + context + attestation = highest trust
- No independence verification between corroborating layers

### CRITICAL: Context governance capture = total namespace hijack
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

## Key Attack Surfaces -- HTTP Features (PR #195)

### CRITICAL: Bridge secret in plaintext over localhost TCP
- File: `crates/scp-node/src/http.rs` line 144
- `ws://{relay_addr}/?token={token_hex}` -- co-tenant can sniff

### HIGH: .well-known/scp URI injection via unescaped context name
- File: `crates/scp-node/src/well_known.rs` lines 42-48
- Name interpolated into scp:// URI without percent-encoding

### HIGH: Conditional GET bypasses routing_id check (cross-context oracle)
- File: `crates/scp-node/src/projection.rs` lines 570-578
- If-None-Match check before routing_id validation = blob existence oracle

### HIGH: Unbounded context/projection registry (no max count, no rate limit)
- Dev API: `crates/scp-node/src/dev_api.rs` lines 405-421
- No DefaultBodyLimit, no max context count

### MEDIUM: Dev API loopback check only at builder, not at bind point
- File: `crates/scp-node/src/http.rs` lines 319-343
- serve() binds dev_addr without revalidating is_loopback()

### MEDIUM: Routing ID enumeration via timing + 404/200 oracle
- File: `crates/scp-node/src/projection.rs` feed_handler
- SHA-256(context_id) is deterministic and publicly computable

### MEDIUM: Broadcast keys cloned without zeroization
- File: `crates/scp-node/src/projection.rs` lines 414, 594

## Patterns Confirmed Working (HTTP Features)
- Bearer token uses subtle::ConstantTimeEq (correct)
- Bridge secret uses ct_eq at relay level (correct)
- Token entropy: 128 bits from OsRng (sufficient)
- Token masked in logs (only prefix shown)
- Context ID hex-only validation prevents injection
- Blob routing_id cross-check in message_handler
- Feed limit clamped to 100
- #![forbid(unsafe_code)] on scp-node

## Key Attack Surfaces -- Transport Expansion (commit 8873a54)

### HIGH: owner_id collision across transports (BLACK-201)
- Three independent AtomicU64 counters (QUIC, WebTransport, WebSocket) all start at 1
- SubscriptionRegistry uses owner_id as sole identity for cleanup/removal
- Files: webtransport/server.rs:153, quic/listener.rs, relay/subscription.rs

### HIGH: WASM SendSyncWrapper unsound under SharedArrayBuffer (BLACK-202)
- webtransport/client.rs 80-95: `unsafe impl Send/Sync` for JsValue, no runtime SAB guard

### HIGH: WebSocket backfill_complete broadcast to ALL subscriptions (BLACK-203)
- webtransport/client.rs 1273-1288: `ref_id: None` broadcast lets a relay truncate any backfill

### HIGH: Cover traffic budget degradation = traffic analysis oracle (BLACK-204)
- cover_traffic.rs 298-338: stepwise Full->Reduced->Off + 60s reset reveals real traffic volume

### MEDIUM: active_subscriptions Vec never pruned on unsubscribe (BLACK-205)
### MEDIUM: QUIC adapter lifecycle manager never used after connect (BLACK-206)
### MEDIUM: HTTP/3 serve() has no rate limiting (BLACK-208)
### CORRECTNESS: WebSocket QUERY clobbers existing subscription (CA-3)
- webtransport/client.rs 1106-1154: query() HashMap::insert overwrites, cleanup drops the original

### Patterns Confirmed Working (Transport Expansion)
- 0-RTT disabled in HTTP/3 config; 512KB frame validation both paths; blob size/TTL server-side
- PublishRateLimiter shared per-IP; delivery jitter breaks timing correlation
- Session cleanup scoped by owner_id within a transport; TLS enforced on all transports

## PR #1606 -- Sender Key AAD, SCPM Magic, Timestamp Bounds (2026-03-31)
- HIGH BLACK-1601 SCPM magic prefix injection by any group member
- HIGH BLACK-1602 no receive-side sequence tracking
- MEDIUM BLACK-1603 access key freshness widened 30s->300s
- MEDIUM BLACK-1604 buffer event timestamp estimation exploitable
- Testing gap: E2eCryptoProvider hardcodes epoch=0, seq=0

## Complete Branch Review (2026-04-01) -- consequence/economy/FFI
- CRITICAL BLACK-1706: WarningCount counts events TARGETING a DID, so an admin manufactures
  proposals to trigger automated eviction; system_assign_role bypasses the RoleAssign check;
  no recovery mechanism, enforcement permanent
- HIGH BLACK-1705: NAPI:1215 + UniFFI:8480 `format!("{other:?}")` unescaped; PyO3:1457 escapes
- HIGH BLACK-1701: evaluate_sybil_resistance is a no-op stub; count-based participation inflates
- HIGH BLACK-1702: EIP-1559 base_fee driven by aggregate_velocity, no per-member cap
- MEDIUM BLACK-1703 escrow capture failure harms operator; MEDIUM BLACK-1704 check_and_composition
  `action_ucan=None` means "already verified" with no compile-time precondition

## ADR-039 Persona Attribution Wiring (branch claude/scp-network-architecture-7zq21l)
- BINDING IS SOUND: signing_key_id is in the signed inner-envelope preimage
  (compute_canonical_hash:557, crates/scp-protocol/src/envelope/inner/mod.rs), domain-separated and
  length-prefixed; verify_inner_signature:330 reconstructs from inner.signing_key_id:370; context_id
  in the preimage:549 blocks cross-context replay
- HIGH wiring gap: every production resolver returns `|_,_| None` (self_host.rs:452, all FFI bridges,
  bridge_runtime.rs, bridge_instance.rs). A future `|did,_| lookup(did)` silently collapses the two
  VMs and an agent message verifies as #active. No mechanical check forbids ignoring the arg.
- MEDIUM: all FFI send paths hardcode SigningKeyId::Active, so no SDK expresses an #agent send
- LOW: governance votes resolve #active unconditionally (mod.rs:1593) and fail closed
- NIT: validate.rs:702-710 hand-rolls the kid match instead of from_fragment

## TS SDK fail-closed/parity (branch fix/sdk-coverage-fail-closed-and-parity @6f4ba65ff)
- PRIMARY DEFENSE SOUND: __setBridgeForTests/assertTestEnvironment/isTestEnvironment are not
  re-exported from index.ts; tsup entry=[index.ts] splitting:false tree-shakes all three.
  files:["dist/"] plus an exports map with only "." makes deep subpath imports throw.
- UCAN regex /^\[SCP-PERM-\d+\]/ anchoring is sound; a leading newline defeats ^ and the message
  rethrows; a misclassify-as-UCAN always yields `unknown` and all six fields false
- RESIDUAL low: BUN_TEST=0 and BUN_TEST=false leave the seam open (length>0 only); moot post-bundle
- FINDING: check-sdk-coverage.py accepts a TYPE name as proof of a runtime capability.
  _extract_typescript_symbols folds interface/type_alias names into the same set as runtime fns, so
  Governance/member_role matches the `MemberRole` type and MCP/connect_client matches the `McpClient`
  interface. The gate stays green after deleting the runtime impls. 2/184 TS ops affected.
  The file is in the CLAUDE.md enforcement allowlist — report it, never self-edit.
