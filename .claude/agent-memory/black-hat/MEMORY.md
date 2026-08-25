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
- After relay restart, session 1 via QUIC and session 1 via WebTransport collide
- Files: webtransport/server.rs:153, quic/listener.rs, relay/subscription.rs

### HIGH: WASM SendSyncWrapper unsound under SharedArrayBuffer (BLACK-202)
- File: webtransport/client.rs lines 80-95
- `unsafe impl Send/Sync` for JsValue types, safety relies on "WASM is single-threaded"
- No runtime guard against SharedArrayBuffer multi-threading
- If SAB enabled, instant UB -- no compile-time or runtime detection

### HIGH: WebSocket backfill_complete broadcast to ALL subscriptions (BLACK-203)
- File: webtransport/client.rs lines 1273-1288
- Event with ref_id: None broadcast to every subscription sender
- Malicious relay can truncate any subscription's backfill

### HIGH: Cover traffic budget degradation = traffic analysis oracle (BLACK-204)
- File: cover_traffic.rs lines 298-338
- Stepwise Full->Reduced->Off creates observable pattern on wire
- 60-second period reset creates synchronized burst pattern
- Budget exhaustion timing reveals real traffic volume

### MEDIUM: active_subscriptions Vec never pruned on unsubscribe (BLACK-205)
- File: webtransport/session.rs handle_unsubscribe_inner
- Unsubscribe removes from registry + my_subscriptions but NOT active_subscriptions
- Memory leak proportional to subscribe/unsubscribe frequency

### MEDIUM: QUIC adapter lifecycle manager never used after connect (BLACK-206)
- File: quic/adapter.rs -- lifecycle field stored but never read
- No reconnection, no health monitoring, network disruption = permanent death

### MEDIUM: HTTP/3 serve() has no rate limiting (BLACK-208)
- File: http3/adapter.rs lines 195-293
- No ConnectionTracker, no per-IP limits, unbounded task spawning
- Unlike QUIC/WebTransport listeners which have full rate limiting

### CORRECTNESS: WebSocket QUERY clobbers existing subscription (CA-3)
- File: webtransport/client.rs lines 1106-1154
- query() over WS does HashMap::insert(routing_id, tx), overwrites existing sub
- After query cleanup, original subscription is gone entirely

## Patterns Confirmed Working (Transport Expansion)
- 0-RTT correctly disabled in HTTP/3 config (http3/config.rs:364-370)
- Frame size validation at 512KB in both client and server paths
- Blob size/TTL validated server-side in WebTransport session handler
- PublishRateLimiter shared across transports (per-IP)
- Delivery jitter breaks timing correlation (BLACK-001 mitigation)
- Session cleanup correctly scoped by owner_id (within single transport)
- TLS enforced on all transports (QUIC/rustls, WASM/wss:// or https://)
- Connection tracking on QUIC and WebTransport listeners (per-IP + total)

## Refactoring Plan Adversarial Analysis (2026-03-21)
- See [refactor-plan-adversarial-analysis.md](refactor-plan-adversarial-analysis.md)
- BLACK-301 through BLACK-311: facade divergence, Phase B TOCTOU, asymmetric wiring, BridgeInstance split-brain
- Key mitigations: generation counter, atomic send+receive wiring, CI mod/re-export check, feature-flagged BridgeInstance

## PR #1606 -- Sender Key AAD, SCPM Magic, Timestamp Bounds (2026-03-31)

### HIGH: SCPM magic prefix injection by any group member (BLACK-1601)
### HIGH: No receive-side sequence tracking (BLACK-1602)
### MEDIUM: Access key freshness widened 30s->300s (BLACK-1603)
### MEDIUM: Buffer event timestamp estimation exploitable (BLACK-1604)
### Testing gap: E2eCryptoProvider hardcodes epoch=0, seq=0

## PR #1628 BridgeInstance Extraction (2026-04-14)
- See [pr1628-bridge-instance.md](pr1628-bridge-instance.md)
- BLACK-301: post-shutdown ghost ops (warn-only lifecycle), BLACK-303: placeholder DID confusion
- BLACK-308: rate limiter ephemeral bypass, BLACK-309: economy unbounded growth

## Complete Branch Review (2026-04-01) -- consequence/economy/FFI

### CRITICAL: Consequence WarningCount weaponized against innocents (BLACK-1706)
- Counts GovernanceAction events TARGETING a DID, not actions BY that DID
- Admin can manufacture governance proposals to trigger automated eviction
- system_assign_role bypasses RoleAssign capability check
- No recovery mechanism exists; enforcement is permanent

### HIGH: FFI string injection on NAPI+UniFFI (BLACK-1705)
- All input-side HTML validation removed from validate.rs
- Output escaping applied to consequence events only
- NAPI line 1215 + UniFFI line 8480: `format!("{other:?}")` unescaped
- PyO3 line 1457 correctly escapes; bridge parity gap

### HIGH: Standing score inflation via message flooding (BLACK-1701)
- evaluate_sybil_resistance remains a no-op stub
- Participation record is count-based, no quality gate
- Inflation computed BEFORE consequence evaluation

### HIGH: Relay pricing manipulation via velocity flooding (BLACK-1702)
- EIP-1559 base_fee driven by aggregate_velocity
- Attacker flood drives up cost for all members
- No per-member velocity contribution cap

### MEDIUM: Escrow capture failure harms operator (BLACK-1703)
- Budget enforcement prevents free rides for members
- Capture failure = operator revenue loss (deliberate H8 tradeoff)

### MEDIUM: check_and_composition latent bypass risk (BLACK-1704)
- action_ucan=None now means "already verified"
- Current callers correct; future callers may skip capability check
- No compile-time enforcement of precondition
- [Event-Log Substrate Swap Phase 2](eventlog_substrate_swap_phase2.md) — RFC6962 swap: export forgery CLOSED; equivocation detector false-positive under dormant cross-member replication; in-memory dedup wiped on respawn

## ADR-039 Persona Attribution Wiring (branch claude/scp-network-architecture-7zq21l, ba06a8e0+7d4cdcf0)

### BINDING IS SOUND (cryptographically)
- signing_key_id IS in signed inner-envelope preimage: compute_canonical_hash line 557 (crates/scp-protocol/src/envelope/inner/mod.rs). Domain-separated, length-prefixed.
- verify_inner_signature (330) reconstructs hash from inner.signing_key_id (370) = same value used for resolution at messaging_helpers.rs:309-310. Consistent.
- context_id in preimage (549) -> no cross-context replay of persona claim.
- MITM/relay/non-member cannot flip signing_key_id. Malicious sender cannot make agent msg appear #active UNLESS resolver returns same key for both VMs.
- Test document_backed_resolver (agent_binding_pipeline_tests.rs:106) maps (DID,Active)/(DID,Agent) to DISTINCT keys; proves wrong-key rejection (test 302). Genuinely tested.

### HIGH (wiring gap, not live-exploitable this diff): every PRODUCTION resolver collapses/returns None
- self_host.rs:452-453, all FFI bridges, bridge_runtime.rs not_configured_key_resolver, bridge_instance.rs ALL return |_,_| None.
- VM-aware guarantee wired through types but NO shipping resolver returns distinct keys. A lazy future resolver |did,_| lookup(did) reintroduces collapse silently -> agent msg verifies as #active. No mechanical check forbids ignoring the SigningKeyId arg.

### MEDIUM: all FFI send paths hardcode SigningKeyId::Active
- napi/context.rs, ffi/src/context.rs, uniffi/bridge.rs. No SDK lets an agent send under #agent. Persona-send is Rust-internal/test-only; accountability claim not expressible from any binding yet.

### LOW (honest deferral, fail-closed): governance votes resolve #active unconditionally
- mod.rs:1593, majority/multisig/unanimity. Attacker with only #agent key -> verify_vote fails -> vote REJECTED. No false-accept, no grief. Vote carries no signing_key_id (no downgrade vector).

### economy kid-parse robust
- economy_logic.rs:92 routes through from_fragment (identity.rs:200). Rejects "active"/"agent"/"#0"/""/"#unknown" -> MalformedToken. Exact byte match, no unicode/case coercion, no panic.

### NIT: validate.rs:702-710 enforce_ucan_category_a hand-rolls kid match instead of from_fragment (pre-existing). Drift risk only.
### CONTEXT: enforce_inner_envelope_category_a never called on live receive path (only sign.rs tests). Pre-existing, out of diff scope.

## TS SDK fail-closed/parity (branch fix/sdk-coverage-fail-closed-and-parity @6f4ba65ff)
### PRIMARY DEFENSE SOUND: test seam tree-shaken out of published bundle
- __setBridgeForTests/assertTestEnvironment/isTestEnvironment NOT re-exported from index.ts; tsup entry=[index.ts] splitting:false => esbuild tree-shakes all 3 (grep count 0 in bundle). Only _evaluateTestEnv survives internally, not in export clause.
- files:["dist/"] excludes src/; exports map only "." => deep subpath imports throw ERR_PACKAGE_PATH_NOT_EXPORTED. Runtime test-guard is defense-in-depth, not the boundary.
- UCAN regex /^\[SCP-PERM-\d+\]/ anchoring sound: leading \n/space defeats ^ => message rethrown (fail-closed). extractCore marker/em-dash injection inert (indexOf=FIRST marker; startsWith prefix fixed by Rust). Misclassify-as-UCAN always lands `unknown` => all 6 CapabilityValidation fields false.
### RESIDUAL low-sev: BUN_TEST=0 and BUN_TEST=false OPEN seam (length>0 only). Moot post-bundle (seam unreachable). Suggest falsey-value guard.
### FINDING gate soundness: check-sdk-coverage.py accepts a TYPE name as proof of runtime capability
- _extract_typescript_symbols folds interface/type_alias names into same set as runtime fns. _to_pascal(op) then matches a type. PROVEN: Governance/member_role matches `MemberRole` type not SCP.contextMemberRole; MCP/connect_client matches `McpClient` interface (alias also lists DELETED connectMcp; real impl mcpClientConnectStdio/Sse). Gate stays GREEN after deleting all runtime impls if same-named type survives. 2/184 TS ops affected. Softer re-intro of the suffix-match gap the PR claims closed. NOTE: file now in enforcement allowlist (CLAUDE.md) — report, don't self-edit.

## ADR-039 permission model (commit 832ed9b2f9)
- [Attack surfaces](pr-adr039-permission-model-spec.md) — #agent can mint a root UCAN granting itself the whole ceiling (SCP-AB-025 pending); step 6b runs before parent signature verification; rule 2 is inert by construction.
