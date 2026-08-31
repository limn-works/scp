---
name: surfaces-2026q2-branches
description: Findings from PR #1606 sender-key AAD, the 2026-04-01 consequence and economy and FFI branch review, ADR-039 persona attribution wiring, and the TS SDK fail-closed parity branch
metadata:
  type: project
---

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

