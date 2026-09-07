---
name: surfaces-crypto-economy-persona
description: Attack surfaces across sender-key AAD (PR #1606), consequence/economy/FFI branch review, ADR-039 persona attribution wiring, and TypeScript SDK fail-closed parity — including the sdk-coverage gate accepting a type name as runtime proof
metadata:
  type: project
---

# PR #1606 — sender key AAD, SCPM magic, timestamp bounds (2026-03-31)

- **HIGH — SCPM magic-prefix injection by any group member (BLACK-1601).**
- **HIGH — no receive-side sequence tracking (BLACK-1602).**
- **MEDIUM — access-key freshness widened from 30s to 300s (BLACK-1603).**
- **MEDIUM — buffer event timestamp estimation is exploitable (BLACK-1604).**
- Testing gap: `E2eCryptoProvider` hardcodes `epoch = 0`, `seq = 0`.

# Branch review 2026-04-01 — consequence, economy, FFI

- **CRITICAL — consequence `WarningCount` is weaponizable against innocents (BLACK-1706).** Counting counts `GovernanceAction` events *targeting* a DID rather than actions *by* that DID, so an admin manufactures proposals to trigger automated eviction. `system_assign_role` skips a `RoleAssign` capability check. No recovery mechanism exists, and enforcement is permanent.
- **HIGH — FFI string injection on napi-rs and UniFFI (BLACK-1705).** Input-side HTML validation was removed from `validate.rs`, and output escaping covers consequence events only. napi-rs line 1215 and UniFFI line 8480 emit `format!("{other:?}")` unescaped; PyO3 line 1457 escapes correctly, so bridges diverge.
- **HIGH — standing score inflation through message flooding (BLACK-1701).** `evaluate_sybil_resistance` remains a no-op stub, a participation record is count-based with no quality gate, and inflation is computed before consequence evaluation.
- **HIGH — relay pricing manipulation through velocity flooding (BLACK-1702).** An EIP-1559 `base_fee` driven by `aggregate_velocity` lets an attacker's flood raise cost for every member, with no per-member velocity contribution cap.
- **MEDIUM — escrow capture failure harms an operator (BLACK-1703).** Budget enforcement stops free rides for members; a capture failure costs an operator revenue, a deliberate H8 tradeoff.
- **MEDIUM — `check_and_composition` carries latent bypass risk (BLACK-1704).** `action_ucan = None` now means "already verified". Current callers are correct; a future caller may skip a capability check, and no compile-time mechanism enforces that precondition.

# ADR-039 persona attribution wiring (branch claude/scp-network-architecture-7zq21l, ba06a8e0 + 7d4cdcf0)

**Binding is cryptographically sound.** `signing_key_id` sits inside a signed
inner-envelope preimage (`compute_canonical_hash`, `crates/scp-protocol/src/envelope/inner/mod.rs:557`),
domain-separated and length-prefixed. `verify_inner_signature` (line 330)
reconstructs that hash from `inner.signing_key_id` (line 370), matching what
`messaging_helpers.rs:309-310` uses for resolution. `context_id` in a preimage
(line 549) blocks cross-context replay of a persona claim. A relay, a MITM, and
a non-member each cannot flip `signing_key_id`; a malicious sender cannot make
an agent message read as `#active` unless a resolver returns one key for both
verification methods. Test `document_backed_resolver`
(`agent_binding_pipeline_tests.rs:106`) maps `(DID, Active)` and `(DID, Agent)`
to distinct keys and proves wrong-key rejection (test 302).

- **HIGH (wiring gap, not live-exploitable in that diff) — every production resolver collapses or returns `None`.** `self_host.rs:452-453`, every FFI bridge, `bridge_runtime.rs` `not_configured_key_resolver`, and `bridge_instance.rs` all return `|_, _| None`. A verification-method-aware guarantee is wired through types while no shipping resolver returns distinct keys, so a later lazy resolver written as `|did, _| lookup(did)` reintroduces collapse silently and an agent message verifies as `#active`. No mechanical check forbids ignoring a `SigningKeyId` argument.
- **MEDIUM — every FFI send path hardcodes `SigningKeyId::Active`.** `napi/context.rs`, `ffi/src/context.rs`, `uniffi/bridge.rs`. No SDK lets an agent send under `#agent`, so persona-send is Rust-internal and test-only, and an accountability claim is not expressible from any binding.
- **LOW (honest deferral, fail-closed) — governance votes resolve `#active` unconditionally.** `mod.rs:1593`, across majority, multisig, and unanimity. An attacker holding only an `#agent` key fails `verify_vote` and a vote is rejected, so no false-accept and no griefing arises. A vote carries no `signing_key_id`, so no downgrade vector exists.
- Economy kid-parsing is robust: `economy_logic.rs:92` routes through `from_fragment` (`identity.rs:200`), rejecting `"active"`, `"agent"`, `"#0"`, `""`, and `"#unknown"` as `MalformedToken`, on exact byte match, with no unicode or case coercion and no panic.
- NIT: `validate.rs:702-710` `enforce_ucan_category_a` hand-rolls a kid match instead of calling `from_fragment` (pre-existing). Drift risk only.
- Context: `enforce_inner_envelope_category_a` is never called on a live receive path, only in `sign.rs` tests. Pre-existing, outside that diff.

# TypeScript SDK fail-closed and parity (branch fix/sdk-coverage-fail-closed-and-parity @6f4ba65ff)

**Primary defense is sound: a test seam is tree-shaken out of a published
bundle.** `__setBridgeForTests`, `assertTestEnvironment`, and
`isTestEnvironment` are not re-exported from `index.ts`; with `tsup`
`entry=[index.ts]` and `splitting: false`, esbuild removes all three (grep count
0 in a bundle). Only `_evaluateTestEnv` survives internally, outside an export
clause. `files: ["dist/"]` excludes `src/`, and an exports map listing only `"."`
makes a deep subpath import throw `ERR_PACKAGE_PATH_NOT_EXPORTED`, so a runtime
test guard is defense-in-depth rather than a boundary. UCAN regex
`/^\[SCP-PERM-\d+\]/` anchoring is sound: a leading newline or space defeats `^`
and a message is rethrown, which fails closed. `extractCore` marker and em-dash
injection are inert, because `indexOf` finds a first marker and `startsWith`
compares a prefix Rust fixes. Misclassifying a message as UCAN always lands
`unknown`, leaving all six `CapabilityValidation` fields false.

- **Residual, low severity:** `BUN_TEST=0` and `BUN_TEST=false` leave a seam open, since only `length > 0` is tested. Moot once a bundle removes that seam. A falsey-value guard would close it.
- **Gate soundness — `check-sdk-coverage.py` accepts a type name as proof of a runtime capability.** `_extract_typescript_symbols` folds interface and type-alias names into one set with runtime functions, and `_to_pascal(op)` then matches a type. Proven: Governance `member_role` matches a `MemberRole` type rather than `SCP.contextMemberRole`; MCP `connect_client` matches an `McpClient` interface, while an alias also lists a deleted `connectMcp` and real implementations are `mcpClientConnectStdio` and `mcpClientConnectSse`. That gate stays green after deleting every runtime implementation when a same-named type survives. 2 of 184 TypeScript operations are affected. This is a softer reintroduction of a suffix-match gap that pull request claimed to close. That file now sits in CLAUDE.md's enforcement allowlist, so report it and never self-edit it.
