---
name: sdk-coverage-failclosed-parity-fc0b53543
description: Alignment review of fix/sdk-coverage-fail-closed-and-parity @ fc0b53543 — mapBridgeError partial scope, ADR-053, spec-stale TrustLevel
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ fc0b53543 (2026-06-22) — ALIGNED w/ 1 carry-forward observation

8 commits past prior ALIGNED 341df72cc. merge-base==1f1ea7cd2 (NOT origin/main a632c731a — branch 8 ahead / 67 behind; review branch-diff only, main work = phantom). Delta scope: scp.ts mapBridgeError extension (+162), discovery.py, ADR-053 §9.12 cite fix, error-code CI fix.

**Why:** focused alignment review on 6 areas (mapBridgeError completeness, SCP-CTX-2001 code, py/ts parity, ADR-053 spec alignment, §22.11.3 cite, artifact-flow).

**How to apply:** findings for next round / merge gate.

## Verified clean
- **SCP-CTX-2001 (trust.test.ts:475)**: CORRECT. Was SCP-CTX-1001 (wrong band); fixed to 2001. sdk-common.md §34: SCP-CTX- = 2000-2999. Test fixture simulating bridge error for mapBridgeError classification.
- **§3.2.1→§9.12 citation sweep**: CORRECT across identity.py:113, scp.ts identityMigrate:774-801, bridge.ts. Spec 03-identity.md:28 confirms migrate=NEW DID + DidRotationEvent to active contexts, mechanism ADR-003 §4b/§9.12. Cross-SDK cite parity coherent.
- **ADR-053 (Proposed)**: ALIGNED. 3 parts map to spec: Part1 PreRotationCustodyProvider separate iface→§9.7.4.1 §3 storage-isolation; Part2 backends→§4; Part3 ceremony→§5. consume/import_seed_bytes migration-reveal cites §9.7.4.1 Partial-publish-recovery + ADR-003 §4b correctly. Artifact-flow clean: ADR cites upstream, proposes-not-implements, defers spec change to "before code" (OpenQ#3). Renamed ADR-051→053 (051 taken by causal-dag).
- **py/ts parity**: STRONG. trust.py PERM-3030 re-raise (770) mirrors trust.ts:461. UCAN classify prefix lists match Rust pipeline. ToolInvoked aggregation count:1 matches (py:798 / ts:493-496). identity.py diff = 1 line (cite only); pure handle/data wrapper mirrors identity.ts.
- **artifact-flow**: CLEANEST. ZERO spec files modified. Only ADR-053 added. ci.yml adds gate self-test BEFORE gate (strengthening, permitted). quinn-proto 0.11.14→0.11.15 = RUSTSEC-2026-0185 fix.

## OBSERVATION (carry-forward, pre-existing, not blocking this branch)
**mapBridgeError only on 14/98 async scp.ts methods.** On main scp.ts had ZERO mapBridgeError; this branch adds the pattern but ONLY to identity methods (driver: real-NAPI test wanted IdentityError from identityRemoveAgentKey, per d0ace52f9). The other 84 async methods (contextSend/contextJoin/toolInvoke/ucanValidate/governance/broadcast/transport/mcp) throw RAW Error (native.ts does NOT type-wrap; e.g. contextSend native.ts:290 passes raw napi Error through). sdk-common.md §Error-Hierarchy MANDATES typed subclasses (ContextError/PermissionError/ToolError, all publicly exported in index.ts) for programmatic handling. Concrete mismatch: scp.contextSend docstring (scp.ts:1178) PROMISES "a typed ContextError with code SCP-CTX-2095" but without mapBridgeError the consumer gets plain Error (message has [SCP-CTX-2095] but instanceof ContextError == false). Branch improves identity, regresses nothing; full closure = wrap all async methods (or wrap in native bridge layer). NOT a blocker for this branch's stated scope.

## SPEC-STALE (independent of branch, worth filing)
TrustLevel variant: spec §22.7:551 + §22.11.3:1026 say `DiscoveryContextVerified`; Rust core scp-protocol/src/discovery/addressing.rs:60 = `HandleRegistryVerified` (every bridge emits {"kind":"HandleRegistryVerified"}). discovery.ts VALID_TRUST_LEVEL_KINDS + discovery.py TrustLevelDict.kind BOTH correctly use HandleRegistryVerified (match wire). Same for ResolutionLayer: spec says DiscoveryContext, Rust=HandleRegistry, py:26=HandleRegistry. **SDK code is RIGHT; SPEC is stale.** Branch did NOT touch spec 22. Fix flows down: update spec to HandleRegistryVerified/HandleRegistry. discovery.ts:42 ParsedAddress.type 4 PascalCase variants (DiscoveryHandle/DomainHandle/AttestationHandle/Unscoped) MATCH §22.11.3:1053-1056 — that cite is accurate.
