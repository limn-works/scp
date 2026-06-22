---
name: sdk-coverage-failclosed-parity-57840faab
description: Review of fix/sdk-coverage-fail-closed-and-parity @57840faab — APPROVED; discovery/bridge/trust parity verified against Rust enums; one Python-vs-TS defensive-validation asymmetry
metadata:
  type: project
---

Reviewed `fix/sdk-coverage-fail-closed-and-parity` @ `57840faab`. Verdict APPROVED.

**Verified correct against Rust core:**
- `BridgeTrustLevel = Literal[0,1,2,3]` (py `bridge.py:26`) and `0|1|2|3` (ts `bridge.ts:38`) map exactly to `provenance.rs:43-67` enum (ShadowBridged=0..NativeNative=3). Integer Literal is the right type: bridge op returns u32 over FFI, so Literal of exact ints is more faithful than re-stringified enum.
- `_TrustLevelDict.kind` = 6 Rust `TrustLevel` variants (`addressing.rs:45-61`); `_ResolutionPathDict.layer` = 5 `ResolutionLayer` variants (`addressing.rs:102-113`). PyO3 wire shape `{"kind": str}` confirmed at `crates/scp-ffi/src/discovery.rs:229-231`.
- PERM-3030 re-raise (py `trust.py:770`, ts `trust.ts:461`) before UCAN classification is correct: handle-affinity caller-misuse must not collapse to all-False CapabilityValidation. Both have regression tests.
- ADR-051 `PreRotationCustodyProvider` (proposed): separate provider (not new methods on KeyCustodyProvider) is both security-correct (§9.7.4.1 §3 substrate isolation) and agent-first (two focused flat interfaces). Good.

**Recurring parity smell flagged (non-blocking):** Python `discover_contexts` (`discovery.py:204`) returns `cast(DiscoveryResult, dict(item))` with NO runtime variant validation, while TS `discovery.ts` validates kind/layer via `validateTrustLevelKind` (SCP-VALID-7100/7101) and throws on unknown variants. Identical wire contract, divergent defensive posture. Bridge is sole producer so no live bug, but asymmetry worth closing. See [[cross-sdk-shape-parity]].

Also: Python `_TrustLevelDict`/`_ResolutionPathDict` are underscore-private but typed as public `DiscoveryResult` field types; TS exports `TrustLevel`/`ResolutionPath`/`ResolutionLayer` publicly. Consider exporting Python field types for annotation parity.
