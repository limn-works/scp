---
name: pr-sdk-coverage-source-id-fix
description: APPROVED @e807b3f9c — source_id NotRequired→str|None fix verified against bridge projection; ADR-053 separate PreRotationCustodyProvider flat/agent-first; trust/discovery/economy Py↔TS parity round
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` @e807b3f9c — APPROVED (api-design).

**Why:** Follow-up to the prior `NotRequired` finding (see [[pr_sdk_coverage_fail_closed_parity]]). That round flagged `ResolutionPathDict.source_id` typed `NotRequired` while the PyO3 bridge ALWAYS `set_item`s it (always-present-nullable). This round fixes it to `str | None`.

**How to apply (verification that confirmed the fix):**
- PyO3 `crates/scp-ffi/src/discovery.rs:236` unconditionally `set_item("source_id", resolution_source_id)` where value is `Option` → serializes `str | None`. Key always present. Tests: `:1412` string (DiscoveryHandle), `:1431`/`:1450` null. TS counterpart `types.ts:945` `sourceId: string | null`. So `str | None` (always-present-nullable) is CORRECT — `NotRequired` was wrong.
- Contrast: `TrustLevelDict.sources` IS correctly `NotRequired` — TS `TrustLevel` only carries `sources` on the `MultiLayerCorroborated` discriminated-union arm, so absence there is genuine. LESSON reinforced: judge each optional field against the bridge projection / discriminated-union shape individually, not blanket.
- `discover_contexts(query)` correctly omits SCP-instance arg: `py_context_discover` is a free `#[pyfunction]` (discovery.rs:286), no `self`. TS `discoverContexts(scp, query)` needs `scp` only for `getBridge` dispatch. `asyncio.to_thread` wrap = correct idiom (free event loop for DHT/DID path).
- ADR-053 proposed `PreRotationCustodyProvider`: flat 4-method callback (`generate`/`public_key`/`import_seed_bytes`/`consume`), SEPARATE from `KeyCustodyProvider` to structurally enforce spec §9.7.4.1 §3 substrate isolation (type-system over docs). Agent-first OK.
- Also good this round: typed `PaymentReceiptVerificationResult` replaces raw JSON string (ok=adapter-responded vs valid/all_valid=crypto-valid documented at every layer); PERM-3030 re-raise parity Py↔TS; test-guard.ts positive-allowlist env check; honest 0-defaults for non-computable behavioral fields.
- Minor non-blocking: `#632` doc-comment remnants survive in native.ts/wasm.ts (pre-existing, not introduced).
