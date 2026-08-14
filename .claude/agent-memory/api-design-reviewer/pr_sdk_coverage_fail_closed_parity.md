---
name: pr-sdk-coverage-fail-closed-parity
description: fix/sdk-coverage-fail-closed-and-parity @6bc9dfead review — discovery/bridge-trust/economy/trust-eval TS↔Py parity + ADR-053 pre-rotation custody; APPROVED with one source_id NotRequired defect
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` (HEAD 6bc9dfead) API review. Verdict APPROVED with one recommended one-line fix.

**The one parity defect (recurring class — verify wire shape, not just the sibling SDK):** Python `discovery.py:ResolutionPathDict.source_id` typed `NotRequired[str | None]`, but the PyO3 bridge at `crates/scp-ffi/src/discovery.rs:236` does `resolution_path.set_item("source_id", resolution_source_id)?` UNCONDITIONALLY — key always present, value `str|None`. TS `types.ts:939 ResolutionPath.sourceId` is `string | null` (always-present-nullable). So `NotRequired` mis-models BOTH the wire shape and the TS contract. Fix: `source_id: str | None`.
**Why this matters as a pattern:** to judge a TypedDict's `NotRequired` correctly you must read the BRIDGE projection (does it `set_item` unconditionally, or skip the key?), not just compare to the TS interface. `set_item(k, Option)` = always-present-nullable = required key + `| None`, NOT `NotRequired`.

**Confirmed-good design decisions (don't re-litigate):**
- `BridgeTrustLevel = Literal[0,1,2,3]` (Py) / `0|1|2|3` (TS): correct return-only literal tightening of prior bare `int`; docstrings map each discriminant to Rust enum variant weakest→strongest.
- `discover_contexts(query)` async via `asyncio.to_thread` over sync `#[pyfunction] context_discover`: idiomatic. Intentional signature divergence — Py module-fn (no SCP instance) vs TS `discoverContexts(scp, query)` instance-arg — is the established dispatch split (PyO3 module-level pyfunction vs TS getBridge(scp)). See [[project_sdk_parity_idioms]].
- ADR-053 `PreRotationCustodyProvider`: 4 flat methods (generate/public_key/import_seed_bytes/consume), Zeroizing on secrets, no typestate. SEPARATE provider (not new methods on KeyCustodyProvider) is structurally mandated by spec §9.7.4.1 §3 substrate-isolation — exemplary agent-first design. `import_seed_bytes` closes the migration-reveal gap UniFFI currently fail-closes.

**Non-blocking observations:**
- Idiom inconsistency in same diff: `discovery.py` uses `total=True`+`NotRequired`; `economy.py` uses split-base-class+`total=False` for same "1 required + rest optional" shape. Both valid + both mirror their TS. Prefer the `total=True`+`NotRequired` form going forward.
- Asymmetry: Py `discover_contexts` does `cast(...)` with NO runtime validation; TS `discoverContexts` runs `parseDiscoveryResult`+`validateTrustLevelKind`. Safe (same in-process Rust core) but TS is stricter.
- `economyVerifyPaymentReceipts` (both SDKs): now typed in/out instead of JSON-string passthrough — DX win; `ok`-vs-`valid` footgun (reachable-but-invalid → ok===true) documented in both. See receipt JSON shape in [[project_sdk_parity_idioms]].
