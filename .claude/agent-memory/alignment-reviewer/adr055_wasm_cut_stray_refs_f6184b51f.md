---
name: adr055-wasm-cut-stray-refs-f6184b51f
description: ADR-055 WASM-bridge-removal residual-reference cleanup branch chore/cut-wasm-stray-refs @ f6184b51f — ALIGNED, 1 trivial broken-prose finding
metadata:
  type: project
---

# ADR-055 WASM Cut Stray-Refs Cleanup @ `f6184b51f` (2026-06-29) — ALIGNED

Branch `chore/cut-wasm-stray-refs`, 5 commits vs origin/main (129 files, +497/-1238). Final alignment confirmation.

**ADR-055** (`.docs/adrs/phase-4.md:1468`): "Remove the WASM Bridge; Browser Clients Are Remote Thin Clients." Supersedes ADR-034 (WASM re-impl strategy) + ADR-022 (TS dual-target). FFI is now THREE bridges (PyO3, UniFFI, NAPI). Browser = remote thin client to server-side scp-node; no in-browser MLS/engine. ADR explicitly: native event-log unification "stands on its own merits where it serves the live engine; only its WASM-parity motivation is retired." `scp-protocol` wasm32 compat retained (evaluated separately).

**This branch is the TAIL cleanup, NOT the bridge deletion.** `crates/scp-ffi/wasm/` already gone on main; real `scripts/bridge-aliases.json` already 0 wasm; TS `_bridge`/`_wasmModule`/`_wasmBridge`/`_mcpAddon`/`_addon` globals already removed on main (count=0). This branch only scrubs residual references.

**Dimension 1 (convergence invariant §9.9.3/§9.8.2/§7.3.1) — PRESERVED.** consequence.rs, governance_integration.rs, event-log (lib/payload/system_actors/tree), runtime (export_import/providers/event_log) all reframe "native↔WASM byte-identical" → "all honest members byte-identical." The equivocation-detection / convergent-leaf requirement (byte-identical leaves cross-member, native↔native = real security boundary) is NEVER weakened or deleted — only the now-meaningless cross-IMPLEMENTATION framing dropped. Governance gating tests RETAIN security assertions (out-of-ceiling actions MUST reject; quorum voter mints exactly 1 leaf); only the dead `cross_impl_*_wasm` parity-test cross-refs removed (those tests gone, 0 refs remain). Factually correct: multi-honest-member minting is the genuine architecture.

**Dead-code deletions — all clean (0 refs anywhere):** `PreRotationCustodyKind::WasmLocalRetention` (scp-platform/traits.rs), `html_escape_json` (scp-ffi-common lib.rs), `CRYPTO_4020-4023` (error_codes.rs). NOTE: `CTX_2040-2046` were RELABELED (doc "WASM context X error"→"Context X error") NOT deleted — they're live, used by dozens of napi/uniffi call sites; relabel is correct (never WASM-only).

**Verified:** `cargo build -p scp-platform -p scp-ffi-common -p scp-event-log -p scp-protocol` clean; bridge-symmetry `run-tests.sh` 6/6 pass (fixtures drop wasm column coherently: good-all-bridges/good-exempt-missing/bad-missing-napi + 3 alias-bad). ffi_conformance.rs change = test-input string swap (still cites ADR-034, assertion logic unchanged). Cargo.toml rand_core/getrandom comment carefully preserves wasm32-compat-for-scp-protocol distinction.

**Dev docs truthful:** README/GETTING-STARTED/TS-README/sdk-quickstart/examples/scaffolds/templates all now "NAPI-only in-process (server Bun/Node); browser = remote thin client." Specs 09/11/25 + migration/technical-overview/white-paper downstream-consistent with ADR-055 (relabel impl/binding facts, not protocol semantics → not an artifact-flow violation).

**ONLY FINDING (TRIVIAL, doc-comment cosmetic, non-blocking):** `crates/scp-ffi/common/src/custody_parse.rs:20` — deleting the WASM clause left dangling sentence "...since the resolver stack is far heavier and" ending mid-clause with orphan "and" + blank comment line. The object ("WASM does not use the callback-custody path (ADR-034)") was removed but the conjunction "and" was not. FIX: change "far heavier and" → "far heavier." (drop the "and") or rewrite. No compile/behavior impact.

**Legit-to-keep confirmed untouched:** scp-protocol wasm32 (8 files), `.docs/specs/05-contexts.md:192` "Statically deployed (WASM, container)" = agent-artifact hashing (unrelated to FFI bridge), webtransport/webrtc, ADR-055/034/022 historical/supersession notes.

VERDICT: ALIGNED. 0 blocking, 0 material, 1 trivial broken-prose. No scope creep, no phantom provenance, convergence invariant intact.
