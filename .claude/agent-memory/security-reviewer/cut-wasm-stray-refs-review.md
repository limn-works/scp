# chore/cut-wasm-stray-refs (ADR-055 WASM-bridge removal cleanup) — CLEAN

Reviewed branch `chore/cut-wasm-stray-refs` tip `1fc4b9d62` (2026-06-29). 129 files,
+498/-1239. Removes residual references to the deleted WASM FFI bridge. ZERO security findings.

## What it actually is
- 99% comment/docstring/test-assertion-message rewords: "native↔WASM" → "all honest members";
  "ADR-011 native↔WASM unification" → "typed-event unification".
- Only non-comment Rust deltas in entire crates diff: TWO test renames
  (`matches_wasm_raw_concatenation`→`matches_spec_...` in bridge_id.rs;
  `future_dated_creation_is_consumed_verbatim` in export_import.rs, local var
  `wasm_deadline`→`verbatim_deadline`). Both test BODIES/assertions byte-preserved.
- Deletions: `html_escape_json` (WASM-only JSON escaper, 0 remaining callers),
  CRYPTO_4020-4023 (WASM-only error codes, 0 refs), `PreRotationCustodyKind::WasmLocalRetention`
  (0 refs, doc said "MUST NOT be used for security decisions"), browser-demo example (621 lines,
  no live surface).

## §9.9.3 equivocation invariant — PRESERVED/STRENGTHENED
- consequence.rs / governance_integration.rs / event-log lib.rs/payload.rs/system_actors.rs/tree.rs:
  every convergence/byte-identical-leaf claim retained; "native or WASM" → "all honest members" is a
  SUPERSET (stronger). No producer made optional/single-trusted/unverified. merge_consequence_events,
  ConsequenceDispatcher, sentinel consts (SYSTEM_TIMER/CLOSE/SAGA/CONSEQUENCE_ACTOR), event_type_tag
  (77-variant taxonomy, tag 59 retired) all logic-unchanged.

## Gates — TIGHTENED only, verified by execution
- check-no-ts-mutable-globals.sh: removed 6 allowlist entries (_bridge,_wasmModule,_initPromise,
  _mcpAddon,_addon,_wasmBridge) — ALL have 0 remaining decls in src (files deleted). Scan logic
  byte-identical. RAN gate: PASS, allowlisted=2 failed=0. Removing allowlist = tightening.
- check-bridge-symmetry.sh + bridge-aliases.json (real): 0 wasm refs. Fixtures dropped wasm/
  wasm_required keys + wasm/widgets.rs. RAN fixture suite: 6/6 pass (good-* exit0, bad-* exit1).
- ffi-export-allowlist.json: 0 wasm refs.

## Other confirmations
- html_escape_event_string (live HTML-entity XSS escaper) RETAINED, used by PyO3 context.rs (+napi/uniffi).
- CTX_2040-2046 codes+ranges UNCHANGED (label-only reword). CRYPTO_4050+ UniFFI codes untouched, no collision.
- Signed-export preimage: EXPORT_SCOPE_TAG_FULL/PUBLIC, domain separators, CURRENT_EXPORT_VERSION=4,
  MAX_CONTEXT_EXPORT_BYTES=64MiB all unchanged+enforced. serde_util 16MiB comment was WASM cap; native
  64 MiB intact. Replay-detection §9 spec: "ephemeral WASM bridge"→"ephemeral storage-less session",
  import-floor invariant logic untouched.
- rand_core/getrandom wasm32 compat retained (scp-protocol needs wasm32 target; legit-to-keep).
- No secrets/PII. cargo check -p scp-protocol -p scp-event-log -p scp-platform: clean.
