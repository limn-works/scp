
## HEAD 30d5d1504 re-review (2026-06-29). Ship. No blocking defects.
- Tip adds 3 NAPI `decode_asserted_nonce` unit tests in NON-gated `mod tests` (non-hex +
  wrong-length fail-closed + canonical-32-hex happy). Target the REAL prod decoder
  (tools.rs:748, invoked saga path line 898); asserted msgs ("is not valid hex"/"exactly 16
  bytes"/VALID_7001) match impl. Closes the NAPI non-hex arm gap (UniFFI already had both).
- RE-RAN neuter BOTH bridges THIS pass: `if false &&` on axis-a guard
  (NAPI identity_registry_contains / UniFFI identity_custody_registry.contains_key) →
  BOTH axis-a tests fail closed (member-but-unhosted now gets 13062 reaching target actor;
  unhosted now falls through to axis-b 13050 msg), axis-b + commit + echo-fallback stay GREEN.
  Restored clean (git diff empty). Axis-a proven independent of axis-b on both.
- Suites green: NAPI lib 266 (feat) / no-feat -D warnings CLEAN; UniFFI lib 170 / no-feat CLEAN;
  PyO3 e2e 61 (6 saga); common saga_errors 5 (incl None-never-0); pipeline_wiring 73
  (3 saga_export_wires bridge assertions, brace-matched fn_body_contains pin axis-a AND axis-b);
  ffi_conformance 47.
- MINOR (low-ROI, non-blocking): PyO3 decode_asserted_nonce non-hex arm (src/tools.rs:1012)
  untested — PyO3 e2e covers only wrong-length; non-hex covered behaviorally on NAPI+UniFFI.
  PyO3 is the "100%-coverage reference bridge" so a 1-line mirror test would close it.
- TS real-napi.test.ts UNCHANGED since prior verified addon 3/3 pass (tip commits Rust-only);
  marshaling independently covered by Rust units. Not rebuilt this pass.

## Submodule relocation re-review at HEAD 49402beae (2026-06-29). Ship.
- Tip commit relocated saga test cluster (helpers + UniFFI 5 / NAPI 4 tests) into a
  single `#[cfg(feature="allow_in_memory_custody")] mod xctx_saga_tests { use super::*; }`
  on both bridges, replacing per-item cfgs. Closes no-feature dead-code regression class
  (ungated pure-string helpers → "never used" warnings).
- VERIFIED pure move: `git show -w 49402beae` non-WS lines = only module-doc + wrapper +
  removed redundant per-item `#[cfg]` + rustfmt reflows (multi-line fn-calls/panic! — string
  contents IDENTICAL) + closing brace. Zero test logic/assertion change.
- `RUSTFLAGS="-D warnings" cargo test -p scp-ffi-{uniffi,napi} --lib --no-run` (NO features):
  both WARNING-CLEAN. Item(1) PASS.
- Feature-on: UniFFI 5/5 + NAPI 4/4 under new `xctx_saga_tests::` names; full libs 170/263.
  PyO3 e2e 6 + map routing 2/2; common saga_errors 5/5; pipeline_wiring 73 (incl all 3
  saga_export_wires); ffi_conformance 47. No rebase breakage.
- NEUTER (item 4) re-run THIS pass, both bridges: deleting axis-a (`contains_key`/
  `identity_registry_contains`) → member-but-unhosted test gets 13062 (reaches target actor)
  not 13050 → FAILS CLOSED. UniFFI bridge.rs:21486, NAPI tools.rs:2358. axis-a proven
  independent of axis-b on BOTH.
- extract_fn_body anchors on `fn <name>(` w/ real depth-counted brace match + comment/string/
  raw-string/char-literal stripping; submodule (calls saga as `.method`, not `fn`) cannot perturb.
- TS real-napi.test.ts NOT touched by tip commit (relocation is Rust-only); prior addon 3/3 stands.
