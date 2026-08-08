---
name: outlet031-pr2b-bridge-render
description: SCP-OUT-031 PR-2b (3 FFI bridges render OutletErrorSurface) audit — where the gaps and false self-report claims were
metadata:
  type: project
---

SCP-OUT-031 PR-2b audit (branch `feat/outlet-031-pr2b-bridge-render`, base d1ebc5ab9). The
bridge render itself landed and all gates/tests pass; the failures were in the **auditNote's
self-report**, not the code. Recurring lesson: verify every load-bearing sentence of an
auditNote against the code — internally-consistent prose passes ordinary review.

Claims that were FALSE and how they were caught:
- "ONE shared projection … all three bridges cannot drift" — the UniFFI bridge does NOT use
  `scp_ffi_common::outlet_error` at all; it hand-writes its own 8/10/4/3-arm `from_core`
  mirrors in `bridge.rs`. Catch: `grep -rn render_members\|render_surface_json crates/` →
  only PyO3 + napi hit.
- "a single in-process 3-way test is impossible: scp-ffi-napi is `crate-type = [\"cdylib\"]`"
  — it is `["cdylib", "lib"]` (crates/scp-ffi/napi/Cargo.toml:11), and a
  `scp-ffi-napi-test-stubs` crate exists precisely to let it link without Node. Catch:
  always `grep -n crate-type` when a comment cites linkability as a constraint.
- "the security tests were widened to all five non-Active states" — `ContextState` has 8
  variants, 7 non-Active; `Creating` and `Closed` are untested at all three bridges. Catch:
  enumerate the enum, don't trust the count in the prose.
- "`from_envelope` is now WIRED into the cross-context path" — the three
  `From<errors::OutletError>` impls have ZERO production producers (`OutletError::new` is
  called only by fixtures). Honest caveat follows two sentences later, but the headline
  contradicts it.

Also: the working-tree generated Kotlin (`bindings/kotlin/.../internal/uniffi/scp/scp.kt`,
gitignored) was stale from an earlier doc-comment revision and made
`scripts/check-error-codes.sh` exit 1 locally. Regenerate uniffi bindings after editing
doc comments on uniffi-exported items.

Related: [[adr057_transport_wasm_surface_parity]].
