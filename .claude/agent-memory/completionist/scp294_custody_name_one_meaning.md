---
name: scp294-custody-name-one-meaning
description: SCP-294 custody-string fail-closed review — where a corrected name stayed wrong; the checked-in UniFFI Swift bindings are a layer reviewers forget to regenerate
metadata:
  type: project
---

Branch `fix/scp-294-custody-name-means-one-thing` (base `5e7e5b4e67`) made `"platform"`
return `SCP-IDENT-1003` on the PyO3 bridge, deleted `CustodyMethod::Platform` and
`CustodyMethod::Software` from the UniFFI bridge in favour of `CustodyMethod::Callback`,
and trimmed the four SDK custody enums. Verdict: INCOMPLETE.

**Why:** a rename that spans an enum exported through UniFFI reaches more surfaces than a
grep for the old string finds.

**How to apply — the surfaces this review found stale, check them on every custody or
UniFFI-enum rename:**
- `bindings/swift/Sources/SCP/Internal/ScpBindings.swift` is a CHECKED-IN
  UniFFI-generated file (`bindings/swift/build-xcframework.sh` writes it;
  `bindings/swift/CLAUDE.md` says "do not edit"). Its Kotlin counterpart
  (`bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/internal/uniffi/scp/scp.kt`) is
  NOT git-tracked and regenerates on build, so the Kotlin side looked correct while the
  Swift side kept the deleted enum cases and shifted every FFI discriminant.
- A live error message can instruct a caller to pass the rejected string:
  `crates/scp-ffi/src/identity.rs` SCP-IDENT-1010 message said `custody='platform'`.
- Scaffold and template SOURCE files, not just their READMEs
  (`scaffolds/swift-*/Sources/main.swift`, `scaffolds/python-agent/main.py`,
  `templates/agent-tool-provider/agent.py`).
- A conformance test running against stub bindings can encode the old contract and still
  pass: `bindings/kotlin/scp-kt/src/test/.../conformance/IdentityConformanceTest.kt`.
- `.docs/adrs/ADR-048-scp-multi-instance.md` documents identity_create's seed rejection
  code; a custody change moves that code.

**Residual cross-bridge divergence the change did not close:** `"file"` builds a key store
on PyO3 and returns `SCP-VALID-7005` on NAPI and UniFFI; `"software"` returns
`SCP-IDENT-1003` on NAPI/UniFFI and `SCP-VALID-7005` on PyO3. Spec §3.2 of
`.docs/specs/03-identity.md` names custody substrates and does not define the accepted
create-selector string set, so no upstream artifact settles it.

Gates that PASS and therefore prove nothing here: `scripts/check-sdk-coverage.py`,
`scripts/check-pyi-generated.sh`, `scripts/validate-prd.py`. The `.pyi` types custody as
`Any`, so it never carried the vocabulary.

See [[adr057_transport_wasm_surface_parity]] for the other shape of this failure: a
surface mirrored on one binding and not the other.
