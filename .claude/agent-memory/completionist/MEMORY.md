# Completionist Memory

Persistent notes for the completionist review agent. Each entry: what was reviewed, the
completeness/divergence findings, and lessons about where gaps hid (which layer, which
artifact diverged) so future passes trace faster.

## Operating reminders
- Verdict is binary: COMPLETE or INCOMPLETE. No partial. An empty matrix cell, an unmet
  acceptance criterion, an unwired symbol, or a diverged artifact ⇒ INCOMPLETE.
- Trace top-down from the artifact (spec/ADR/PRD) through every layer: scp-protocol →
  scp-runtime → FFI bridges (PyO3/UniFFI/NAPI/WASM) → SDK wrappers → tests → capability matrix.
- Walk the `CLAUDE.md` Integration checklist for every new operation; build the
  requirement × layer matrix and fill every cell.
- Self-reports prove nothing — grep the real call site, read the real test body, check the
  real checkbox. Green CI only proves the tests that exist pass.
- One-way artifact flow: when code and an upstream artifact disagree, the artifact wins;
  the finding is "code diverged" (or "spec is wrong — fix spec first"), never "update spec
  to match code."
- Never weaken an enforcement file to close a gap (see the enforcement-file list in
  `CLAUDE.md`); the gap is real — fix the gap.

## Reviews
- [#2297 DID two-encoding amendment](did_two_encoding_amendment_2297.md) — relay layer = full
  JSON, Mainline = 4-element bootstrap core; deleted cross-layer byte-identity/highest-seq/
  healing. Where the deleted rule survived: security classifications resting on it (ADR-062
  E4), end-of-section tables, unnumbered lists above amended items, PRD `title`/`result`.
- [ADR-057 transport wasm-surface parity](adr057_transport_wasm_surface_parity.md) — every
  embedder-facing `pub fn` on `scp-client::ScpClient` must be mirrored on
  `scp-client-wasm::WasmScpClient`; `resubscribe_all` was not (inter-layer gap). Also: type
  renames (Socket→RelaySink) leave stray doc refs; native reciprocal-announce is a legit
  recorded follow-up.
