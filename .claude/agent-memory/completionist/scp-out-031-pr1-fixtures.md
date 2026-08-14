---
name: scp-out-031-pr1-fixtures
description: SCP-OUT-031 PR-1 audit — §5.4.4 OutletError taxonomy reconciliation + cross-SDK fixture/conformance contract @e44055576
metadata:
  type: project
---

# SCP-OUT-031 PR-1 audit (latest commit ed4bb5353, branch feat/outlet-031-pr1-fixtures-reconciliation)

**Verdict: COMPLETE (PR-1 scope) — zero findings.** Story stays `pending` (PR-2/3/4 remain).

**REVISION (ed4bb5353, supersedes e44055576):** InvalidGrant RECLASSIFIED from Protocol/6100/
`protocol.invalid-grant` → **Input/6120/`input.invalid-grant`/OutletInputError** (rationale: caller-
supplied credit-grant range violation, mirrors §5.4.5 `input.estimate-exceeds-bound` precedent).
All 8 outlet subclasses now uniformly `Outlet`-prefixed (OutletProtocolError, OutletAuthorizationError,
OutletInputError, OutletExecutionError, OutletOutputError, OutletEconomicError, OutletTransportError,
OutletGovernanceError). My earlier ALL_SLUGS gap was CLOSED: `pub const ALL_SLUGS: [&str;69]` added +
source-parse unit test (`all_slugs_lists_exactly_the_defined_slug_constants`) set-equating it to the
SLUG_* const defs, and the conformance test now set-equates fixtures↔ALL_SLUGS AND EXPECTED_PAIRS↔
ALL_SLUGS (registry-driven, closed by construction). Verified all layers consistent (spec §5.4.4,
error_codes const/slug_to_class/module-doc/rustdoc, AC[13], fixture, EXPECTED_PAIRS); no residual
6100/protocol.invalid-grant except an intentional NEGATIVE unit assertion (`slug_to_class(
"protocol.invalid-grant")==None`). 69 valid + 8 malformed + 2 supplementary (32-byte panic hash,
u64>2^53) fixtures; supplementary excluded from bijection (their pairs already in valid set). 6 conformance
+ 20 error_codes unit tests pass, validate-prd 18/443. 042b unchanged this round.

**Env gotcha:** `cargo test -p scp-testing --test outlet_error_conformance` gave a FALSE "cannot find
ALL_SLUGS / SLUG_INPUT_INVALID_GRANT" compile error from a STALE scp-protocol rlib in
~/.cargo/shared-target. `cargo clean -p scp-protocol -p scp-testing` then rerun → all pass. Always
clean-rebuild scp-protocol before trusting a "new symbol not found" error in a downstream crate here.

---
## Original PR-1 audit (commit e44055576 — SUPERSEDED by the reclassification above)
No dropped requirement, no coverage gap. One minor non-blocking hardening note (now fixed via ALL_SLUGS).

**Why:** PR-1 lands the wire-truth contract every SDK must later match; it touches spec §5.4.4,
the registry (`crates/scp-protocol/src/context/outlets/error_codes.rs` — note: in scp-protocol,
NOT scp-runtime as the commit message says), fixtures, and the Rust conformance gate.

**How to apply / verified facts:**
- Registry has exactly 69 `SLUG_*` consts, all in `slug_to_class`, all in `EXPECTED_PAIRS`,
  all in fixtures (69 valid, one per (code,slug); 8 malformed, one per class). 15 codes, all
  covered. Verified by set-diff script + all 5 conformance tests pass + 18 error_codes unit tests.
- AC17 (IkmCommitment) moved to SCP-OUT-042b cleanly: 042b AC[0-3,6,9] cover struct +
  derive_accept_time/sign/verify + AcceptOutletInterface rewiring + canonical-pair swap-regression
  test. Both stories' text honestly record the move. Nothing dropped.
- D3 InvalidGrant: uniformly 6100 / `protocol.invalid-grant` / Protocol across §5.4.4, error_codes
  (SLUG const + slug_to_class arm + module-doc table + const rustdoc + unit test), AC[13], fixtures.
  6100 default slug (`protocol.violation`) and retry (Never) NOT displaced (unit-test-pinned). No
  layer says 6101.
- `EXPECTED_PAIRS` references registry consts directly (rename/removal → compile error). Set-equality
  is fixtures↔EXPECTED_PAIRS.

**Minor finding (non-blocking, not an AC gap):** registry exposes `ALL_CODES` (so code-addition
drift IS auto-caught by `every_allocated_code_has_a_valid_fixture`) but has NO `ALL_SLUGS`. A future
slug added to `slug_to_class` WITHOUT also being added to `EXPECTED_PAIRS` would NOT fail any test —
the conformance module-doc's claim that "a registry addition without a matching fixture fails the
coverage assertion" is optimistic for the slug ADD case (true for codes, not slugs). Recommend a
`pub const ALL_SLUGS` enumeration checked against EXPECTED_PAIRS/fixtures, mirroring ALL_CODES, to
close the slug path by construction. Coverage is 69/69 TODAY, so not a current gap.
