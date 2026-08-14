---
name: outlet-report-pr3-collapse-audit
description: Adversarial audit of PR-3 outlet re-port collapse (feat/outlet-report-pr3 @2f45eefa6) — full model change (OutletQuery/Call split, §7.3.8 caveats, UCAN origin_kind) rebased onto main. Verdict: SHIP, 5 attack hunts all fail-closed. One process note.
metadata:
  type: project
---

# PR-3 outlet collapse (feat/outlet-report-pr3 @2f45eefa6) — SHIP

**Why:** concurrent-execution branch rebased onto moved main + coder-agent integration fixes. Task: break it on 5 hunts.
**How to apply:** if this branch / a follow-on caveat-model PR resurfaces, these are the load-bearing proofs.

## Baseline fact that reframed everything
merge-base(origin/main,HEAD) == origin/main tip (main changed 0 files since branchpoint). So `git diff origin/main...HEAD` IS the branch delta; NO un-integrated main work to mis-merge. Hunt #3 "wrong side" collapses to internal-correctness of branch delta.
origin/main has NEITHER `TokenNbCaveatResolver` NOR `caveat_resolver` field NOR `SCP-CODE-OK` — all three are NEW in this branch (the §7.3.8 work).

## Hunt #1 caveat_resolver classification — CLEAN
- `ValidationContext.caveat_resolver`: outlet-invocation MUST use `TokenNbCaveatResolver`; validate/evaluate/broadcast use `NoCaveatResolver`.
- ALL production `validate_outlet_invocation_ucan` callers pair TokenNbCaveatResolver: napi/outlets.rs, ffi/mcp.rs, ffi/outlets.rs, uniffi bridge.rs (×2), saga.rs:1226. Verified.
- NoCaveatResolver sites are all non-invocation: broadcast subscribe (broadcast.rs:231 + tests), ucan validate/evaluate diagnostics, spending.rs (documented inert), tests (invoke.rs:1854 is a TEST not prod).
- `verify_leaf_outlet_stem_consistency` (validate.rs:1920): mixed-family forgery rejection is UNCONDITIONAL (doesn't need resolver); only the origin_kind-vs-stem consistency + time-box need Some caveats. So NoCaveatResolver at non-invocation sites skips only inert-there checks; the real forgery gate always runs.
- Rebase commit 2f45eefa6 only added `caveat_resolver:&NoCaveatResolver` to broadcast-subscribe test/handler + `nb:None` compile-fix + `.expect()` on Capability::new. Correct classification.

## Hunt #2 Capability::new Option fail-open — CLEAN (all fail-closed)
- Two `new`s: `CapabilityUri::new`→Self (UNCHANGED); `roles::Capability::new(&str)->Option` (fallible, strict §5.4.2.1; hard-breaks tool_invoke:/outlet_invoke:/tool_register to None).
- `filter_map(Capability::new)` at ffi/src/context.rs:1869 builds `granted` ALLOWLIST → drop can only SHRINK → contains()=false → DENY = fail-closed. `required` is let-else deny-on-None.
- Ceiling parse: pyo3 runtime.rs:1516 + napi runtime.rs:1594 + uniffi bridge.rs:6862/6899/8076 use `ok_or_else(..)?` REJECT loop. uniffi/runtime.rs:1097 uses skip-not-reject but relies on upstream ContextRoleState::new gate; only affects ceiling-NARROW (safe dir). No escalation path.
- Every `Capability::new("LIT").expect/unwrap` literal parses to Some in new parser; ZERO on a hard-break literal → no panic landmine.

## Hunt #3 wrong-side merge — CLEAN
Normalized (tool/outlet→XX, ws-strip) logic-diff over 131 changed src files: 60 flagged RESIDUAL(1) = ALL normalization artifacts (reflow + intended `.expect()` fallible-reconcile + intended new logic: OutletQuery/Call split, per_outlet_invoke, caveat resolver). Every residual token is an XX rename token; no stray control-flow/value change. saga.rs conflict = rename-only (matches prior triple-review); no NEW break.

## Hunt #4 event wire strings — CLEAN
Preserved byte-for-byte: `EventType::ToolInvoked` 50=50, `"ToolInvoked:"` 5=5, tree tags `=>11`/`=>76`, RegisterTool/RemoveTool/EstablishToolInterface 33/14/33. `tool_invoke:` 183→7 and `ToolInvoke` 149→4 = INTENDED capability-model removal (roles.rs hard-breaks it). Residuals are docs + hard-break rejection code + fail-closed tests (`assert_eq!(Capability::new("tool_invoke:foo"),None)`) + ONE inert stale fixture (ucan/mod.rs:582 `attenuation_clone_eq`, opaque string, never parsed — cosmetic).

## Hunt #5 enforcement weakened — 1 PROCESS NOTE (not a hole)
- check-error-codes.sh ADDS net-new `SCP-CODE-OK:` inline exemption (0→44 repo-wide). Commit a1b3649a6 calls it a "port" — MISLEADING, nothing existed to port. Per CLAUDE.md, check-error-codes.sh is MANDATORY-protected; adding an exemption path arguably needs human approval. BUT: Phase-1-only, per-line auditable, all 44 markers confined to outlets/error_codes.rs + errors.rs on registry-def / negative-fixture / validator-self-ref lines (none on prod emit). Only genuinely-tripping line = `SCP-OUTLET-6100` non-canonical-prefix negative fixture. Gate passes exit 0 legitimately (2785 codes). SCP-TOOL- is canonical (§5.4.4, 6000-6999) — error codes correctly NOT renamed to SCP-OUTLET (matches DO-NOT-RENAME).
- sdk-coverage.py (values tool*→outlet*, keys/cardinality preserved; wrong alias would FAIL not pass), ffi-export-allowlist.json (in-place renames, count preserved), check-handler-no-panic.sh (comment rename) = inert.

## Minor observations (non-blocking)
- New SCP-TOOL-61xx outlet codes: 0 in .docs/standards/sdk-common.md (no gate cross-checks individual codes, only ranges — doc-completeness nit).
- economy CostCategory keeps single `per_outlet_invoke` (did NOT split query/call) — design choice, not a collapse bug.
- ucan/mod.rs:582 stale `tool_invoke:assistant` in inert clone-test.

Build: `cargo build -p scp-protocol -p scp-runtime --features scp-runtime/testing` exit 0 (renamed targets resolve).
