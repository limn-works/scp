---
name: pr-1884-ceiling-grammar
description: PR #1884 ceiling-entry grammar validator — canonical validator well-shaped; per-bridge validation calls partly redundant with runtime gate
metadata:
  type: project
---

PR #1884 (`fix/ceiling-wellformed-custom-enforcement`) adds `validate_ceiling_entry` (canonical string validator, spec §5.3.1.1) + `Capability::validate_as_ceiling_entry` (enum-form entry point) + `CapabilityCeiling::validate_entries` + `CeilingEntryError` + wiring into RoleError/ContextCreationError + enforcement at `ContextRoleState::new` + per-bridge calls in WASM/PyO3/NAPI/UniFFI.

**Verdict: APPROVED, no BLOCKER.** This is the *correct* shape for an enforcement check, not over-engineering:
- The grammar lives in ONE place (`validate_ceiling_entry`). Helpers and bridges DELEGATE; no duplicated grammar logic. The 3-layer stack (`validate_ceiling_entry` string fn → `validate_as_ceiling_entry` enum adapter → `validate_entries` collection adapter) is thin adapters over one definition, each justified (string vs enum vs collection callers).
- It is a CLOSED POSITIVE matcher: accept exactly 3 well-formed shapes (built-in exact-match table, custom `{r}:{a}`, explicit `{r}:*`), reject everything else. Not a denylist chasing spellings. Bounded by construction. Faithful transcription of spec §5.3.1.1 / §05-contexts.md.
- Not redundant with a stronger mechanism — `Custom(String)` is an open string type the type system cannot constrain, so a runtime validator is the right tool.

**The one real (non-blocking) finding — double validation in PyO3/NAPI real paths:**
- PyO3 real path (`context.rs::context_create`): line 1966 `register_context`→`register_ffi_state` runs the NEW per-bridge validation, THEN line 2006 `sup.create_context`→runtime gate `ContextRoleState::new`→`validate_entries` validates the SAME strings again.
- NAPI real path (`context.rs::context_create_on`): `ensure_registered` (new validation) + `dispatch_lifecycle_command(CreateContext)`→runtime gate. Same double-validation.
- So for PyO3/NAPI the per-bridge call is strictly redundant with the canonical runtime gate. Justified-ish because it surfaces the typed `InvalidCeilingCategory`/`VALID_7000` at the bridge boundary before UCAN-string normalization (`Capability::new`+`ucan_capability_name` is where silent `name→name:*` widening lived) and because `register_ffi_state` ordering runs before `create_context`. Acceptable defense-in-depth; not worth a BLOCKER.
- WASM per-bridge call is GENUINELY necessary: WASM does NOT route through `ContextRoleState::new` (ADR-034 — re-implements locally), so its call is the sole enforcement point there.
- UniFFI uses `.filter(...is_ok())` (skip-malformed) rather than reject, explicitly because its cache is populated AFTER the runtime gate already rejected malformed entries — infallible defense-in-depth. Reasonable.

Root-cause fix lives in `ucan_resource_action` `Custom` no-colon branch: was `name→name:*` (silent wildcard widening), now `name→name:name` (concrete, can't grant wildcard). That + the runtime gate is the actual security fix; the per-bridge calls are belt-and-suspenders.
