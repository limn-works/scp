---
name: ceiling-wellformed-type-invariant
description: branch fix/ceiling-wellformed-custom-enforcement — moving ceiling validation to a type invariant; good convergent shape, two local simplifications
metadata:
  type: project
---

Branch `fix/ceiling-wellformed-custom-enforcement` (HEAD 8caf7fb62, worktree /private/tmp/scp-ceiling) replaces per-caller ceiling validation with a TYPE-LEVEL invariant. Reviewed READ-ONLY; NO BLOCKER.

**Why it's the good (convergent) shape:** positive closed whitelist grammar (built-in exact match + parameterized tool_invoke `[a-z0-9_-]` token + custom `{kebab}:{kebab|*}`); `BUILTIN_CAPABILITIES` pinned to the enum by an exhaustive `match` test (`builtin_capabilities_list_is_exhaustive`) — closed by the compiler, not vigilance. Native uses `#[serde(try_from = "CapabilityCeilingRaw")]` (correct over a newtype — CapabilityCeiling is a public struct with many methods embedded in ContextRoleState; newtype would shim every method for zero added soundness). WASM uses a `ValidatedCeilingStrings(HashSet<String>)` newtype with 3 validating constructors + Deref — justified analogue because ADR-034 WASM stores strings not Capability enums, so native Deserialize can't cover it.

**Two validators are NECESSARY, not redundant:** `validate_ceiling_entry` (colon form `tool:invoke:*`) vs `validate_ucan_ceiling_string` (UCAN form `tool_invoke:*`). UCAN built-ins contain `_` which the kebab custom grammar forbids — one validator can't serve both without becoming a spelling-union (the bad shape). They share `validate_custom_ceiling_entry` (custom tail).

**Kept runtime `validate_entries()` in import_context/restore_context (lifecycle_helpers.rs) are SOUND defense, not dead:** `Supervisor::import_context` takes an already-deserialized `ContextExport` VALUE at the public boundary; `restore_context` gets a typed snapshot from a `ContextPersistence` provider that may not cross serde (in-memory provider). So those values reach the helpers WITHOUT the validating Deserialize. Real residual gap. (Open question for crypto/arch reviewers: if every PROD provider decodes from bytes, these become test-only and could be `debug_assert!`.)

**Round 2 (HEAD c2503b59a) — CONVERGED, no blocker.** Author addressed the prelude dup: extracted `validate_ceiling_entry_charset` (roles.rs:818), private fn, exactly 2 callers (the two validators delegate at 764/900), net -11 lines, doc states the "why" not the body — clean, no over-abstraction. Added `ceiling_deserialize_rejects_malformed_entry_msgpack` test: EARNS its keep (not redundant w/ JSON) — export snapshot decodes via `rmp_serde::from_slice` (real prod path) and covers both `to_vec` array + `to_vec_named` map encodings; verified sound because `CapabilityCeiling::new` (roles.rs:497) only collects, does NOT validate, so the malformed value genuinely serializes and rejection fires at the `#[serde(try_from)]` TryFrom. Grammar still closed-by-construction (positive whitelist), nothing widened. CLARITY doc-volume note from round 1: the ValidatedCeilingStrings doc (manager.rs:258) is legit "why" (ADR-034 reason + canonical-form convergence) — leave it.

**One LOW residual (optional, NOT a blocker):** the 3 WASM ceiling constructors (manager.rs from_colon_entries:320 / from_capabilities:342 / from_ucan_strings:370) repeat the same `.map_err(|e| ScpWasmError::Validation { message: e.to_string(), code: VALID_7000 })` closure verbatim 3×. In-scope (type introduced this branch). Fix = a 1-line `fn ceiling_validation_err(e) -> ScpWasmError`. Did not block.

Use as a POSITIVE reference for "replace per-caller checks with a type invariant done right" AND for a clean convergent fix-loop (dup extraction + a serde-format test that earns its keep, no over-engineering added in the follow-up).
