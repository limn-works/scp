---
name: ceiling-entry-validation-cross-bridge-divergence
description: validate_ceiling_entry (PR #1884) validates RAW string while native path validates Capability::new()-normalized form, causing cross-bridge divergence on `custom:`-prefixed ceiling entries
metadata:
  type: project
---

# Ceiling-entry grammar validator: validate raw vs normalized

PR #1884 (`fix/ceiling-wellformed-custom-enforcement`) added `validate_ceiling_entry(&str)` in
`crates/scp-protocol/src/context/roles.rs` to reject malformed ceiling entries (spec cites §5.3.1.1,
which does NOT exist in `.docs/specs/05-contexts.md` — spec only has §5.3.1 "exact match, case-sensitive"
against the enumerated table; there is NO custom `{resource}:{action}` grammar in the spec at all → alignment gap).

**Core bug (MEDIUM): cross-bridge divergence.** Two validation entry points disagree because they
validate different forms of the same input:
- Bridge string validators (PyO3 `register_ffi_state`, NAPI `ensure_registered`, WASM `create_context`)
  call `validate_ceiling_entry(raw_user_string)`.
- Native path (UniFFI/runtime `ContextRoleState::new` → `validate_entries` → `validate_as_ceiling_entry`
  → `validate_ceiling_entry(self.name())`) validates the `Capability::new(s)`-NORMALIZED form, which
  strips a leading `custom:` prefix.

Proven mirror-image divergence:
- `custom:payments`     → WASM accepts (stores `custom:payments`), native REJECTS
- `custom:payments:approve` → WASM rejects, native ACCEPTS (stores `payments:approve`)

WASM is the only bridge whose SOLE gate is the string validator (it does not route through
`ContextRoleState::new`) AND it uses its own `capability_to_ucan_format` (does not call `Capability::new`,
so it treats `custom:` as a literal resource token). PyO3/NAPI route create through native
`dispatch_lifecycle_command(CreateContext)` → native validator (stricter, wins). Violates the
"identical shape across all language bindings" invariant (CLAUDE.md agent-first API design).

Root cause: validate the normalized canonical form everywhere. Either run `validate_ceiling_entry`
on `Capability::new(s).name()` at the bridges too, or reject `custom:`-prefixed inputs uniformly.

Pre-existing context: `Capability::new` strips `custom:`; `Custom("a:b:c")` is a documented
roundtripping form (`capability_display_new_roundtrip` test). `ucan_resource_action` for Custom uses
`rsplit_once` (last colon) while `validate_ceiling_entry` uses `split_once` (first colon) + rejects
multi-colon — so the validator and the UCAN-name producer disagree on well-formedness for multi-colon
customs (validator rejects `a:b:c`, but `ucan_capability_name` still yields `a_b:c`).

## PR #1884 fix re-review (HEAD 8caf7fb62) — original VALIDATION divergence CLOSED, STORAGE divergence REMAINS on WASM create path

The fix switched all bridge VALIDATORS (PyO3/NAPI/UniFFI/WASM-create) from `validate_ceiling_entry(raw)`
to `Capability::new(raw).validate_as_ceiling_entry()` (parsed/normalized form) + added `set_ceiling`
fallible grammar gate + propose-time + import/restore + WASM `dispatch_modify_ceiling` + governance-string
arm. Verified clean: set_ceiling callers (only prod caller = governed apply at governance_helpers.rs:489,
maps err→InvalidState, fail-closed; 6 others are #[cfg(test)] .expect); propose validates before stage,
apply re-validates (no TOCTOU); import REJECTS via ImportRejected, restore via PersistenceFailed (both
validate_entries); import test non-vacuous (real signed export, matching vkey, rejected by ceiling not sig).
Tests: scp-protocol 3023 / scp-runtime 1923 / ffi-common 323 / WASM-host 14 ceiling — all pass.

**STILL-OPEN MEDIUM (NEW SPELLING of the same root cause): WASM create-path stores from RAW string.**
`crates/scp-ffi/wasm/src/manager.rs` create_context VALIDATES `Capability::new(entry).validate_as_ceiling_entry()`
(line ~1464, strips `custom:`) but STORES `build_ceiling_strings(&ceiling)` (line ~1472) →
`capability_to_ucan_format(RAW_entry)` (line ~5701, does NOT strip `custom:`). For input
`"custom:payments:approve"`: validation accepts (as `payments:approve`), WASM stores `custom_payments:approve`,
but native PyO3/NAPI/UniFFI store `Capability::new(s).ucan_capability_name()` = `payments:approve`. Mirror cases:
`custom:billing:read`→WASM `custom_billing:read` vs native `billing:read`; `custom:a:b`→`custom_a:b` vs `a:b`.
Proven by hand-trace of both code paths. Not priv-esc (WASM form is different, not broader) but breaks
cross-bridge ceiling consistency + "identical shape across bindings" invariant: a scp-core UCAN for
`payments:approve` passes native is_within_ceiling, fails WASM. WASM ModifyCeiling path is SAFE (gets parsed
Capability enums, stores `capability_to_ucan_format(&c.name())` where name() already stripped custom:).
Fix: WASM create must parse-then-store like ModifyCeiling — `ceiling.iter().map(|s| capability_to_ucan_format(&Capability::new(s).name()))` (or `.ucan_capability_name()`). UNTESTED: create tests use `payments:approve` not `custom:`-prefixed; no native==WASM stored-form parity test on create path (only on ModifyCeiling).

No-colon Custom fallback changed `("name","*")` → `("name","name")` (removes silent wildcard) — correct,
sole non-test caller is `crypto/ucan/mint.rs:265`, behavior change is the intended fix.

Tests: 110 roles tests + pyo3 register_context tests pass; clippy clean. Reject tests assert the
actual `CeilingEntryError::InvalidCeilingCategory` variant (good). Byte-length cap uses `entry.len()`
(bytes, correct). `is_control()` = Cc category (correct). kebab byte-checked `[a-z0-9-]` (correct).
