---
name: ceiling-entry-grammar
description: §5.3.1.1 ceiling-entry grammar enforcement (PR #1884) — mint/validate parity, the no-colon→wildcard fix, and the ModifyCeiling enforcement gap
metadata:
  type: project
---

# Capability ceiling-entry grammar (spec §5.3.1.1)

PR #1884 (`fix/ceiling-wellformed-custom-enforcement`) added `validate_ceiling_entry` (single canonical string validator) in `crates/scp-protocol/src/context/roles.rs` and wired it at `ContextRoleState::new` (via `CapabilityCeiling::validate_entries`) + 4 bridge create paths (pyo3/napi reject, wasm rejects inline, uniffi `filter`-skips as post-create defense-in-depth).

**The real broadening fix is at `Capability::ucan_resource_action`** (roles.rs ~296): the no-colon `Custom` branch changed from `name → name:*` (silent wildcard) to `name → name:name` (concrete, inert). This is the mint→validate bridge: `to_ucan_string_set()` derives the ceiling string set the validate gate (`CapabilityUri::is_within_ceiling`) checks. So even a directly-constructed no-colon custom can no longer grant `name:*`.

**Mint↔validate parity (sound):** mint enum-gate `CapabilityCeiling::contains` and string validate-gate `is_within_ceiling` agree for exact custom, explicit `{resource}:*`, and absent custom. Parity tests `ceiling_mint_and_validate_agree_on_custom_action` / `..._wildcard` pass. Built-in `tool:invoke:*` wildcard semantics unchanged.

**GAP found (enforcement asymmetry, NOT broadening):** the grammar gate runs ONLY at context creation. The `ModifyCeiling` governance flow does NOT validate:
- native: `execute_modify_ceiling` → `apply_pending_ceiling_modification` → `set_ceiling(CapabilityCeiling::new(...))` (governance_helpers.rs ~480) — no `validate_entries()`.
- wasm: `manager.rs` ~3360 `ModifyCeiling` rebuilds `ceiling_strings` from `new_ceiling` with no `validate_ceiling_entry`.
- `set_ceiling` (roles.rs ~1425) does not validate.

Impact: a malformed entry (`payments`, `*:*`, `payments:read:write`) CAN be stored via ModifyCeiling, contradicting the PR comment "a malformed entry can never be stored in a CapabilityCeiling." Not an authorization broadening (no-colon→name:name keeps it inert; stray-`*` entries never match a legitimately-parsed URI), but a spec-conformance gap (§5.3.1.1 rejection is creation-only). Fix: call `CapabilityCeiling::validate_entries()` in the ModifyCeiling propose or apply path (both native + wasm).

Validators (`validate_ceiling_entry` etc.) callers as of PR #1884: only the 4 bridge create paths. `validate_entries` only at `ContextRoleState::new`.

## Re-review @8caf7fb62 (the ModifyCeiling-bypass fix)

Prior ModifyCeiling GAP is CLOSED: `set_ceiling` is now fallible (`-> Result<(),CeilingEntryError>`, validates whole replacement via `validate_entries` before store, fail-closed leaves prior unchanged); native apply path (`apply_pending_ceiling_modification`) routes through it; native propose path (`execute_modify_ceiling`) per-cap `validate_as_ceiling_entry`; WASM `dispatch_modify_ceiling` per-cap validate then store via `capability_to_ucan_format(&c.name())`; common bridge `validate_governance_action_strings` ModifyCeiling arm validates parsed enum. Native ModifyCeiling fully typed `Vec<Capability>` — no string re-parse, propose==apply parity by construction.

**BLACK-003 parity fix at the 4 create bridges**: switched from `validate_ceiling_entry(raw)` to `Capability::new(raw).validate_as_ceiling_entry()` so validate-side parse == store-side parse. Correct for pyo3/napi (store-side ALSO `Capability::new(s).ucan_capability_name()`). uniffi filter parsed.

**NEW FINDING (HIGH, introduced by THIS PR): WASM create-path validate/store split.** WASM create validate-side now parses (`Capability::new(entry).validate_as_ceiling_entry()`, manager.rs ~1463) BUT store-side `build_ceiling_strings` (manager.rs ~5728/5701 `capability_to_ucan_format`) is UNCHANGED — operates on RAW string. The two disagree exactly on `custom:`-prefixed multi-token entries. `"custom:payments:approve"`: validate parses→`Custom("payments:approve")`→ACCEPT; store raw `capability_to_ucan_format("custom:payments:approve")`→`"custom_payments:approve"`. Native create stores `"payments:approve"`. Result: (a) validate/store representation mismatch on WASM create; (b) native↔WASM equivocation for same creation input; (c) a UCAN for `payments:approve` is admitted on native, REJECTED on WASM (step-8 `ceiling_strings.contains` miss). Pre-PR this was masked: base WASM raw-validate REJECTED `custom:payments:approve` (action contained `:`). The parsed-validation change newly admits it without fixing store. FIX: WASM create store must parse too — `build_ceiling_strings` should map `Capability::new(s).name()` (or equivalent) before `capability_to_ucan_format`, mirroring the WASM ModifyCeiling handler which already does `capability_to_ucan_format(&c.name())`.

**Pre-existing (NOT this PR): Bridging string divergence.** `Capability::Bridging` → native `ucan_capability_name`=`"bridging:*"` (ucan_resource_action gives `("bridging","*")`) but WASM `capability_to_ucan_format("bridging")`=`"bridging"` (no colon, passthrough). Reachable on create path both pre/post PR. Separate cross-impl issue; flag informational.
