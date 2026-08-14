---
name: ceiling-wellformed-custom-8caf7fb62
description: Black-hat review of CapabilityCeiling well-formedness invariant (native serde try_from + WASM ValidatedCeilingStrings newtype) on branch fix/ceiling-wellformed-custom-enforcement
metadata:
  type: project
---

# Ceiling well-formedness invariant review (8caf7fb62) — NO BYPASS FOUND

Branch fix/ceiling-wellformed-custom-enforcement, HEAD 8caf7fb62. Files: scp-protocol/src/context/roles.rs, scp-ffi/wasm/src/manager.rs, scp-runtime/src/context/lifecycle_helpers.rs (last is DOC-ONLY, no behavior change).

## Verdict: invariant HOLDS. No CRIT/HIGH/MED. Tried hard, found no storable malformed/over-broad entry and no native↔WASM canonical-form divergence introduced by the diff.

## Native side
- `#[serde(try_from = "CapabilityCeilingRaw")]` on CapabilityCeiling. Raw mirror is private, only deserialization waypoint, runs validate_entries() in TryFrom. CONFIRMED fires for BOTH serde_json AND rmp_serde/MessagePack (test `context_role_state_msgpack_roundtrip` + `import_rejects_malformed_ceiling_entry` + `restore_rejects_malformed_ceiling_entry` + `tampered_role_ceiling_rejected` all pass).
- Capability enum serializes as VARIANT repr (e.g. {"Custom":"payments:approve"}), NOT UCAN string. Native export = ContextRoleState{CapabilityCeiling enum-set}.

## WASM side
- ValidatedCeilingStrings(HashSet<String>) newtype. Inner .0 PRIVATE to manager.rs. Only Deref (read-only &HashSet), NO DerefMut. 3 validating ctors: from_colon_entries (create), from_capabilities (ModifyCeiling), from_ucan_strings (import). default()=empty/default_ceiling-mapped. test_insert is #[cfg(test)].
- WASM export = SEPARATE WasmContextExportSnapshot{ceiling_strings: Vec<String>} (UCAN strings) — DOES NOT use native CapabilityCeiling type, so native validating Deserialize does NOT protect WASM import; from_ucan_strings@6450 is the sole guard (present).
- All 5 prod write sites to PerContextState.ceiling_strings route through a ctor/default. No raw field write outside manager.rs (consequence.rs uses make_bare_per_context_state). No field is pub.

## Vectors probed and CLOSED
- `*:*`, `*:read` → rejected (resource fails is_kebab_token).
- `a:b:c` multi-colon → rejected (action contains ':').
- `payments` no-colon → rejected.
- `tool_invoke:my-tool:extra` → rejected (tool_id token fails on ':').
- Unicode/control/whitespace/HTML-special → rejected (byte-level is_ascii_lowercase + is_control + is_whitespace).
- Non-canonical COLON-form built-ins on import (`tool:invoke:*`, `context:child:create`) → REJECTED by from_ucan_strings (calls validate_custom_ceiling_entry directly, not validate_ceiling_entry) so import can't store a spelling that diverges from canonical UCAN.
- DoS on honest import: all 18 built-in ucan_capability_name() forms accepted by rule 1 (incl underscore forms media:screen_share, context_child:create, tool_invoke:*, bridging:*). Bare `bridging` (no colon) WOULD be rejected, but no conformant exporter emits it (canonical is bridging:*). Not a real DoS.
- Idempotency: import-then-reexport stable on both sides.

## INFORMATIONAL footgun (pre-existing grammar, NOT introduced; diff ALIGNS bridges)
- `custom:tool:invoke:*` → Capability::new strips custom: → Custom("tool:invoke:*") → validate_as_ceiling_entry validates name() "tool:invoke:*" which IS a BUILTIN_CEILING_CATEGORY → Ok → ucan_capability_name = "tool_invoke:*" (privileged invoke-all in string checks). NEW WASM stores tool_invoke:* (matches native); OLD WASM stored harmless custom_tool_invoke:*. So diff removes a WASM-side quirk and aligns to native's PRE-EXISTING (creator-self-authored, arguably over-permissive) behavior. Correct convergence direction; the grammar admitting custom:<builtin-colon-form> is the underlying clarity issue, worth a spec note but not an invariant break (ceiling = creator's own max-authority declaration).
- Pre-existing native enum-vs-string-check divergence: Custom("tool:invoke:*")/Custom("messages:*") are NOT recognized by enum CapabilityCeiling::contains() (only string-form in_ceiling wildcard match grants). Out of scope of this diff.

## Gotchas for re-review
- wasm32 TEST target has 23 pre-existing compile errors (scp_identity unlinked) — CONFIRMED present on clean HEAD via stash. Ceiling WASM tests validated via `cargo test -p scp-runtime --test wasm_conformance --features testing` (55 pass) + clippy `-p scp-ffi-wasm --target wasm32-unknown-unknown` (clean lib).
- `make_bare_per_context_state` mode = "Unencrypted" (typo-ish vs "Encrypted"/"Broadcast") — unrelated.
