# Ceiling well-formedness — charset-prelude dedup + msgpack reject pin (c2503b59a HEAD) — CLEAN, ZERO findings

worktree /private/tmp/scp-ceiling, branch fix/ceiling-wellformed-custom-enforcement, HEAD c2503b59a.
Range reviewed = `git diff 8caf7fb62 HEAD` (2 commits: 8bd7499bb = the fix already reviewed at the
prior "8caf7fb62 HEAD" entry; c2503b59a = the new refactor delta). 3 files: roles.rs (+482),
wasm manager.rs (+431), lifecycle_helpers.rs (+37 COMMENT-ONLY). NOTE on commit confusion: my prior
memory entry titled "8caf7fb62 HEAD" actually reviewed the tree AT 8caf7fb62 (HEAD then). 8caf7fb62
is the BASE here; the real delta is the two commits above it.

## What the delta does (beyond prior CLEAN review)
- c2503b59a extracts the §9.1A length+control+whitespace+HTML prelude into shared fn
  `validate_ceiling_entry_charset` (roles.rs), called FIRST by BOTH `validate_ceiling_entry`
  (colon form) and `validate_ucan_ceiling_string` (UCAN form) BEFORE any structural parse.
  Fail-closed ordering preserved (charset reject precedes split_once/built-in match). Verified by diff:
  old inline body in validate_ceiling_entry replaced verbatim by the call; no logic drift.
- Adds `ceiling_deserialize_rejects_malformed_entry_msgpack` test pinning the rmp_serde path
  (BOTH to_vec array + to_vec_named map encodings reject; valid round-trips). This is the
  export-snapshot wire path (deserialize_export uses rmp_serde::from_slice).

## All 6 audit concerns — re-VERIFIED CLEAN at this HEAD
1. EVERY from-bytes path fail-closed. `CapabilityCeiling` `#[serde(try_from=CapabilityCeilingRaw)]`
   runs validate_entries on serde_json AND rmp_serde (export snapshot via deserialize_export →
   rmp_serde::from_slice::<StoredValue<ContextExport>>, transitively decodes embedded ceiling →
   try_from). Tests prove json + msgpack(array+named) + embedded ContextRoleState all reject.
2. WASM import from_ucan_strings rejects malformed AND non-canonical colon-form built-ins
   (tool:invoke:*, context:child:create) — calls validate_custom_ceiling_entry DIRECTLY (not
   validate_ceiling_entry) so colon-form built-ins fall through to custom grammar and reject =
   NARROWER/fail-closed. Closes BLACK-005 (import was raw-copy). manager.rs:6458.
3. Shared-helper extraction preserves fail-closed: charset prelude runs before structural parse on
   BOTH validators (diff confirms call is line 1 of each).
4. WASM ModifyCeiling validates+canonicalizes WHOLE replacement via from_capabilities BEFORE
   require_active_context_mut + policy check + mutate (manager.rs:3440-3455). Err short-circuits,
   prior ceiling unchanged. No TOCTOU (stateless validation).
5. Error msgs echo only capability name + grammar reason; ceiling entries PUBLIC (§5.7); charset
   sanitization strips control/HTML preventing log injection. No secret leak.
6. Type-level guarantee SOUND. Runtime validate_entries() at lifecycle_helpers.rs:1790 (import,
   ImportRejected) + 2412 (restore, PersistenceFailed) RETAINED, comment-only rewrite. GENUINE
   belt-suspenders: Supervisor::import_context (supervisor.rs:7966) takes ContextExport VALUE (no
   serde at that boundary) → bypasses try_from → 1790 catches programmatic malformed export. NOT
   redundant/false-security. ContextPersistence::load_context may hand back already-typed snapshot
   not crossing serde (in-memory provider) → 2412 covers restore.

## Write-site enumeration (no prod bypass)
WASM ceiling_strings writes: 1433 default(empty), 1612 from_colon_entries(create), 3455 from_capabilities
(ModifyCeiling), 6458 from_ucan_strings(import). 385 = #[cfg(test)] test_insert. 5969/6947/8331/8395 =
snapshot DTO Vec<String> (read-out / test), not PerContextState. ValidatedCeilingStrings inner PRIVATE,
Deref only (no DerefMut). Native test mutators ceiling_mut/capabilities_mut BOTH #[cfg(any(test,
feature="testing"))]-gated — not prod. set_ceiling (roles.rs:1655) validates before store.

## Cross-path consistency (round-trip export→import)
Valid custom never contains `_` (resource+action both is_kebab_token = [a-z0-9-], no underscore), so
colon-form == UCAN-form for customs → create/modify (validate_as_ceiling_entry colon) produce strings
import (validate_ucan_ceiling_string) accepts. Export DTO reads canonical stored set → importer accepts.
3 ctors converge (test_wasm_ceiling_constructors_converge_on_canonical_form).

## Tests (RAN, all green)
scp-protocol roles: 118 pass (incl ceiling_deserialize_rejects_malformed_entry / _msgpack /
context_role_state_deserialize_rejects_malformed_ceiling / validate_ucan_ceiling_string_accepts...).
scp-ffi-wasm: 16 ceiling tests + test_wasm_create_path_canonical_form_matches_native pass.

ZERO findings, all 4 categories. APPROVED.
