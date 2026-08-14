# ceiling-wellformed-custom-enforcement review (fix/ceiling-wellformed... HEAD 8caf7fb62)

Change: malformed CapabilityCeiling unrepresentable. Native validating Deserialize
(`#[serde(try_from = "CapabilityCeilingRaw")]` → validate_entries), WASM
ValidatedCeilingStrings newtype (3 constructors from_colon_entries/from_capabilities/
from_ucan_strings), new scp-protocol fns validate_ucan_ceiling_string +
const BUILTIN_CAPABILITIES (18) + extracted validate_custom_ceiling_entry.

VERDICT on intended change: CLEAN. Compiles (protocol+runtime+wasm), 117 roles tests +
16 wasm ceiling + 26 runtime ceiling + 55 wasm_conformance all pass. clippy clean.
- Serde round-trip sound: try_from affects deserialize only; serialize still uses field
  `#[serde(with=serde_sorted_set)]`; Raw mirror replicates the attr exactly → no wire change.
  CeilingEntryError derives thiserror (Display) so serde try_from error bound satisfied.
- validate_ucan_ceiling_string correct: rule1 exact-match BUILTIN_CAPABILITIES (handles
  underscore forms context_child:create, media:screen_share, bridging:*, tool_invoke:*),
  rule2 tool_invoke:{id} via is_tool_id_token (allows _), rule3 custom delegates to
  validate_custom_ceiling_entry (rejects multi-colon / non-canonical colon-form built-ins).
  len==18 correct (20 variants − ToolInvoke − Custom); exhaustive-match test enforces.
- Dead code: build_ceiling_strings fully removed (only 2 doc-comment mentions remain).
  capability_to_ucan_format still used legitimately for SuspendCapability/RestoreAccess
  (suspended set, NOT ceiling — out of scope, pre-existing).
- Runtime validate_entries() retained at import_context:1790 + restore_context:2412
  (belt-and-suspenders for in-memory Supervisor entry, bypasses serde).

CRITICAL ENV ARTIFACT (not a code defect): during review the worktree's UNCOMMITTED
roles.rs changes got reverted on disk (~23:36) leaving manager.rs:370 calling
validate_ucan_ceiling_string which no longer exists → `cargo build -p scp-ffi-wasm`
fails E0425. The change is a 3-file atomic set (roles.rs + manager.rs + lifecycle_helpers.rs);
roles.rs is the producer, other two are consumers. Lost roles.rs = broken build.
Recovered intended state via `git apply` of roles.rs hunk from `git diff HEAD` to verify.

LOW (pre-existing, not this diff): SuspendAccess copies ctx.ceiling_strings (now canonical
UCAN) into suspended set, but SuspendCapability/RestoreAccess use
capability_to_ucan_format(cap.name()) — old conversion that yields custom_X for multi-token
custom. Potential format mismatch on RestoreAccess removal for custom multi-token caps.
Untouched by this change; flag if touching suspension code.

LESSON: re-grep / re-read after any external file mutation — early grep returned STALE
line numbers (1472/5728 for build_ceiling_strings) because the file was being modified
mid-review. md5/re-grep to confirm ground truth before reporting.
