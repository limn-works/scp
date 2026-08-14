# PR #1894 — ceiling built-in-collision validator (branch fix/ceiling-builtin-collision-validator)

CLEAN review (2026-06-24). File: crates/scp-protocol/src/context/roles.rs.

Change: `Capability::validate_as_ceiling_entry` `Custom(s)` arm re-resolves `s`
through `Capability::new(s)` and rejects if result is non-`Custom` (built-in in any
spelling) = "No privileged-built-in collision".

### Re-reviewed at HEAD 7bd7b4293 (2026-06-26): STILL CLEAN
HEAD replaced the old projection-membership test with a NEW second rule:
`validate_custom_ceiling_entry` now has "No built-in-resource wildcard shadow":
`if action == "*" && BUILTIN_CAPABILITIES.iter().any(|c| c.ucan_resource_action().0.as_ref() == resource) -> reject [shadow]`.
Rationale: `member:*` does NOT resolve to a built-in (no `member:*` variant) so the
collision rule misses it, but `is_within_ceiling` (capability.rs:202) does
`ceiling.contains("{resource}:*")` so a stored `member:*` would grant `member:ban`.
Shadow rule mirrors that exact `{resource}` projection — closed by construction over
BUILTIN_CAPABILITIES. Also: `validate_ceiling_entry` `pub`->`pub(crate)` (never
re-exported from context/mod.rs; zero cross-crate callers — compile-safe, no dead-code
warning). Empirical truth table (probe in throwaway wt) over member/messages/media/tool/
role/governance/context/metadata/bridging:* + tool_invoke:* + payments:*/a-b-c:* +
member:promote/messages:archive:
- all builtin-resource `{r}:*` REJECT[shadow] on Custom/ucan/colon paths;
- `bridging:*`: Custom=REJECT[names] (resolves to Bridging), ucan=ACCEPT (legit builtin
  form), colon=REJECT[shadow] — test's `wildcard_is_builtin_form` branch logic correct;
- `tool_invoke:*`: Custom=REJECT[names], ucan=ACCEPT(builtin), colon=REJECT (kebab
  resource rejects `_` before shadow check) — correct, can't be spelled by a custom;
- payments:*/a-b-c:*/member:promote/messages:archive ACCEPT on all 3 (no over-reject).
Cow `.0.as_ref()==resource`: all BUILTIN_CAPABILITIES `.0` are Cow::Borrowed (no Custom
in the list) -> no alloc, no panic. Both new tests (`ceiling_rejects_custom_wildcard_
shadowing_builtin_resource`, `ceiling_accepts_nonshadowing_customs`) FAIL when shadow
check neutered, PASS restored — meaningful, assert reason "shadows"/"names". 131 roles
tests pass. clippy scp-protocol clean.

### Original pass (earlier commit, kept for history):
`validate_custom_ceiling_entry` retains a membership test rejecting customs
whose canonical UCAN projection equals a built-in's `ucan_capability_name`.

Verified by truth table (probe test in throwaway worktree):
- enum-form `validate_as_ceiling_entry(Custom(..))` + deserialize boundary (serde
  try_from -> validate_entries -> per-entry validate_as_ceiling_entry) REJECT every
  built-in spelling (tool:invoke:*, tool:invoke:calc, bridging, bridging:*,
  messages:read, context:child:create, media:screen_share). This is the real attack
  surface (untrusted Custom on wire). Correct.
- `validate_ceiling_entry` (raw colon string) returns OK for legit built-in colon
  spellings (accepted as built-ins via rule 1/1b) — correct, not a bug. Only
  `bridging:*` reaches the membership test and is rejected (collides).
- Legit customs payments:read / payments:* pass all paths (no over-reject).
- ToolInvoke arm unchanged; valid ids accepted, malformed (`*`, empty) rejected.
- Custom("custom:foo") -> new strips prefix -> Custom("foo") roundtrips -> validates
  as resource `custom`/action `foo` -> OK (no built-in projection). Consistent.
- `Capability::new` is infallible (returns Self, never Err). No unwrap/panic in new code.
- Minor: legit-custom path allocates a throwaway String in new() before
  validate_ceiling_entry(name). Not a bug.

Test quality VERIFIED MEANINGFUL: reverted both guards in worktree -> all 7 new
regression tests FAIL before / PASS after. Tests assert error REASON ("names a
built-in", "collides with a built-in", "§5.3.1.1") so they prove the specific guard
fired, not incidental grammar failure. Accept-tests guard over-rejection. No `let _ =`
gaming. clippy clean on scp-protocol.

Production callers: validate_entries() (per-entry via enum form) is the authoritative
gate at try_from deser (line 570), ContextRoleState::new (1549), set_ceiling (1783);
governance_helpers.rs:1566 also uses enum form. Backstop sits on the real gate.
