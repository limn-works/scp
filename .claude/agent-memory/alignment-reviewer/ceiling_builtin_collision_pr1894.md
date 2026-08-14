---
name: ceiling-builtin-collision-pr1894
description: PR #1894 fix/ceiling-builtin-collision-validator spec review (ALIGNED) — wildcard-shadow invariant + canonical-resolution reframe of §5.3.1.1
metadata:
  type: project
---

# PR #1894 ceiling built-in collision validator — spec review @ ca6cadbf7 (2026-06-26) — ALIGNED

Spec/artifact review of `fix/ceiling-builtin-collision-validator`. True PR diff = THREE-DOT (merge-base 27c1849c9), only 4 files: 05-contexts.md, 07-trust-validation, phase-2.md, roles.rs (+458). `gh pr diff` / two-dot were POLLUTED (main advanced ~50 files past merge base) — always use three-dot for this PR.

**Why:** Closes a masquerade where a custom ceiling wildcard over a built-in resource (`member:*`) silently grants privileged built-in actions (`member:ban` → governance Revoke) at minting, because `is_within_ceiling` (capability.rs:196) treats stored `{resource}:*` as covering every `{resource}:{action}`.

**How to apply (verified facts):**
- §5.3.1.1 now has TWO clauses: "No privileged-built-in collision" (enforced by canonical resolution via `Capability::new` in validate_as_ceiling_entry — round-trip-to-Custom) + NEW "No built-in-resource wildcard shadow" (enforced in `validate_custom_ceiling_entry` grammar core, roles.rs ~1107).
- Wildcard-shadow reserved set is GENERATED, not hand-maintained: `BUILTIN_CAPABILITIES.iter().any(|c| c.ucan_resource_action().0 == resource)` — same `{resource}` projection `is_within_ceiling` matches. Spec accurately says "generated... never a hand-maintained enumeration."
- Actual generated set (11): bridging, context, context_child, governance, media, member, messages, metadata, role, tool, tool_invoke. Spec's "e.g." list (8) is a STRICT SUBSET — all real, NO phantom. ca6cadbf7 specifically FIXED a phantom `tool_register` (ToolRegister projects to resource `tool`, not `tool_register`) + reframed exhaustive→illustrative.
- VERIFIED by probe: `Capability::Custom("member:*").validate_as_ceiling_entry()` => Err with exact spec reason string. Locked by tests `ceiling_rejects_custom_wildcard_shadowing_builtin_resource` (4349) + `ceiling_accepts_nonshadowing_customs` (4440). 131 roles tests pass.
- Spec-first, flow-respecting: spec is upstream; code matches; downstream sentences in 07 + phase-2 are accurate summaries citing §5.3.1.1. No `.docs/` artifact depends on the now-forbidden construct (no valid-ceiling examples use `member:*` etc.; the `tool_register` hits elsewhere are FFI fn names, unrelated).

GOTCHA: main worktree was on a DIFFERENT branch (feat/actor-2c-xctx-tool-saga) — local `sed`/`grep` of roles.rs read STALE wrong-branch content; the shadow enforcement appeared "missing" until I used `git show origin/<branch>:file` + a probe worktree. Always read the BRANCH file via git show, never the local working tree, when the session branch differs.
