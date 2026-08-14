---
name: pr1894-ceiling-wildcard-shadow-clause
description: PR #1894 §5.3.1.1 "No built-in-resource wildcard shadow" spec clause review — ALIGNED, 1 MINOR spec-accuracy defect (tool_register)
metadata:
  type: project
---

# PR #1894 §5.3.1.1 "No built-in-resource wildcard shadow" clause — ALIGNED (2026-06-26)

Reviewed at PR HEAD `7bd7b4293` (== `origin/fix/ceiling-builtin-collision-validator`). GOTCHA: local branch ref `fix/...` was STALE (`8168e6cf6`); `gh pr diff` compares against PR base but local `git show <branch>` resolves the stale ref — always `git rev-parse origin/<branch>` and review against the PR HEAD sha, not the local branch name.

**What:** new normative clause added to 05-contexts §5.3.1.1, mirrored compactly into 07-trust §116 and phase-2.md §366. Forbids a custom shape-3 wildcard `{resource}:*` when `{resource}` is the resource-token projection of any built-in (e.g. `member:*`). Security finding: `is_within_ceiling` (capability.rs:196) does `ceiling.contains(format!("{}:*", self.resource))`, so a stored `member:*` covers `member:ban` — but `Capability::new("member:*")` keeps it a `Custom` (no `member:*` built-in), so the no-collision rule misses it. Enforcement: validate_custom_ceiling_entry (roles.rs ~:222) rejects `action=="*" && BUILTIN_CAPABILITIES.any(|c| c.ucan_resource_action().0 == resource)`.

**Verdict ALIGNED.** Flow-respecting (spec = normative invariant, code cites §5.3.1.1), sound, permanent, option-1 scope correct (broader reserved-namespace rule would wrongly block legit shape-2 `member:promote`). Carve-outs verified: shape-2 under built-in resource stays valid (exact-match, no coverage); `payments:*` stays valid; `bridging:*` caught earlier by no-collision (resolves to Bridging). No downstream PRD/story depends on the forbidden construct.

**1 MINOR finding — 05-contexts.md:118:** prose resource-token list names `tool_register`, which is NOT a built-in resource projection. `ToolRegister` projects to resource `tool` (action `register`). Actual code-enforced set = 11 distinct `BUILTIN_CAPABILITIES` projections: messages, tool_invoke, tool, member, role, governance, context, context_child, bridging, media, metadata. Prose lists 12 (wrong by one). Fix: drop the hardcoded list (closed-by-construction definition already governs) or correct to 11. Also `tool_invoke`/`context_child`/`tool_register` are UNREACHABLE shadow targets (custom charset `[a-z0-9-]+` has no `_`), so listing them is moot. Confined to 05:118 — 07/phase-2 reference the rule by name + examples only, no list.

**Observations:** 05:63 "Media capabilities (`media:*`)" now slightly imprecise (`media:*` is a forbidden custom string post-clause) but it's colloquial family-shorthand, not a ceiling-entry claim — optional clarity nit. §7 cross-ref accurate (member:ban gates RevokeAccess, 05:61). Three-artifact mirror coherent.
