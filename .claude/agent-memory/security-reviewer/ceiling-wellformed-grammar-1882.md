# PR #1882 — Ceiling-Entry Grammar (docs/ceiling-wellformed-custom-entries, 545af55fa) — 2026-06-23

Spec change governing a security gate. Bans silent-wildcard footgun: bare `Custom("payments")` no longer
silently widens to `payments:*`. New §5.3.1.1 grammar in spec 05; §5.3.1 + §7.2 + ADR phase-2 Custom(String)
comment updated.

VERDICT: APPROVED WITH 2 RECOMMENDATIONS (core hole closed; residual ambiguity in resource-token grammar).

Grammar (05-contexts.md §5.3.1.1, ~L106-116): entry = (1) built-in category exact-match | (2) custom
`{resource}:{action}` both non-empty | (3) explicit `{resource}:*`. Catch-all: "Any other unrecognized or
ill-formed string (empty resource, empty action, control characters, etc.) is likewise rejected with
InvalidCeilingCategory." Closed-by-construction (positive whitelist + fail-closed default) = correct posture
per CLAUDE.md over-engineering guidance.

CORE HOLE CLOSED: bare-token → InvalidCeilingCategory at creation, explicitly "MUST NOT be silently
interpreted as payments:* or any other capability." `:*` is the ONLY wildcard, stated unambiguously
("There is no implicit or silent wildcard"). No collision with built-ins (built-ins matched exactly first).
No fail-open: reject-on-any-non-conforming at creation time.

RESIDUAL GAPS (recommendations, not blockers — neither is a *silent-widening* of the literal text):
1. `{resource}` not constrained to exclude `*`. `*:*` / `*:read` could be read by a wildcard-matching impl
   (step 6 "wildcard support", spec 07 L79) as a grand all-resources wildcard from one short entry. Grammar
   never says resource != `*`. MOST security-relevant gap. Spec authors DO apply this rigor elsewhere
   (injectivity-invariant L1818: "attacker-placeable raw `:`"). Recommend: constrain `{resource}` charset to
   exclude `*` and `:`.
2. Multiple colons (`payments:read:write`) undefined — may `{action}` contain `:`? Interop/legibility gap,
   not widening (worst case = narrower literal). Recommend define.
3. Whitespace (prompt asked) not addressed; "control characters" named but not the existing §9.18.6 /
   consequence-sanitization standard (L725: reject U+0000-001F/007F-009F + HTML-special + length caps).
   Recommend cross-ref §9.18.6 + define resource/action charset + length cap for the closed whitelist to be
   truly closed.

InvalidCeilingCategory: grep of crates/*.rs returned no match in this worktree (code enforcement lands next
per prompt — "the code enforces it next"). Not a finding against the docs PR.
