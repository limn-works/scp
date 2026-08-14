# PR #1882 ceiling-wellformed-custom-entries (docs) -- 2026-06-23

Branch docs/ceiling-wellformed-custom-entries @ b9b1e7382. DOCS-ONLY.
Adds §5.3.1.1 Ceiling-Entry Grammar (05-contexts), mirrored in 07-trust §7.2 + phase-2 ADR-009.

## Grammar logic: SOUND (REC-1 + REC-2 met)
- `*` airtight: shape #3 allows `*` ONLY as whole action segment of `{resource}:*`. `*:*`,`*:read`,`*`,`pay*ments`,`payments:wr*`,`pay*:read`,`*:` all malformed. No resource wildcard. Explicit "no implicit/silent wildcard."
- charset `[a-z0-9-]+` (sourced from §7.2), exactly-one-colon, reject-by-default ("neither built-in nor well-formed custom" -> InvalidCeilingCategory). Closed whitelist.
- Precedence (the key subtlety): two-colon built-ins (`tool:invoke:*`, `tool:invoke:{tool_id}`) accepted via shape #1 exact-match; one-colon custom rule never rejects them (colon-count disjoint). One-colon built-ins (`messages:read` etc.) overlap shape #2 structurally but acceptance is OR not XOR (Category-validation para: fail only if "neither"), so harmless. `media:screen_share` underscore: accepted via #1 literal lookup, not subject to kebab charset. No fail-OPEN. NOT ambiguous.

## DEFECT (still open): wrong §-citation for sanitization + cap (broken provenance)
All THREE files cite "§9.18.6 string sanitization ... §9.18.6 string length cap (256 bytes)":
- 05-contexts.md:120, 07-trust:116, phase-2.md:366
BUT:
- §9.18.6 = "Context and Governance (Invariants)" constants TABLE. Contains NO control-char/HTML sanitization rules. Its only string-length constant is "Max role name length 64 bytes" (NOT 256).
- Canonical sanitization rule = §9.1A "Input Validation Principle" (control chars U+0000-001F/007F-009F, HTML-special <>&"'). Existing specs cite it as §9.1A (e.g. 05-contexts.md:422 "String field validation (§9.1A)").
- General 256-byte cap is a per-field value in §9.1A/§5.9 tables (role/name=256), not in §9.18.6.
- Note 07-trust:725 (pre-existing) correctly cites §9.18.6 ONLY for the 64-byte role-name constant -- so the right citation pattern already exists in-repo.
Fix: cite §9.1A for sanitization; cite the per-field 256-byte cap location (§9.1A pointer / §5.9), not §9.18.6.
