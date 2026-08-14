---
name: pr1894-ceiling-collision-canonical-resolution
description: PR #1894 — §5.3.1.1 no-builtin-collision ceiling rule moved to canonical resolution (Capability::new round-trip); spec/code/ADR consistent, all intake paths guarded, COMPLETE
metadata:
  type: project
---

PR #1894 (branch `fix/ceiling-builtin-collision-validator`) reviewed COMPLETE 2026-06-26.

What it did: made CANONICAL RESOLUTION the sole §5.3.1.1 "No privileged-built-in
collision" mechanism. `Capability::validate_as_ceiling_entry()` `Custom(name)` arm
re-resolves via `Capability::new(name)`; if it does NOT round-trip back to a `Custom`,
reject (the string names a built-in in some spelling — colon OR UCAN, incl.
parameterized `tool:invoke:{id}`/`tool_invoke:{id}`). roles.rs:428. Closed by
construction; no denylist. Amended specs 05 §5.3.1.1, 07-trust, ADR phase-2.md to match.

**Why:** the OLD spec wording described a projection-membership test
(`ucan_capability_name` ∈ builtin-UCAN-set) as authoritative — but on `main` that test
was NOT actually wired into the `Custom` path of `validate_as_ceiling_entry`; the Custom
arm just called grammar `validate_ceiling_entry`, which EARLY-ACCEPTS a built-in's colon
spelling (`tool:invoke:*` is in BUILTIN_CEILING_CATEGORIES) and treats `bridging:*` as a
valid custom. So a `Custom("tool:invoke:*")` from untrusted deserialize would masquerade.
The PR fixes the gap and aligns the spec.

**How to apply (key wiring facts for future ceiling reviews):**
- Choke point: `CapabilityCeiling::validate_entries()` (roles.rs:684) loops every entry
  through `validate_as_ceiling_entry()`. Reached by: serde `try_from` (roles.rs:576),
  `set_ceiling` (roles.rs:1758), `ContextRoleState::new` (roles.rs:1524).
- Bridges normalize incoming ceiling STRINGS via `Capability::new` (PyO3 context.rs:1503,
  NAPI context.rs:4279, UniFFI bridge.rs:7518) → a string masquerade becomes a built-in
  ENUM (never `Custom`), neutralized; a `Custom`-valued masquerade (deserialize bypass) is
  caught by the re-resolution guard. Two surfaces jointly closed.
- WASM mirrors: `from_colon_entries`/`from_capabilities` → `validate_as_ceiling_entry`;
  `from_ucan_strings` → `validate_ucan_ceiling_string` (import stores raw UCAN verbatim,
  NO `Custom` wrapper, so no collision surface). manager.rs:326/347/371.
- Governance ModifyCeiling: propose-time `validate_as_ceiling_entry` (governance_helpers
  1566) + apply-time `set_ceiling`→validate_entries (489). Doubly guarded.
- UniFFI bridge FILTERS/skips malformed entries (runtime.rs:1004) rather than rejecting —
  pre-existing; runtime `ContextRoleState::new` still rejects, so not a gap, not opened here.

**Drift guard verified:** `builtin_capabilities_list_is_exhaustive` (roles.rs:4091) uses
a compile-error-forcing exhaustive match + asserts len==18; a round-trip test asserts
every built-in's UCAN form re-parses via `Capability::new` back to its variant. So
`Capability::new`/`BUILTIN_CAPABILITIES` cannot silently under-cover the enum.

No tests deleted (PR is additive on tests + a cosmetic early-return refactor of
`validate_custom_ceiling_entry`). 85 ceiling tests pass. Branch fresh (27c1849c9 ancestor;
diff = exactly roles.rs + 3 spec/ADR files). No leftover old-mechanism text in .docs/ or code.
