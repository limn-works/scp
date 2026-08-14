---
name: ceiling-builtin-collision-5311
description: §5.3.1.1 no-privileged-built-in-collision converged onto ONE mechanism (canonical re-resolution in validate_as_ceiling_entry); redundant projection test deleted
metadata:
  type: project
---

PR #1894 (branch `fix/ceiling-builtin-collision-validator`, merge-base off origin/main) consolidated spec §5.3.1.1 "No privileged-built-in collision" enforcement in `crates/scp-protocol/src/context/roles.rs` onto a SINGLE mechanism.

The enforcement: `Capability::validate_as_ceiling_entry`'s `Custom(name)` arm does `if !matches!(Self::new(name), Self::Custom(_)) { reject }` — re-resolve the custom string through the single canonical parser `Capability::new`; if it resolves to any non-`Custom` variant, the string names a built-in (in colon OR UCAN spelling, including parameterized `tool_invoke:{id}`) and is rejected. Closed by construction: `Capability::new` is the sole authority on what is a built-in, so the rule covers every spelling and extends to new built-ins automatically — NOT a denylist.

History (2 commits): commit 1 (`cd3eef157`) added BOTH the re-resolution guard AND a redundant `BUILTIN_CAPABILITIES.iter().any(|c| c.ucan_capability_name() == entry)` projection-membership test INSIDE the shared grammar core `validate_custom_ceiling_entry`. Commit 2 (`cb060675b`) DELETED that projection test (+ its 2 dedicated tests), leaving `validate_custom_ceiling_entry` as pure grammar.

Why the projection test was redundant (weaker, not defense-in-depth): canonical re-resolution strictly subsumes projection-membership. Any string whose UCAN projection equals a built-in's UCAN form ALSO resolves via `Capability::new` to that built-in. Re-resolution additionally catches colon-spelling built-ins (`tool:invoke:*`) that projection-on-a-`Custom` would miss. So the projection check could not reject anything re-resolution doesn't already reject → negative value.

`validate_ucan_ceiling_string` rule 1 (the `BUILTIN_CAPABILITIES...any(ucan==entry)` early-return) is a DIFFERENT, still-needed mechanism: it ACCEPTS legit built-in UCAN forms on the import path (which stores raw strings verbatim, no `Custom` wrapper → no collision surface). Not redundant with the collision guard.

Chokepoint is universal: `CapabilityCeiling` uses `#[serde(try_from)]` → `validate_entries()` → `validate_as_ceiling_entry()` per cap, so deserialized untrusted `Custom` values cannot bypass. All 4 bridges + runtime route through `validate_as_ceiling_entry`.

NOTE: the "deleted redundant test" was an intra-branch WIP artifact, never on main. Net PR-vs-main effect = closes a real masquerade gap (main had NO collision guard) + this consolidation. See [[commit12-helpers-logic-split]] for the helpers/logic split convention in the same area.
