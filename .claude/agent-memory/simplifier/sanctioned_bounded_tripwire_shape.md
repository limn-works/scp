---
name: sanctioned-bounded-tripwire-shape
description: The codebase's SANCTIONED answer to the non-convergent-enforcement BLOCKER charge — a private-field newtype with a closed constructor set + a count-pinning positive-allowlist tripwire test. Recognize it; do NOT flag it.
metadata:
  type: feedback
---

When judging whether an enforcement mechanism is the non-convergent-denylist
BLOCKER (per CLAUDE.md's over-engineering guard), this codebase has an
established GOOD shape that is the opposite of the anti-pattern. Do not flag it.

**The sanctioned shape** (two anchors, both in `crates/scp-runtime/src/context/`):
- `actor/class_s.rs` — `ClassSCell` + test `class_s_no_persist_mutator_whitelist_is_bounded`.
- `ttl_close_helpers.rs` — `ConvergentDeadline` newtype + test `convergent_deadline_constructor_allowlist_is_bounded`.

Recognize it by these traits:
1. A newtype with a PRIVATE field, no `from_raw`, no `Deserialize`/serde derive — so Rust module privacy makes the constructor set CLOSED BY CONSTRUCTION (a raw scalar/bytes can never be minted into the trusted type).
2. A small, fixed set of sanctioned constructors (e.g. 3), each a real function.
3. A test that pins the constructor COUNT with a `const SANCTIONED_* = N` and calls all N live constructors. Bumping N forces a deliberate, reviewed edit.

**Why it is NOT the BLOCKER anti-pattern:** it is a positive whitelist / change-detector layered ON TOP of a compile-time (privacy) guarantee — a tripwire, NOT a source-text/AST denylist scanning for forbidden spellings, and NOT a redundant re-check of the type property (the test can't and doesn't re-verify privacy; it detects set-growth). Cost is tiny (~1 struct + 2 methods + ~30-line test) vs the security property it guards. This is the CORRECT bounded shape — affirm it, don't nitpick.

Contrast with the BLOCKER: an ever-growing denylist enumerating forbidden cases, added to across revisions, never closing. See [[commit12-helpers-logic-split-rule]] context and `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`.
