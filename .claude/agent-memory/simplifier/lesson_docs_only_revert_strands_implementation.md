---
name: docs-only-revert-strands-implementation
description: A spec revert is only complete if the code, FFI surface, and enforcement files that implement the deleted spec are deleted in the same change — otherwise it strands a live implementation.
metadata:
  type: feedback
---

Deleting fabricated/wrong spec content is not done when the spec file is clean. Before approving a
spec-deletion PR, grep the repo for the deleted symbols/section numbers. If code, FFI exports,
`sdk-capability-matrix.json` entries, or `pipeline_wiring.rs` assertions still implement the deleted
text, the PR **inverts** the artifact flow: the spec now forbids what shipped code asserts, and the
enforcement files are stranded asserting a requirement the spec denies.

**Why:** PR #2275 deleted spec §8.4.1/§8.4.2 (app-as-protocol-entity) and `EventType::AppBound/AppUnbound`
from ADR phase-2, but left ~2.7k lines of `crates/scp-runtime/src/context/app_sandbox.rs`, tags 74/75 in
`scp-event-log/src/tree.rs`, 64 `app_bind`/`bind_app` sites across bridges+SDKs, two capability-matrix
rows, and live `pipeline_wiring.rs` assertions citing the now-negated sections. Section numbers were also
*reused* (`§8.4.1`) for content negating the old `§8.4.1`, so every code comment citing `§8.4.1` silently
flipped meaning.

**How to apply:** On any spec/ADR deletion review, run `grep -rn "<DeletedSymbol>\|§<deleted.section>"`
across `crates/`, `bindings/`, `.docs/standards/`, and enforcement scripts. Non-zero hits outside the PR
diff = BLOCKER. Also: never reuse a section number for content that negates it — retire the number.
Related: [[commit12-helpers-logic-split]].
