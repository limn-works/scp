# Backend Agent Memory

- [Durable leaf timestamp sourcing](durable_leaf_timestamp_sourcing.md) — each durable event-log leaf takes a convergent timestamp, never `now()`; the per-class rules and the `preserve_order` coupling.
- [scp-node live slot](project_liveslot_collapse_scp_node.md) — one `LiveSlot<NodePublishedState>`; three design points that look wrong when re-derived.
- [Attestation revocation list gets a writer](project_attestation_revocation_writer_2335.md) — writer on verify-on-ingest, not a fail-closed checker (an agent chose it, not Alec); the step order that keeps it sound.
- [cargo-deny reports only the highest duplicate](finding_cargo_deny_highest_version_only.md) — a dependency bump can turn the gate green while unpatched copies still ship; check every copy in `Cargo.lock`.

## Build and tool traps
- `clippy::too_many_lines` counts only code lines, so deleting comments from a function at the limit changes nothing; remove or fold code lines.
- A compile-fail test uses a rustdoc ```` ```compile_fail,E0277 ```` block (the repository's convention; do not add trybuild). Pin the error code, since a bare `compile_fail` passes on a typo, and pair it with a positive control. Put the control in an integration test too, because `cargo nextest` does not run doctests; only `cargo test --doc` does.
- In a worktree, Edit once reported success without changing the file on disk while Read showed the edit. Before concluding that a change landed or that work is already done, confirm the load-bearing lines with `grep -n` and `git diff`.
- A per-thread tracing log capture needs `filter::dynamic_filter_fn`, not `filter_fn`: `filter_fn` caches its first answer as the callsite interest (`always`/`never`), so a callsite first hit on a non-capturing test thread stays muted everywhere and the capture passes or fails by test order.
