# Backend Agent Memory

- [Durable leaf timestamp sourcing](durable_leaf_timestamp_sourcing.md) — each durable event-log leaf takes a convergent timestamp, never `now()`; the per-class rules and the `preserve_order` coupling.
- [Browser client transport facts](browser_client_transport_facts.md) — openmls stores the Ed25519 seed behind a test-only accessor, the relay echoes a publish to its publisher, native subscribes without backfill, and wasm-bindgen error values panic on the host.
- [scp-node live slot](project_liveslot_collapse_scp_node.md) — one `LiveSlot<NodePublishedState>`; three design points that look wrong when re-derived.
- [Attestation revocation list gets a writer](project_attestation_revocation_writer_2335.md) — Alec chose a writer on the verify-on-ingest path over a fail-closed checker ("Do NOT re-litigate that choice"); the step order that keeps the writer sound.
- [cargo-deny reports only the highest duplicate](finding_cargo_deny_highest_version_only.md) — a dependency bump can turn the gate green while unpatched copies still ship; check every copy in `Cargo.lock`.

## Build and tool traps
- `clippy::too_many_lines` counts only code lines, so deleting comments from a function at the limit changes nothing; remove or fold code lines.
- A compile-fail test uses a rustdoc ```` ```compile_fail,E0277 ```` block (the repository's convention; do not add trybuild). Pin the error code, since a bare `compile_fail` passes on a typo, and pair it with a positive control. Put the control in an integration test too, because `cargo nextest` does not run doctests; only `cargo test --doc` does.
- In a worktree, Edit once reported success without changing the file on disk while Read showed the edit. Before concluding that a change landed or that work is already done, confirm the load-bearing lines with `grep -n` and `git diff`.
- The environment snapshot in a task prompt can name a commit the worktree's live HEAD does not have. Run `git rev-parse HEAD` before branching from a pinned base.
