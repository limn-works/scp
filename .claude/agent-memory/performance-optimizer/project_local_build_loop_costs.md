---
name: local-build-loop-costs
description: Measured costs of the scp-runtime edit-build-lint loop on Alec's 16-core Mac (2026-11-02), what dominates, which levers cannot pay, and the dev-dependency traps that put crates on the critical path
metadata:
  type: project
---

Measured 2026-11-02, Rust 1.98.0, Apple ld-prime, under load from other agents' builds (load average 17-110). Full write-up: `~/.claude/plans/local-speed-2026-11.md`.

- The scp-runtime lib-test unit (256k lines in one crate) dominates every scp-runtime loop. With `-Ztime-passes`, a one-line edit costs 65.7 s: macro expansion 9.8 s (not incremental), mono collection and partitioning 9.4 s, codegen 22.9 s plus 7.7 s finishing, dep-graph serialization 5.4 s, link 3.2 s. A cold build costs 461 s, of which borrowck is 219 s.
- The linker takes about 3 s of that, so lld, mold and other linker levers cannot pay. Do not re-measure them.
- Any dev-dependency edge that reaches back to scp-runtime makes the lib-test unit wait until scp-runtime's lib, and every crate on that edge, has compiled. Cargo runs no unit of a target before all of its dev-dependencies. A self dev-dependency (`scp-runtime = { path = ".", features = ["testing"] }`) still costs one non-test build of the lib before the lib test starts: 12-18 s for `cargo test --lib`, and in the hook's clippy the whole lib check (110-226 s), because clippy re-lints the lib on every run.
- The self dev-dependency is still required. `scripts/check-examples-compile.sh` (CI rust-clippy) runs `cargo clippy -p scp-runtime --example NAME` without features, and the examples declare `required-features = ["testing"]`. Removing every edge that turns on `scp-runtime/testing` fails that gate. The examples need scp-runtime's own feature because they call `ProtocolRepository::new_for_testing`, which sits behind `allow_unencrypted_storage`. The scp-dht and scp-platform `testing` features already reach them through dev-dependencies. So rewriting the examples onto encrypted storage, then dropping `required-features` and the self-edge, removes the serialization.
- With `--timings`, the hook's clippy for a scp-runtime edit runs at the length of the chain scp-runtime check, scp-transport, scp-node, scp-ffi-common, then the scp-ffi-uniffi and scp-ffi-napi check-test units. Clippy's late lint passes re-run over the whole crate on every build: after a one-line edit, scp-runtime's check-test unit alone takes 80-177 s.
- The session scratchpad is shared by every agent in the session. Generic names such as `commit-msg.txt` get overwritten between a write and `git commit -F`, so use a file name that only you would choose.

**Why:** Alec wants each loop step at its physical floor. These facts decide which levers can pay.
**How to apply:** Reject linker and dev-profile debuginfo levers outright. Look for crate-graph edges on the critical path first, and the size of the crate being edited second.
