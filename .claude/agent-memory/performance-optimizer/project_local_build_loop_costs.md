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
- scp-runtime now has no dev-dependency edge back to itself. Its examples need no scp-runtime feature: they store through `ProtocolRepository::new` over an `EncryptingAdapter`, and `messaging` mints a real KeyPackage. Every scp-runtime test command therefore names `--features testing`, and `src/lib.rs`'s `compile_error!` says so when one does not. Do not re-add an edge to make a bare `-p scp-runtime` command work. Measured after removal: the lib test starts at 1-3 s rather than 13-18 s, and the hook's clippy took 199-318 s against 307-498 s, because the lib check-test now runs beside the lib check rather than after it.
- `scripts/check-examples-compile.sh` only compiles examples. `messaging` compiles and fails at its first send with `PseudonymRegistryEmpty`, under any feature set (#3204). Run an example before claiming anything about its behavior.
- With `--timings`, the hook's clippy for a scp-runtime edit runs at the length of the chain scp-runtime check, scp-transport, scp-node, scp-ffi-common, then the scp-ffi-uniffi and scp-ffi-napi check-test units. Clippy's late lint passes re-run over the whole crate on every build: after a one-line edit, scp-runtime's check-test unit alone takes 80-177 s.
- A local bridge build for tests uses `--profile ci-bridge`, which is what CI tests, never `--release`. `[profile.ci-bridge]` sets `incremental = true`, and CI's `CARGO_INCREMENTAL=0` overrides it. The napi addon rebuild after a one-line scp-runtime edit took 745 s under release, 269 s under non-incremental ci-bridge, and 72-79 s under incremental ci-bridge. Release and its descendants compile non-incrementally unless a profile says otherwise.
- Tests that are slow at the default dev opt-level usually spend their time in dependency crypto (Argon2 passphrase tests take 18-34 s each, and the protocol oracle tests 180 s). `[profile.dev.package."*"] opt-level = 1` cut the scp-protocol suite's run from 117 s to 43 s and doubled the CPU of a cold dependency build.
- The session scratchpad is shared by every agent in the session. Generic names such as `commit-msg.txt` get overwritten between a write and `git commit -F`, so use a file name that only you would choose.

**Why:** Alec wants each loop step at its physical floor. These facts decide which levers can pay.
**How to apply:** Reject linker and dev-profile debuginfo levers outright. Look for crate-graph edges on the critical path first, and the size of the crate being edited second.
