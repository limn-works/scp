# The shared target directory has one lock, and 1.4 million files

Every git worktree on the machine that builds this repository compiles into one directory,
`/Users/alec/.cargo/shared-target`, because `~/.cargo/config.toml` sets `build.target-dir`
to it. Alec ruled on 2026-08-30 that agents use that directory rather than a private one,
verbatim: **"this is the reason we have a shared build target, dummy."** That ruling
stands. This file records what the directory costs a fix round as of 2026-09-13, so a
later reader can tell a slow compile from a queue.

## What a fix round's wall time went to

One `cargo check -p scp-protocol --all-targets`, run in a worktree created that morning,
took **29 minutes 40 seconds**. Cargo's own `--timings` report decomposes it:

| term | measured |
|---|---|
| waiting for the build lock | 23 min 16 s |
| compiling four crates | 6 min 24 s |
| executing build scripts | 0.00 s, for all 24 of them |

The first unit started at t=1395.7 s in the timing report. An independent `lsof` poll on
`debug/.cargo-lock` recorded the lock passing to that cargo at 23 minutes 18 seconds after
it started, so the two measurements agree to within two seconds.

Cargo prints one line when this happens: `Blocking waiting for file lock on build
directory`. A run that prints it and then sits is queued, not compiling.

## The same command, run again against a cache that needed nothing: 28 minutes 27 seconds

Immediately after the run above finished, the identical `cargo check -p scp-protocol
--all-targets` ran again in the same worktree, against artifacts it had just written.
Cargo printed no `Checking` line at all, only `Finished … in 28m 27s`. Every second of that
was queued behind another worktree's `cargo check -p scp-node --tests`.

Two further attempts to time a run measured the same thing: one died on a 900-second bound
having never acquired the lock, and one was killed after 22 minutes still waiting.

When the lock is free, the whole local check is fast. Measured the same day with nothing
else compiling, `bash scripts/fix-round-check.sh scp-protocol` took 49 seconds end to end:
under a second for the toolchain comparison, 0 seconds for a `cargo check` against warm
artifacts, 3 seconds for `cargo fmt --all -- --check`, and 46 seconds for the 28 gates the
runner's list held that day. The
same script with no argument took 50 seconds. So the queue, not the work, is what a fix
round waits on.

## Who held the lock

The lock's holder was another agent's `cargo check -p scp-protocol -p scp-node --tests`,
which had held it for 42 minutes. Its three `rustc` children retired **zero instructions,
used zero CPU nanoseconds, and moved zero bytes of disk** across two separate 20-second
`proc_pid_rusage` samples; every thread sat in state `S`. That build was stopped, not slow,
and the syscall it stopped in went unidentified. Three cargo processes were queued behind
it: one waiting 30 minutes, one waiting 17 minutes, and a `scripts/check-pure-helpers.sh`
run that printed the blocking line and died on a 300-second timeout.

Killing the wedged cargo drained the queue in four seconds.

## The compile that follows the wait is also slow, and source size does not explain it

The six units cargo actually compiled, with the crate's own line count:

| unit | lines of Rust in `src/` | `cargo check` |
|---|---|---|
| scp-crypto lib | 436 | 83.6 s |
| scp-did lib | 4,695 | 84.3 s |
| scp-event-log lib | 11,630 | 55.7 s |
| scp-protocol lib | 144,821 | 193.7 s |
| scp-protocol test-lib | 144,821 | 197.5 s |
| scp-protocol hpke_oracle test | — | 50.4 s |

A 436-line crate took 83.6 seconds to type-check while an 11,630-line crate took 55.7
seconds, so the cost is a fixed charge per unit rather than work proportional to the
source.

## Where that fixed charge comes from: one `stat` costs 2.7 milliseconds

`debug/deps` holds **1,381,573 entries** and 336 GB. `debug/incremental` holds another
227 GB. The whole directory is 575 GB.

A single `os.stat` in `debug/deps`, measured against freshly written directories of known
size on the same volume:

| directory | entries | µs per `stat` |
|---|---|---|
| scratch | 1,000 | 2.0 |
| scratch | 10,000 | 2.0 |
| scratch | 100,000 | 2.0 |
| scratch | 400,000 | 59.0 |
| `debug/deps` | 1,381,573 | 2,713 |

The last row used 20,000 distinct names, each looked up once, which is the access pattern a
compile produces. Repeating the same 20 lookups 2,000 times each drove the cost down over
four rounds — 2,000 µs, 1,201 µs, 581 µs, 215 µs — and never reached the 2 µs a small
directory answers with, so residency explains part of the cost and directory size explains
the rest. A full `stat` pass over `debug/deps` takes about an hour at that rate, which is
what two such passes measured before they were killed at 27 and 42 minutes.

## Why the directory holds 1.4 million files

**978,452 of the 1,381,573 entries, 70.8%, are artifacts of this workspace's own 26
crates.** Registry dependencies account for the other 29%.

Cargo hashes a package's absolute path into the `-C metadata` value it passes to rustc, so
the same crate compiled from two worktrees produces two sets of artifacts that never share.
`git worktree list` named 538 worktrees on the measurement date, 497 of them directories
under `.claude/worktrees/`. Counting the dep-info files cargo wrote and reading the source
path out of each one gives a lower bound on how many worktrees each crate has been compiled
from:

| crate | dep-info files | distinct source worktrees | still on disk |
|---|---|---|---|
| `scp_protocol` | 260 | 17 | 16 |
| `scp_runtime` | 288 | 35 | 34 |
| `scp_core` | 326 | 16 | 15 |

Two other multipliers sit under those numbers and are much smaller. Reading every
fingerprint JSON for those three packages found **three distinct rustc versions** (the
1.98.0 pin, the `stable` channel at 1.97.1, and one more) and **two to six distinct feature
sets** per package — 2 for `scp_protocol`, 6 for `scp_runtime`, 5 for `scp_core`. Three
compilers times six feature sets is 18 combinations, against 89 to 131 `.rlib` variants per
crate, so neither the compiler nor the feature set explains the count. The worktree path
does.

The directory also holds artifacts for `scp_personal_relay`, `scp_primitives`,
`scp_rust_client`, `scp_relay_scaffold`, and `scp_cross_context_bridge` — five crates the
workspace no longer contains. Cargo never removes them.

## An editor is in the queue too, on a different project and a different compiler

`~/.cargo/config.toml` belongs to the user, not to this repository, so its
`build.target-dir` sends **every** Rust project this user builds into the same directory.
At 10:29 on 2026-09-13, `lsof` on `debug/.cargo-build-lock` named three holders. One was an
SCP agent's `cargo check -p scp-node --tests`. One was this investigation's own check. The
third was

    /Users/alec/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo check --workspace
      --message-format=json --manifest-path /Users/alec/Developer/nodes/ctx.network/Cargo.toml
      --keep-going --all-targets

started by Zed's `rust-analyzer` (its flycheck writes `shared-target/flycheck0`). That
command compiles a different repository, on the `stable` channel, which resolves to 1.97.1
rather than the 1.98.0 this repository pins, and it re-runs whenever the editor's flycheck
fires. It queues on the same lock as every agent, and its artifacts land in the same
directory and in a third hash space.

So the answer to "who is holding the lock" is not always an agent, and a queue that does not
drain is not evidence that an agent misbehaved.

## Two cargo subcommands that look free and are not

`cargo metadata --no-deps --offline` measured 68, 68, and 72 ms three times in a row, and
two and a half minutes once while another worktree's `cargo check` ran. `cargo fmt --all --
--check` measured 2.83 seconds alone and sat for more than three and a half minutes under
the same concurrency, because `cargo fmt` resolves the workspace through a full
`cargo metadata` first. Neither compiles anything. Treat a stalled `cargo fmt` or
`cargo metadata` as the same queue rather than as a broken toolchain.

## Within one worktree the cache stays warm across branches

Cargo's `-C metadata` hash reads the package name, its version, the absolute path of its
source, the selected features, the profile, and the compiler. A branch changes none of
those, so two branches checked out in turn into one worktree address the same artifacts,
and cargo recompiles a crate only where the branch changed that crate's source.

Worked against `fix/bridge-handlers-honor-auth-scope`, the branch of pull request #2373,
bridge handlers honouring the authorization scope: its diff changes six files in
`crates/scp-protocol/` and no file in `crates/scp-clock/`, `crates/scp-crypto/`,
`crates/scp-did/`, or `crates/scp-event-log/`, and its `Cargo.lock` differs by one line, an
`async-trait` entry in `scp-node`'s dependency list. So `cargo check -p scp-protocol
--all-targets` on that branch recompiles the three `scp_protocol` units and reuses its four
workspace dependencies and every registry dependency. Switching back recompiles the same
three units in the other direction.

That claim is read off the diff and off cargo's hash inputs. Three attempts to time the run
itself each died in the queue described above, so no wall time here measures it.

## What this means for a check run before a push

Run one cargo command and let it finish. A second cargo command started beside it does not
run in parallel; it takes a number and waits. `scripts/fix-round-check.sh` exists so a fix
round runs exactly one, scoped to the crates it edited, and leaves the workspace clippy run
and the workspace nextest run to the `rust-clippy` and `rust-test` jobs of
`.github/workflows/ci.yml`.

`cargo clean -p <crate>` on one crate remains the remedy for an artifact that does not match
its source. Wiping the directory, or opting out of it with `CARGO_TARGET_DIR`, is what
Alec's 2026-08-30 ruling forbids.

## What a reader should not conclude from this file

The macOS Gatekeeper assessment lane is a separate cost with its own record in
`.docs/lessons/` and in session memory, and it was **not** what these measurements found.
Measured the same day on the same machine: a freshly compiled 16 KB binary's first exec
cost 203 ms from queue to scan finished, and its second exec produced no assessment at all
and took 5.5 ms. That is small. On 2026-09-11 the same queue reached 31 minutes per item
and killed a fix round, so the cost varies by orders of magnitude between days and has to
be measured rather than assumed.

Apple ships no supported per-path exclusion for either Gatekeeper exec assessment or
XProtect. The `SystemPolicyControl` payload carries `EnableAssessment`,
`AllowIdentifiedDevelopers`, and `EnableXProtectMalwareUpload` and names no path; the
`SystemPolicyRule` payload matches a code-signing requirement, and Apple's requirement
language states that for ad-hoc-signed code "there are no certificates at all and all
certificate constraints evaluate to false". Path and folder exclusions are a third-party
antivirus feature, not an Apple one.
