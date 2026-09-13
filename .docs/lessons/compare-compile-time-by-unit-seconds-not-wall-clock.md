# Compare a compile-time change by summed unit-seconds, not by wall clock

**The rule:** when you measure whether a change made the Rust build faster, compare the
`summed unit time` two `cargo build --timings` reports give, and attribute the difference
to named units. Do not compare the two runs' wall-clock times and report the difference as
your change's effect. A GitHub-hosted `ubuntu-latest` runner varies enough to swamp any
change worth making.

## The evidence

`.github/workflows/compile-timings.yml` builds the workspace test target cold, with no
cache step, and uploads `cargo build --timings` reports. Four runs, all of the same job on
`ubuntu-latest`, measuring three trees:

| run | tree | packages | units | wall | summed unit time |
|---|---|---|---|---|---|
| 34762016253 | before | 550 | 891 | 392.9 s | 1484.7 s |
| 34763096677 | before | 550 | 891 | 392.8 s | 1487.4 s |
| 34763099801 | before | 550 | 891 | 400.7 s | 1523.7 s |
| 34762550890 | 39 packages removed | 511 | 835 | 303.2 s | 1143.1 s |

The fourth row reads as a 23% win. It is not one. It landed on a faster runner: on that run
`scp-runtime`'s lib-test unit took 63.6 s against 116.2 s on the first, and that crate's
source is identical in both trees. A later run of a tree with even fewer packages reported
1403.2 unit-seconds — more than the 1143.1 the fourth row shows, from strictly less work.

Per-unit durations move by as much as 45% between runs on identical source. Summed unit
time over ~890 units moves by about 3% between comparable runners and by about 25% when the
runner differs. Unit *count* does not move at all.

## What to report instead

Three figures, in descending order of how much they can be trusted:

1. **Unit and package count.** `cargo tree --workspace --target <triple> --edges
   normal,build,dev --features <the CI list> --prefix none` counts exactly what the CI log's
   `Compiling` lines count, and it is deterministic. On the tree above it printed 550, and
   the CI log printed 550 `Compiling` lines.
2. **Attributed unit-seconds.** Take the pre-change report, sum the durations of exactly the
   packages the change removes, and divide by the report's total. For the 46 packages
   pull request #2460 removes that is 95.0 of 1484.7, or 6.4%, over 60 of 891 units. This number comes from one run, so no
   runner comparison enters it.
3. **Wall time, with the sample count and the spread.** Report it as a median over at least
   three runs per side and name the range.

## Why wall time is predictable once you have unit-seconds

Every run of this job reports the same structure: mean parallelism 3.78 of 4 cores, wall
time 6% above `summed unit time / 4`, and under 2 s of the whole build with no unit ready to
start. The build is core-bound rather than graph-bound, so wall time follows unit-seconds
and follows nothing else. `903.9 / 4 × 1.06 = 240 s` predicted the 4 min 16 s warm compile
that run 34721754678 measured, within 7%.

That relationship also says which levers exist. Removing dependency work cuts wall time in
proportion to the unit-seconds removed. Reordering the dependency graph cuts nothing,
because the graph is already keeping 3.78 of 4 cores busy.

## A worked case: a change the reports rejected

`uniffi_bindgen` compiled twice on the pre-change tree, for 25.5 s and 28.4 s, and the two
units carried different feature sets — `[]` on the host side, where `uniffi_build` declares
the crate with `default-features = false`, and `["cargo-metadata", "default"]` on the target
side, where scp-ffi-uniffi's `uniffi` dependency reaches it through `cli -> bindgen`.
Cargo's documentation says a package shared between a build dependency and a normal
dependency is built twice when the features differ, which reads as a promise that matching
them makes cargo build it once.

Naming `uniffi_bindgen` in `[build-dependencies]` with default features on did make the two
sets match: run 34763516577 shows both units at `['cargo-metadata', 'default']`. Cargo
compiled it twice anyway, 22.4 s and 22.2 s, and the run's unit count stayed at 824 — the
same count as the run before the change. `goblin` repeated the result: identical features on
both sides, two units.

Matching the feature sets is necessary for sharing and it is not sufficient. Cargo keys a
unit by its compile kind as well, and a host unit and a target unit stay distinct even when
the triple and the features agree. The change was reverted. Had it been judged on the wall
clock it would have looked like a 63-second win, because run 34763516577 landed on a faster
runner than the one before it.
