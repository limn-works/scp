# Compare a Compile-Time Change by Summed Unit-Seconds, Not by Wall Clock

**The rule:** to measure whether a change made the Rust build faster, compare the
`summed unit time` of two `cargo build --timings` reports and attribute the difference to
named units. A GitHub-hosted `ubuntu-latest` runner varies enough to swamp any real change:
per-unit durations moved by up to 45% between runs on identical source, and summed unit time
by about 25% when the runner differed. One run of a tree with 39 packages removed read as a
23% win only because it landed on a faster runner.

## What to report, most trustworthy first

1. **Unit and package count.** `cargo tree --workspace --target <triple> --edges
   normal,build,dev --features <the CI list> --prefix none` is deterministic and matches the
   CI log's `Compiling` lines.
2. **Attributed unit-seconds.** From one pre-change report, sum the durations of exactly the
   packages the change removes and divide by the total. No runner comparison enters it.
3. **Wall time**, as a median over at least three runs per side, with the range.

`.github/workflows/compile-timings.yml` builds the workspace test target cold and uploads the
timings reports. The build is core-bound (mean parallelism 3.78 of 4 cores, wall time about
6% above `summed unit time / 4`), so removing dependency work cuts wall time in proportion
and reordering the graph cuts nothing.

## A cargo fact the reports established

Matching a crate's feature sets between `[build-dependencies]` and normal dependencies does
not make cargo build it once. Cargo keys a unit by compile kind as well, so a host unit and a
target unit stay distinct even when the triple and the features agree: `uniffi_bindgen` and
`goblin` both still compiled twice with identical features on both sides.
