# A local `cargo deny` run sees fewer advisories than CI does

**The rule:** never delete an entry from `deny.toml`'s `[advisories] ignore` list because a
local `cargo deny check` called it `advisory-not-detected`. Delete an entry only when you
can name the crate that carried the advisory and show that the crate has left the
dependency graph.

## What happened

Pull request #2460, the cold-compile dependency cut, removed three dependency edges and
with them 46 crates, including every crate under `openmls_libcrux_crypto`. Six advisory
ignores in `deny.toml` named those crates, so they could go. A local
`cargo deny check advisories` confirmed that, and reported a seventh entry as unused in the
same breath:

```
warning[advisory-not-detected]: advisory was not encountered
   ┌─ deny.toml:66:6
   │
66 │     "RUSTSEC-2026-0097",
   │      ━━━━━━━━━━━━━━━━━ no crate matched advisory criteria
```

That seventh entry covers `rand` 0.8.5, which the change did not touch. The same run
against the unmodified tree reported the same warning, which established that the entry was
already unused before the change rather than made unused by it. The entry came out along
with the six.

`Rust / deny` then failed on the pull request:

```
error[unsound]: Rand is unsound with a custom logger using `rand::rng()`
    ├ Advisory: https://rustsec.org/advisories/RUSTSEC-2026-0097
advisories FAILED, bans ok, licenses ok, sources ok
```

## Why the two runs disagree

The local run used cargo-deny 0.19.0 from the mise shim. The CI job runs
`EmbarkStudios/cargo-deny-action@v2`, which installs its own cargo-deny and fetches its own
copy of the RustSec advisory database. Two things differ between the runs and either one
alone produces the disagreement: the two cargo-deny releases classify an advisory carrying
`informational = "unsound"` differently, and the two advisory databases are fetched at
different times. RUSTSEC-2026-0097 is an `unsound` advisory, and it is the class the local
run passed over.

The failure mode is asymmetric. A local run that reports an advisory the CI run does not
costs a developer one unnecessary ignore. A local run that passes over an advisory the CI
run reports costs a red merge gate, and it reads as a clean local result right up to the
push.

## What to do instead

- Treat `cargo deny check` on a developer machine as a lower bound on what CI reports.
- Remove an ignore only with a positive argument: name the crate the advisory covers, and
  show with `cargo tree -i <crate>` that nothing reaches it any more. The six libcrux
  entries met that test, and CI's run confirmed it by reporting none of them.
- When an ignore survives for a reason a reader could mistake for staleness, write the
  reason into the entry's comment, including that a local run under-reports it.
