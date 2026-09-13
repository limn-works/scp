# A Cache Step That Never Restores Is Not a Cache

**Problem**: `.github/workflows/ci.yml` carried eighteen `Swatinem/rust-cache` steps, and
pull-request runs of the same branch took between 18.5 and 33.6 minutes with nothing else
different. The variance was the cache: on run 34711741563 all four of the long jobs printed
`No cache found`, on run 34750056435 three of the four printed
`Restored from cache key … full match: true`, and on run 34731762140 two hit while two
missed inside one run. A hit took `Rust / test (macos-latest)` from 33.0 minutes to 15.3,
`Cross-bridge runtime parity (UniFFI Swift)` from 30.9 to 17.9, and `Swift / build + test`
from 22.2 to 12.2. Nobody had written a broken cache step. Eighteen correct ones, on one
repository, evicted each other.

## Rules

- **Count the entries a workflow writes against the 10 GB a repository gets.**
  `Swatinem/rust-cache` defaults `add-job-id-key` to true, so each step writes its own
  entry holding its own copy of the same compiled dependencies. Measured on 2026-09-13,
  this repository held 26 entries totalling 13.4 GB against a 10 GB cap, so GitHub was
  evicting least-recently-used entries faster than the runs wrote them, and a job's hit or
  miss depended on which eviction had run last. `gh api repos/<owner>/<repo>/actions/cache/usage`
  prints the total and `gh api "repos/<owner>/<repo>/actions/caches?per_page=100"` lists
  every entry with its ref, its size, and when something last read it.
- **A cache entry is readable from the ref that wrote it and from the default branch, and
  from nowhere else.** A write on `refs/pull/N/merge` or on
  `refs/heads/gh-readonly-queue/…` buys its own run nothing — the compile already happened
  — and it evicts an entry some later run needed. Restricting writes to a push to `main`,
  through `save-if: ${{ github.ref == 'refs/heads/main' }}`, is what lets a pull request
  hit on its FIRST run rather than on its second. Before that restriction, every one of
  the repository's 21 sized Rust entries sat on a pull-request ref or a merge-queue ref and
  not one sat on `refs/heads/main`.
- **Name the group by what a job writes, not by what a job is called.** Jobs that compile
  the same crate graph into the same target directory share one entry through
  `shared-key`, and the action already appends the runner OS and architecture, so a group
  name never spells either out. Two jobs whose cargo commands differ only in `--release`
  write two directories and need two groups: cargo shares no artifact between
  `target/debug` and `target/release`, nor between `target/release` and
  `target/<triple>/release`.
- **In a shared group, name the producer and silence every other member.** The first job
  to reach its post step uploads, and every later job with that key is told the entry
  already exists. Left alone, the group's contents are decided by whichever member
  finishes first — which here would have been `shipped-feature-graph`, a job that resolves
  a feature graph, compiles almost nothing, and finishes eleven minutes before the job
  whose artifacts the group exists to carry. Give the producer the `save-if` and give
  every other member `save-if: false`.
- **Leave `cache-workspace-crates` false.** A checkout writes every source file with the
  checkout's own mtime, newer than any cached artifact, so cargo rebuilds each workspace
  crate whatever the entry holds. Turning it on adds about a gigabyte that never produces
  a hit, against the same 10 GB budget.
- **A cache decides how long a job takes and never what it reports.** Cargo compares
  fingerprints against every restored artifact and recompiles what does not match, so a
  group named wrong costs a miss and cannot cost a wrong result. That is what makes this
  class of change safe to make in one pass, and it is also why nobody notices when it
  silently stops working.

## See also

- `.docs/lessons/route-a-changed-file-to-every-lane-it-decides.md` — the other way this
  workflow's speed and its correctness trade against each other.
- `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md` — the pin whose
  environment hash is part of every cache key here.
