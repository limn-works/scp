# A Cache Step That Never Restores Is Not a Cache

Pull-request runs of one branch took between 18.5 and 33.6 minutes with nothing else
different, because eighteen `Swatinem/rust-cache` steps evicted each other. A cache hit took
`Rust / test (macos-latest)` from 33.0 minutes to 15.3.

## Rules

- **Count every entry every workflow writes against the 10 GB per-repository cap.**
  `Swatinem/rust-cache` defaults `add-job-id-key` to true, so each step writes its own copy
  of the same dependencies. On 2026-09-13 the repository held 13.4 GB, so eviction ran faster
  than the writes. `gh api repos/<owner>/<repo>/actions/cache/usage` prints the total and
  `gh api "repos/<owner>/<repo>/actions/caches?per_page=100"` lists each entry.
  `scripts/check-workflow-compile-steps.py` counts cache groups across every workflow file,
  including `fuzz.yml`, whose scheduled runs write on `refs/heads/main`.
- **Write the cache only from a push to `main`**, with
  `save-if: ${{ github.ref == 'refs/heads/main' }}`. An entry is readable only from the ref
  that wrote it and from the default branch, so a write on a pull-request or merge-queue ref
  buys nothing and evicts an entry a later run needed.
- **Name a cache group by what the job writes.** Jobs share an entry through `shared-key`
  only when they compile the same crate graph into the same target directory under the same
  compile mode. `target/debug`, `target/release`, and `target/<triple>/release` share
  nothing, and check mode (`cargo clippy`, `cargo doc`) produces `.rmeta` artifacts under
  different fingerprint names from build mode (`cargo build`, `cargo nextest`). A job that
  runs both modes restores both groups.
- **In a shared group, give the producer `save-if` and every other member
  `save-if: false`.** Otherwise whichever member finishes first, often one that compiles
  almost nothing, decides the entry's contents.
- **Leave `cache-workspace-crates` false.** A checkout's fresh mtimes make cargo rebuild every
  workspace crate anyway, so caching them adds about a gigabyte that never hits.
- **The `cargo run` that builds uniffi-bindgen must pass the same `--release` and `--target`
  as the library build**, and the `--library` path must sit in the directory those flags
  select. Otherwise cargo compiles about 650 dependencies a second time, or reads a library
  no step produced.
- **A `Swatinem/rust-cache` entry decides how long a job takes, never what it reports**, because cargo recompiles
  whatever fingerprint does not match. A misnamed group costs a miss, which is also why
  nobody notices when caching silently stops working.
