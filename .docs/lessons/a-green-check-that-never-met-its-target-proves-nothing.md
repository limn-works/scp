# A Green Check That Never Met Its Target Proves Nothing

A check reports success in two different situations: it met its target and rejected
nothing, or it never met its target at all. The two look identical in CI output. These
rules separate them.

## Rules

- **A check placed where its target cannot arise reports success forever.** An assertion
  comparing `rustc --version` against the pin ran in a GitHub Actions job, and a GitHub
  runner exports no `RUSTUP_TOOLCHAIN`, so the variable the assertion exists to catch could
  not occur there. It now runs in `scripts/hooks/pre-commit`, immediately before that hook
  runs `cargo fmt` and `cargo clippy` under whatever compiler the developer's shell
  resolved. Place a check where its target occurs, and say in the check where that is.
- **When a design change removes a check's reason, ask separately whether it removed the
  check's target.** A container-discovery check existed because an image tag used to name
  the compiler, so a stale tag was a string a gate could read. Making the tags name a
  Debian release and no Rust version did not remove that obligation — it moved the
  obligation from the tag to the `COPY` that brings `rust-toolchain.toml` into the image,
  and a new Dockerfile that omits that copy compiles on whatever the base image ships and
  builds successfully. The check moved with the obligation. Bundling both deletions into
  one line-count reduction is how a refactor loses coverage nobody argued about.
- **An artifact that no job builds is an artifact nobody knows is broken.** No CI job had
  ever built the root `Dockerfile`. It sat on `FROM rust:1.85-slim`, thirteen minor
  versions behind the pin, while `scripts/check-shipped-feature-graph.sh` reasoned about
  the binaries it ships and `templates/personal-relay/README.md` told self-hosting
  operators to run a container build. The first `docker build .` anyone ran surfaced three
  defects that no other check could reach:
  1. `.dockerignore` excluded `*.md`, and twelve crates open with
     `#![doc = include_str!("../README.md")]`, so the build failed at the first of them.
  2. `cargo chef cook` with no package filter cooks the whole workspace, which pulls in
     `scp-ffi` and fails at `pyo3-build-config` with "no Python 3.x interpreter found". The
     image ships no Python bindings, so the cook step names the two binaries it builds.
  3. The `rust:slim` base ships no cmake, no perl, and no OpenSSL headers, which
     `aws-lc-sys`, `ring`, and `libsqlite3-sys` compiling SQLCipher each need.
- **When a change repairs something no required check exercises, run the thing before
  merging the repair.** Three fuzz jobs referenced a toolchain action by a ref that never
  resolved, so every scheduled run failed at job setup and the fuzzer had not executed
  since. No pull request runs a scheduled workflow, so those consecutive failures never
  appeared on one. `gh workflow run <file> --ref <branch>` runs the branch's copy of a
  workflow that exists on the default branch. One dispatch reported what a green pull
  request could not: the repaired jobs got past setup and started their
  fuzzers, and the six weekly deep-fuzz jobs died at cargo-fuzz's first rustc invocation on
  `RUSTFLAGS="-Zsanitizer=address,undefined"`, because rustc offers no `undefined`
  sanitizer — it names the ones it accepts in the error. That second defect sat behind the
  first and would have outlived the repair.
- **Read a shared build cache everywhere, and write it only from a push to the default
  branch.** A cache written on a pull-request ref is readable only by that pull request,
  and it evicts entries from the budget every other cache step in the workflow shares.

## See also

- `.docs/lessons/a-gate-enumerates-its-population-and-reads-the-parse.md` — the other half
  of gate soundness: which members the check finds, and how it reads each one.
- `.docs/lessons/test-whitelist-masks-ci-red.md` — the same failure in a test suite: a
  narrowed local run reporting green over a red full suite.
