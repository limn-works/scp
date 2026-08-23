# Pin the Rust Toolchain Once, and Derive Every Other Consumer From That One File

**Date:** 2026-08-22, revised 2026-08-23
**Source:** branch `fix/clippy-1-98-chunks-exact` — the `Rust / clippy` required check failed
on every branch after Rust 1.98.0 shipped, and a local run of the identical command
reported nothing.

## The Rule

A repository that runs `cargo clippy` as a required check names its compiler version in
exactly one file, and every other consumer reads the version out of that file. A workflow
step that installs `dtolnay/rust-toolchain@stable` selects whichever stable release exists
on the morning the job runs, so a required check built that way fails for a reason nobody
changed and nobody can reproduce.

The corollary is the part this branch learned the hard way: **a second file that names the
version is the defect, and a gate asserting that the two agree is a workaround for it.**
Write the version once, and make every other consumer derive it, so two files cannot
disagree.

State that scope precisely, because the derivation does not close everything. It removes
every disagreement between two files in the repository. It does not remove a
`RUSTUP_TOOLCHAIN` exported into a developer's environment from outside the repository,
which still overrides `rust-toolchain.toml` and which `scripts/hooks/pre-commit` therefore
checks on every commit.

## What Happened

Rust 1.98.0 shipped on 2026-08-20. Its clippy added two lints, and they sit in different
groups. `chunks_exact_to_as_chunks` is a `style` lint, warn by default and a member of
`clippy::all`, so it fires with no group flags at all. `unused_async_trait_impl` is allow
by default and reaches this workspace through the `pedantic` group.
`[workspace.lints.clippy]` enables `all`, `pedantic`, `nursery`, and `cargo` at `warn`,
and CI escalates every one with `-D warnings`. Dropping `pedantic` would therefore not
have prevented the outage, because the style lint would still have fired.

Every branch in the merge queue started failing `Rust / clippy` the next morning, against
code no one had touched. Local machines were still on 1.97.1, so running the exact CI
command locally printed a clean pass, and one agent reported the failure as
unreproducible.

CLAUDE.md requires running CI locally before pushing. That requirement decides nothing
while the two runs resolve to different compilers.

## The First Fix Made Seven Files Name the Version, and a 426-Line Gate Check That They Agreed

The first fix wrote `1.98.0` into `rust-toolchain.toml`, `.mise.toml`, the root
`Dockerfile`, the container recipe in `templates/personal-relay/README.md`, and four rows
of `.docs/standards/rust.md`, then wrote `nightly-2026-05-03` into
`fuzz/rust-toolchain.toml` and into a `FUZZ_TOOLCHAIN` variable in each of two workflows.
`scripts/check-toolchain-pin.sh` — 426 lines, plus five fixture repositories and a
123-line runner — read every one of those locations and required exact equality.

Every reason each location gave for naming the version was locally sound, which is why six
review rounds passed the design and kept finding new spellings to reject inside it. The
design was the defect. Seven declarations means seven chances to disagree, and the gate
detected a disagreement after someone wrote it rather than preventing anyone from writing
one.

## The Fix: One Source, Every Consumer Derived

`rust-toolchain.toml` is the one place this repository names a stable Rust version, because
`cargo` and `rustup` read it natively and no other file can supply it to them. Every other
consumer now reads it:

- **mise** reads it because `.mise.toml` sets
  `idiomatic_version_file_enable_tools = ["rust"]`. mise's rust tool registers
  `rust-toolchain.toml` as its version source, parses `channel`, `components`, and
  `targets` out of it, passes all three to `rustup toolchain install`, and exports
  `RUSTUP_TOOLCHAIN` with the channel it just read. See
  https://mise.jdx.dev/configuration.html#idiomatic-version-files.
- **The root `Dockerfile`** copies the file into the builder stage before the first cargo
  command. Its base tag reads `rust:slim-bookworm`, which names a Debian release and no
  Rust version, and rustup inside the image resolves the pin.
- **The container recipe in `templates/personal-relay/README.md`** does the same through
  its `COPY . .`.
- **`.docs/standards/rust.md`** names no version; its toolchain row points at
  `rust-toolchain.toml`.
- **`fuzz/rust-toolchain.toml`** names the nightly the standalone fuzz crate needs, because
  cargo-fuzz does not run on stable. Every documented fuzz command runs from inside `fuzz/`
  — `cd fuzz && cargo fuzz run <target>` — because rustup applies the toolchain file of the
  directory a command runs in, so `fuzz/README.md`, `fuzz/.claude/CLAUDE.md`, CLAUDE.md's
  toolchain table, `.docs/standards/rust.md`, and the fuzz-build job in
  `.github/workflows/ci.yml` name no channel at all. `.github/workflows/fuzz.yml` is the
  exception: its `cargo fuzz` commands run from the repository root so their corpus-cache
  paths and their command paths agree, so it reads the channel out of the file in one job
  and passes that output to the others.

Raising either version is now a one-line edit. Getting there took a second pass: the first
one moved the two toolchain files and the workflows and left the channel written out in 35
documented commands across nine files, including CLAUDE.md's own toolchain table. A
single-source design is not done while the commands people are told to run still type the
version.

## What `RUSTUP_TOOLCHAIN` Actually Does, and When mise Sets It

The first fix's artifacts stated that "mise sets `RUSTUP_TOOLCHAIN` for the commands it
runs." mise sets it **only for a rust toolchain it has installed**: `exec_env` runs per
installed `ToolVersion`, so `rust = "stable"` with stable installed exports
`RUSTUP_TOOLCHAIN=stable`, while `rust = "1.98.0"` that `mise install` has not yet fetched
exports nothing at all. That distinction is what produced the outage's local half. Before
this branch, `.mise.toml` read `rust = { version = "stable", ... }`, mise had `stable`
installed, and every shell in the repository therefore carried `RUSTUP_TOOLCHAIN=stable`,
which overrides `rust-toolchain.toml` entirely — channel, components, and targets alike. A
shell compiled on 1.97.1 while every file in the repository read 1.98.0.

Naming the pinned version in `.mise.toml` would have fixed that instance and left the
mechanism intact, because the two files could still be edited apart. Reading the version out
of `rust-toolchain.toml` removes the mechanism: the exported variable is now derived from
the file it used to override.

Check what a shell resolves with `mise x -- printenv RUSTUP_TOOLCHAIN`; plain `mise env`
does not print the variable.

A variable exported from somewhere other than mise still overrides the file, and nothing
derives that away. `scripts/hooks/pre-commit` now checks it; the section below on deleting
checks records why it moved there rather than out.

## `dtolnay/rust-toolchain` Reads No Toolchain File

The action's `action.yml` performs no filesystem read of the checkout. With the `toolchain`
input omitted, `@master` exits with `'toolchain' is a required input`; `@stable` defaults
the input to `stable`. So each `dtolnay/rust-toolchain@stable` step in these workflows
installs rustup's `stable` and runs `rustup default stable`, and it selects no version for
this repository — rustup then applies `rust-toolchain.toml` as a directory override, which
beats `rustup default`, so every cargo command in a CI job compiles on the pin. Each step
costs one redundant toolchain install and installs its `targets:` inputs into a toolchain
cargo does not use.

A workflow that needs a version the action must install — the fuzz jobs, which need a dated
nightly — reads the channel in a prior step and passes it as the `toolchain` input to
`@master`.

## The Paths Filter Has To List the Pin

`.github/workflows/ci.yml` guards every Rust job with
`if: needs.changes.outputs.rust == 'true'`, and the `ci` job that aggregates every other
job's result fails only on a result of `failure` or `cancelled`, so a skipped job reports
success to branch protection. The `rust` filter that produces that output listed
`crates/**`, `Cargo.toml`, `Cargo.lock`, and `deny.toml`.

Adding the pin without adding the filter entry would have reproduced the outage the pin
prevents, one step later. A pull request raising the pin to 1.99.0 touches
`rust-toolchain.toml` and nothing else, and that path matched no entry the `rust` filter
listed. `rust` resolves to `false`, `Rust / clippy`, `Rust / test`, `Rust / build`, and
`Rust / deny` all skip, the `ci` aggregator reports success, and the bump merges without
one command compiling on 1.99.0. Every branch that rebases onto it then finds
`Rust / clippy` red the next morning, which is the outage this pin exists to prevent,
reached through the pin file itself.

Routing is one of two properties the derivation cannot supply, because no file states
which CI jobs a change has to reach. `scripts/check-toolchain-wiring.sh` asserts that
membership, and `scripts/tests/toolchain-wiring/run-tests.sh` proves the assertion fires.
The list it checks holds one line per filter and entry: the `rust` filter must list
`rust-toolchain.toml`, `Dockerfile`, and `.dockerignore`, and the `fuzz` filter must list
`fuzz/**`, which covers `fuzz/rust-toolchain.toml`.

That list needed a criterion, and writing one changed what belongs on it. The `rust` filter
also lists `crates/**` and `Cargo.toml`, and dropping either produces the identical
failure — the guarded jobs skip and the aggregator passes. The four declared entries share
a property those two do not: **their omission is invisible on an ordinary pull request.**
Dropping `crates/**` skips the Rust lane on nearly every pull request and someone notices
within a day; dropping `rust-toolchain.toml` skips it only on the rare pull request that
raises the pin — the one that most needs the lane — and nobody notices. The gate covers the
second class, says so in its header, and says that an `OK` is not a claim that the filters
are correct.

A gate that runs only when a paths filter selects it enforces nothing for a file the filter
omits. Adding a file that decides how CI builds means adding that file to the filter that
runs the jobs it decides for, in the same commit.

## Deleting a Check Because Its Reason Changed Is Not the Same as Deleting It Because Its Target Vanished

Two checks in the 426-line gate had nothing to do with version agreement, and both nearly
went out with it.

**The compiler-identity check** ran `rustc --version` and compared it against the pin. Its
target is any `RUSTUP_TOOLCHAIN` in the environment, from any source — not only from mise.
Deriving mise's export from the file removed mise as a source and left every other one, so
the check still has a target. What was wrong with it was its *placement*: it ran in the
`enforcement / toolchain pin agreement` CI job, and a GitHub runner exports no
`RUSTUP_TOOLCHAIN`, so it ran only where its target cannot arise. A check placed where its
target cannot occur reports success forever, which is indistinguishable from the check
working. It now runs in `scripts/hooks/pre-commit`, immediately before that hook runs
`cargo fmt` and `cargo clippy` under whatever compiler the shell resolved, and it reads the
expected version out of the pin so it names none.

**The container-discovery check** searched every file carrying a line-initial `FROM` and
required each to be declared. It existed because a container tag used to *name* the
compiler, so a stale tag was a string a gate could read; `templates/personal-relay/README.md`
shipping Rust 1.85 is what it caught. Making the tags name a Debian release and no Rust
version did not remove that obligation — it moved it, from the tag to the `COPY` that brings
`rust-toolchain.toml` into the image. A new Dockerfile that omits that copy compiles on
whatever the base image ships and builds successfully, so the `docker-image` job cannot
detect it. So the check moved with the obligation: `scripts/check-toolchain-wiring.sh` finds
every file that builds from a `rust` base image and fails when it carries no `COPY` of the
pin.

The generalisation: when a design change removes a check's *reason*, ask separately whether
it removed the check's *target*. Bundling both deletions into one line-count reduction is
how a refactor loses coverage it never argued about.

## An Image No Job Builds Is an Image Nobody Knows Is Broken

No CI job had ever built the root `Dockerfile`. It sat on `FROM rust:1.85-slim`, thirteen
minor versions behind the pin, while `scripts/check-shipped-feature-graph.sh` reasoned
about the binaries it ships and `templates/personal-relay/README.md` told self-hosting
operators to run a container build. The first `docker build .` anyone ran surfaced three
defects that no other check could reach:

1. `.dockerignore` excluded `*.md`, and twelve crates open with
   `#![doc = include_str!("../README.md")]`, so the build failed at the first of them.
2. `cargo chef cook` with no package filter cooks the whole workspace, which pulls in
   `scp-ffi` and fails at `pyo3-build-config` with "no Python 3.x interpreter found". The
   image ships no Python bindings, so the cook step names the two binaries it builds.
3. The `rust:slim` base ships no cmake, no perl, and no OpenSSL headers, which
   `aws-lc-sys`, `ring`, and `libsqlite3-sys` compiling SQLCipher each need.

`ci.yml` now carries a `docker-image` job, guarded by the `rust` paths filter, and the
wiring gate asserts that `Dockerfile` and `.dockerignore` are entries in that filter. The
job reads the layer cache everywhere and writes it only on a push to `main`, because a
cache written on a pull-request ref is readable only by that pull request and would evict
entries from the 10 GB budget the workspace caches in this workflow share.

## Why the First Fix's Container Check Was a Whitelist, and Why It Is Gone

The container check took three rounds of the wrong shape before it became a whitelist of
permitted `FROM` lines. Each round validated Docker's `FROM` syntax by pattern, and each
round a reviewer named one more legal spelling the pattern mishandled: an indented keyword,
a lowercase one, an untagged `FROM rust`, a registry-qualified image, a second stage whose
tag named no Debian release. Docker's grammar admits many spellings of one image, so
enumerating the spellings does not terminate. Enumerating the permitted lines does.

The whitelist was the right shape for the wrong question. It existed to stop a container
tag from naming a Rust version other than the pin, and a tag that names no Rust version
cannot. Both container builds now read the version out of the file, and the check is
deleted.

Two things it guarded remain true and are stated where they apply rather than enforced by a
script. The base tag still selects a Debian release, and glibc is backward compatible only,
so a builder stage on Debian 13's glibc 2.41 produces binaries that cannot exec against the
runtime stage's Debian 12 glibc 2.36 — which is what `rust:1.85-slim` (bookworm) to
`rust:1.98.0-slim` (trixie) would have done. Both stages name `bookworm`, and the
`docker-image` job builds the result.

CLAUDE.md names the review-pass count as the signal that an approach is the wrong one. Six
rounds on one script was well past that signal, and the reviews kept converging on
spellings inside a design nobody had questioned. The lesson is not that the reviewers found
bugs; it is that the third round finding a fourth spelling was already enough evidence to
ask what the script was compensating for.

## A Scheduled Workflow Fails Where No Pull Request Looks

Auditing the fuzz steps turned up a defect that had nothing to do with the pin: all three
fuzz jobs referenced the action as `dtolnay/rust-toolchain@nightly-2026-05-03`, and that
repository publishes `master`, `stable`, `beta`, `nightly`, and a branch per released
version — but no dated-nightly branch. The ref never resolved, so every scheduled Fuzz run
failed at job setup with "unable to find version", and the fuzzer had not executed since
the ref was introduced. No pull request runs the scheduled Fuzz workflow, so its ten
consecutive failures never appeared on one. Naming the date through the `toolchain` input
of `@master` gives a ref that resolves.

## Raising the Pin

1. Edit `channel` in `rust-toolchain.toml`. Nothing else names the version.
2. Run `mise install`, so the local shell picks up the new toolchain.
3. Run the CI clippy command from the "Orchestrator verification protocol" section of
   CLAUDE.md.
4. Fix everything the new release reports, in that same pull request.

A new stable release then reports its lints to whoever raised the pin, on the pull request
that raised it.
