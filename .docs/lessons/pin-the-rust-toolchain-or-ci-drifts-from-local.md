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
`RUSTUP_TOOLCHAIN` exported into a developer's environment, which still overrides both
toolchain files: `scripts/hooks/pre-commit` compares `rustc --version` against the
workspace pin on every commit, and `fuzz/build.rs` fails the fuzz crate's build when cargo
resolved a compiler `fuzz/rust-toolchain.toml` does not name.

The second corollary this branch learned: **a tool that exports one toolchain value per
shell cannot serve a repository that resolves a different toolchain per directory.** mise
does that, so mise no longer manages Rust here at all.

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

- **rustup** reads it natively for any cargo command run in the directory holding it, and
  installs the channel, components, and targets it names on first use. `.mise.toml` names
  no Rust version and installs no Rust toolchain, so nothing exports a `RUSTUP_TOOLCHAIN`
  that would override the file — the section below records why that omission is the
  design and not an oversight.
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

## A Per-Directory Toolchain and a Per-Repository Environment Variable Cannot Both Decide

The first fix's artifacts stated that "mise sets `RUSTUP_TOOLCHAIN` for the commands it
runs." mise sets it **only for a rust toolchain it has installed**: `exec_env` runs per
installed `ToolVersion`, so `rust = "stable"` with stable installed exports
`RUSTUP_TOOLCHAIN=stable`, while `rust = "1.98.0"` that `mise install` has not yet fetched
exports nothing at all. That distinction is what produced the outage's local half. Before
this branch, `.mise.toml` read `rust = { version = "stable", ... }`, mise had `stable`
installed, and every shell in the repository therefore carried `RUSTUP_TOOLCHAIN=stable`,
which overrides `rust-toolchain.toml` entirely — channel, components, and targets alike. A
shell compiled on 1.97.1 while every file in the repository read 1.98.0.

The second attempt kept mise as the exporter and made the exported value derive from the
file, through `idiomatic_version_file_enable_tools = ["rust"]`. That removed the
disagreement between two files and broke every fuzz command, because it answered the wrong
question. **`RUSTUP_TOOLCHAIN` holds one value for the whole shell, and this repository
resolves two compilers by directory:** `rust-toolchain.toml` names the stable release the
workspace compiles on, and `fuzz/rust-toolchain.toml` names the nightly cargo-fuzz needs.
Measured on this branch with mise 2026.2.22 and rustup 1.29.0: `mise env` at the repository
root printed `export RUSTUP_TOOLCHAIN=1.98.0`, and with that variable set, `rustc --version`
inside `fuzz/` reported `1.98.0` rather than the `1.97.0-nightly (20de910db 2026-05-02)` the
same command reports with the variable unset. Every rewritten fuzz command —
`cd fuzz && cargo fuzz run <target>` — therefore died on
`error: the option 'Z' is only accepted on the nightly compiler`, and CLAUDE.md tells
readers to run `eval "$(mise env)"`, which is exactly how the variable gets into a shell.
The commands the branch replaced carried `+nightly`, which sets `RUSTUP_TOOLCHAIN` for one
command and is immune to the exported one; dropping the flag removed that immunity.

So mise stopped managing Rust. `.mise.toml` names no Rust version and enables no idiomatic
version file for rust, `README.md` lists rustup among the prerequisites, and rustup reads
the toolchain file of whichever directory a command runs in — which is the mechanism the
whole design already rested on. Measured with that configuration, in a directory outside
any other mise config: `mise env` printed no `RUSTUP_TOOLCHAIN` at the root or in `fuzz/`,
`rustc --version` reported `1.98.0` at the root, and `1.97.0-nightly` in `fuzz/`.

The generalisation: **when a tool supplies one value per shell and the repository needs one
value per directory, deriving that tool's value from the right file does not fix it.**
Derivation removes disagreement between two files; it does not give a single variable two
values. Remove the tool from that job instead.

A variable exported from somewhere else still overrides both files, and nothing derives that
away. Three checks cover what remains: `scripts/check-toolchain-wiring.sh` fails when
`.mise.toml` names a Rust version source again, `scripts/hooks/pre-commit` compares
`rustc --version` against the workspace pin before it runs `cargo fmt` and `cargo clippy`,
and `fuzz/build.rs` fails the fuzz crate's build when cargo resolved a compiler
`fuzz/rust-toolchain.toml` does not name. The last one also gives the `fuzz-build` CI job
something to assert: that job runs `cargo check` from `fuzz/`, which passes no `-Z` flag and
so would have succeeded on stable, reporting green over a broken directory override.

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

## A Change to the Pin Has To Reach the Jobs That Compile On It

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

Routing is one of the properties the derivation cannot supply, because no file states which
CI jobs a change has to reach. `scripts/check-toolchain-wiring.sh` asserts it, and
`scripts/tests/toolchain-wiring/run-tests.sh` proves the assertion fires.

The criterion is: **the omission of a path from its filter is invisible on an ordinary pull
request.** The `rust` filter also lists `crates/**` and `Cargo.toml`, and dropping either
produces the identical failure — the guarded jobs skip and the aggregator passes. Dropping
`crates/**` skips the Rust lane on nearly every pull request and someone notices within a
day; dropping `rust-toolchain.toml` skips it only on the rare pull request that raises the
pin — the one that most needs the lane — and nobody notices. The gate covers the second
class, says so in its header, and says that an `OK` is not a claim that the filters are
correct.

A gate that runs only when a paths filter selects it enforces nothing for a file the filter
omits. Adding a file that decides how CI builds means adding that file to the filter that
runs the jobs it decides for, in the same commit.

## The Rust Lane Is Not the Only Lane That Compiles Rust

Six other filters guard a job that compiles a crate of this workspace, and writing the
criterion in terms of the `rust` filter hid all six.
`python-test` runs `maturin develop --release`.
`typescript-check` runs `cargo build -p scp-ffi-napi --release`.
`typescript-wasm-check` and `scaffold-typescript-web-check` run `wasm-pack build` from the
repository root. `kotlin-test` runs `cargo build -p scp-ffi-uniffi --features testing`.
`swift-build-test` runs `bindings/swift/build-xcframework.sh --dev`, which calls
`cargo build`. Each of those jobs installs `dtolnay/rust-toolchain@stable` and then runs
cargo inside the repository, so rustup applies `rust-toolchain.toml` as a directory
override and each one compiles on the pin.

Listing the pin in the `rust` filter alone therefore reproduced the defect in six more
filters. A pull request that edits only `channel` runs clippy, the test lane, the builds,
cargo-deny, and the image build on the new compiler, while `Python / test`,
`TypeScript / check + lint + test`, the two wasm jobs, `Kotlin / test`, and
`Swift / build + test` all skip, and the `ci` aggregator counts each skip as a pass. Should the new compiler break the
pyo3 cdylib link, the UniFFI bindgen run, or the wasm-pack build, the first branch to see
it is the next one that touches `bindings/python`, and that branch changed no compiler.

The rule the `rust`-only version obscured: **route a file to every lane that guards a job
whose behaviour the file decides, not to the lane whose name matches the file.**
`rust-toolchain.toml` sits at the repository root and names a Rust version, which makes the
`rust` filter the obvious single destination, but the compiler that file selects reaches
every job that runs cargo.

## Writing the Pin Into Seven Filters, and Then Into a Seven-Pair List, Was the Same Mistake Twice

Listing `rust-toolchain.toml` in seven filters, and asserting that membership with seven
pairs in the gate, put the pin in fourteen places. Both lists grow with the lanes, and
neither one tells anyone about a lane added later. CLAUDE.md names the review-pass count as
the signal that an approach is the wrong one, and five consecutive commits on this one gate
each closed "one more spelling" of the same hole.

The workflow names the pin once instead. The `changes` job declares a `toolchain` filter
holding `rust-toolchain.toml`, and each lane's output reads
`steps.filter.outputs.<lane> == 'true' || steps.filter.outputs.toolchain == 'true'`. The
gate reads the set of output names out of the workflow rather than out of a list it holds,
so a lane added later without that OR fails the gate, and nobody has to remember to teach
the gate about it.

The remaining root-level entries — `Dockerfile`, `.dockerignore`, `.clippy.toml`,
`rustfmt.toml` — got the same treatment from the other side. Instead of naming the files
that must be routed, the gate enumerates every root-level file in the git tree and requires
each one to be routed by the `rust` or `toolchain` filter, or declared in a list of files
no compile reads. Every root file is then classified exactly once, and a file added
at the root later is unclassified, so the gate fails until someone decides which it is.
That is the property the list of required entries did not have: **an entry nobody added was
an entry nobody heard about.**

**The first version of that enumeration read the criterion off the wrong feature.** The
criterion is a path whose omission from a filter no ordinary pull request reveals, and the
enumeration kept only paths holding no slash, which is a property of where the four files
that prompted it happened to sit. `.cargo/config.toml` satisfies the criterion and holds a
slash: cargo reads it out of every ancestor of the directory a command runs in, its
`[target.wasm32-unknown-unknown]` stanza is what selects getrandom's wasm backend for
`wasm-pack build`, no filter listed it, and a `[build]` stanza added there would change
what every crate in the workspace compiles to. A pull request deleting that stanza and
changing nothing else skipped every job, and the aggregator reported success. The
enumeration now covers a second population derived from cargo's own documented
configuration discovery — every `.cargo/config.toml` and `.cargo/config` in the tree, at
any depth — and the pin's filter lists `.cargo/**`, so the population and the routing meet.
**Writing an enumeration from the examples in front of you reproduces their incidental
shape; derive it from the criterion instead.**

The general form: a check that names the things which must be present fails silently on the
thing nobody thought of, while a check that enumerates the population and requires each
member to be classified cannot.

**Rejected alternative: write the `rust` filter as `'**'` followed by exclusions.** That
inverts the default so an unlisted path runs the lane, which is the safe direction, and it
would retire the root-file classification. Two things argue against it. First, it does not
work as written under the action's default: dorny/paths-filter's README says its
`predicate-quantifier` input defaults to `'some'` — "File is included if it matches at least
one pattern (default)" — so `'**'` alone makes the filter true for every pull request, and
the `!`-prefixed exclusions only subtract under `'some-with-excludes'`. Switching the
quantifier changes matching for all eight filters in the block at once. Second, the cost is
recurring: with `'**'` minus a directory list, every commit under `.claude/agent-memory/`
and `.docs/` runs clippy, the test lane, both production builds, cargo-deny, and the ~6 GB
`docker-image` build, against a failure mode that arises when someone adds a Rust-compiling
path outside `crates/`.

## Deleting a Check Because Its Reason Changed Is Not the Same as Deleting It Because Its Target Vanished

Two checks in the 426-line gate had nothing to do with version agreement, and both nearly
went out with it.

**The compiler-identity check** ran `rustc --version` and compared it against the pin. Its
target is any `RUSTUP_TOOLCHAIN` in the environment, from any source — not only from mise.
Taking Rust out of `.mise.toml` removed mise as a source and left every other one, so the
check still has a target. What was wrong with it was its *placement*: it ran in the
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
every file Docker builds from a `rust` base image and fails when it does not carry the
ASSERT-PINNED-RUSTC block, which makes the build itself compare the compiler it resolved
against the copied-in pin.

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
wiring gate reaches `Dockerfile` and `.dockerignore` through its root-file enumeration:
both sit at the repository root, so each must be routed by a filter or declared as a file
no compile reads. The
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

**Repairing a scheduled workflow and merging on a green pull request proves nothing about
the schedule, so dispatch it.** `gh workflow run fuzz.yml --ref <branch>` runs the branch's
copy of a workflow that exists on the default branch. Run 32634187570 did that, and it
reported two things a green pull request could not: the twelve nightly jobs got past setup,
installed cargo-fuzz on the dated nightly, and started their fuzzers — and all six weekly
`Deep Fuzz` jobs died at cargo-fuzz's first rustc invocation on
`RUSTFLAGS="-Zsanitizer=address,undefined"`, because rustc has no `undefined` sanitizer and
never has. That second defect predates the action-ref defect, sat behind it, and would have
outlived the repair: the workflow's last 40 runs record 38 failures and one cancellation.

The rule: **when a change repairs something no required check exercises, run the thing
before merging the repair.** One dispatch cost a runner hour and found a second defect that
would otherwise have kept the deep-fuzz lane dark while the repair was recorded as landed.

## `grep -F` Compares Lines, Not Blocks

The container check requires each container file to carry a three-line assertion block
"verbatim", and it compared with `grep -qzF -- "$ASSERT_BLOCK" "$f"`. grep splits a pattern
holding newlines into one pattern per line and matches when **any single one** matches, so
that call accepted a Dockerfile keeping one line of the block with the comparison and the
`exit 1` deleted, and accepted a Dockerfile holding all three lines in reverse order.
Measured on GNU grep 3.12, BSD grep 2.6.0-FreeBSD, and ugrep 7.8.4; `-z` changes the input
record separator and does not change how the pattern is split.

The gate reads the whole file into a variable and uses bash's `[[ $text == *"$block"* ]]`,
which is a literal substring test over the file and therefore compares the lines in order
and unbroken. `scripts/tests/toolchain-wiring/run-tests.sh` carries the two cases the old
comparison passed.

The generalisation: **`grep -F` with a multi-line pattern is a line-membership test, and a
comment claiming it compares "line for line and in order" describes a command grep does not
offer.** When a check needs a block comparison, read the file and compare the block.

## Searching for a Keyword Finds the Prose That Quotes It

After the container check became a block comparison, its discovery step still searched every
file in the tree: `git grep -l --untracked -E '^FROM[[:space:]]'`, then a second pattern
that kept the files whose `FROM` line named a `rust` image. That search reads a Dockerfile
and a Markdown file the same way, so a document that pasted a Dockerfile's first line into a
fenced block became a file the gate demanded the three-line assertion from. The
`enforcement / toolchain wiring` job runs on every pull request with no paths filter
(`.github/workflows/ci.yml`, the `toolchain-wiring` job), so a documentation-only pull
request failed a required check. Its author's two ways out were to paste build-time shell
into the prose, or to write the sentence so `FROM` no longer opened a line — and that second
edit also hides a real container build whose author typed a leading space.

The gate's own header stated the opposite: "Under-detection is the failure mode; nothing this
gate finds is rejected wrongly." That sentence was true of the criterion the header had
written above it — "a file that Docker builds from a `rust` base image" — and false of the
search that stood in for the criterion. CLAUDE.md names the failure: the search was an
indicator list written in the register of a contract. A line-initial `FROM rust` accompanies
a container build; it does not decide that Docker builds the file.

What decides it is the path, so the gate now reads the path. A basename Docker builds is one
rule: `Dockerfile`, `Dockerfile.<suffix>`, `<prefix>.Dockerfile`, and the three
`Containerfile` spellings. The BUILT_FROM_DOCUMENTATION list is the other, and it names
`templates/personal-relay/README.md`, whose block an operator is told to save and build. The
tree-wide search survives as a classification check rather than as the discovery rule: a file
outside both rules that holds a `FROM` line naming a rust image must appear in
QUOTES_A_CONTAINER_BUILD, and the gate fails on a file neither list names. A container build
kept under an unconventional name is therefore still caught, and its author says which of the
two the file is.

Reading the path also closed a gap the text search had. A `Dockerfile` that writes
`  from rust:slim-bookworm` — indented and lowercase, both of which Docker accepts — escaped
the old discovery search entirely. The name rule discovers that file whatever its `FROM`
lines look like.

The generalisation: **when a check asks whether a build system reads a file, the check reads
what the build system reads — a path, a manifest entry, a workflow input — not a keyword the
file's contents happen to carry.** A keyword search answers "does this text mention a
container build", and a document that explains one mentions it exactly as loudly as a
Dockerfile does.

## An Advisory Ignore Records the Day Somebody Wrote It

`deny.toml` suppressed RUSTSEC-2026-0098, RUSTSEC-2026-0099, and RUSTSEC-2026-0104 with the
justification "Awaiting upstream rustls-webpki patch". rustls-webpki published the patch for
the first two on 2026-04-14 and for the third on 2026-04-22, four months before anyone read
the file again, and every requirement on the crate in this workspace is semver-compatible
with it: rustls 0.23.37 requires `^0.103.5` and rustls-platform-verifier 0.6.2 requires
`^0.103`, so `cargo update -p rustls-webpki --precise 0.103.13` moved one lockfile entry and
nothing else. Until then the relay kept linking 0.103.10, which accepts a URI name
constraint it should reject, accepts a wildcard-asserting certificate under a permitted
DNS-name constraint, and panics on a syntactically valid empty `BIT STRING` in a CRL's
`onlySomeReasons` extension before that CRL's signature is verified.

An operator reading `deny.toml` to learn which advisories this repository still carries
would have read "no fix exists" and left all three suppressed. The three ignore entries are
deleted, and `cargo deny check advisories` — which the `rust-deny` job runs, guarded by a
filter that lists `deny.toml` and `Cargo.lock` — now fails if the lock ever resolves a
vulnerable rustls-webpki again.

The generalisation: **"awaiting upstream" is a claim about a date, and the file it lives in
does not age with it.** An ignore entry whose justification is the absence of a fix is a
claim to re-check against the advisory database's `patched` range, not a decision to record
once.

## Raising the Pin

1. Edit `channel` in `rust-toolchain.toml`. Nothing else names the version.
2. Run the CI clippy command from the "Orchestrator verification protocol" section of
   CLAUDE.md. rustup downloads the new toolchain, its components, and its targets on that
   first cargo invocation.
3. Fix everything the new release reports, in that same pull request.

A new stable release then reports its lints to whoever raised the pin, on the pull request
that raised it.
