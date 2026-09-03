#!/usr/bin/env bash
#
# Toolchain-wiring gate.
#
# `rust-toolchain.toml` is the one place this repository names a stable Rust version, and
# `fuzz/rust-toolchain.toml` the one place it names a nightly. Every consumer derives the
# version from one of those two files, so no two consumers can disagree. This gate checks
# the four things a derivation cannot establish on its own. Check 4 belongs here because
# checks 2a through 2e all rest on how the `ci` aggregator treats a skipped job, and that
# aggregator has to observe the `changes` job whose failure produces the skips.
#
# ── CHECK 1: every container build proves which compiler it resolved ─────────────────
#
# THE CRITERION. Docker builds a file's contents, and a build whose base image is a `rust`
# image compiles this workspace's crates on whatever compiler that image ships, unless the
# build brings `rust-toolchain.toml` in and rustup resolves it. The property that decides
# whether such a build is correct is the compiler the image actually resolves — not the
# text of any COPY line.
#
# So each such file asserts it itself. Each one carries the ASSERT_BLOCK below verbatim:
# three lines that read the channel out of the copied-in pin, read `rustc --version`, and
# fail the build when they differ. The gate requires the block, and the block then proves
# the property at build time.
#
# Reading COPY lines instead does not converge, and two probes show why: a pin copied into
# a stage that never compiles passes such a check, and a legitimate whole-context copy
# written `COPY . /build` fails it. Docker's grammar admits many spellings of one effect,
# and the stage graph decides which copy reaches which compile. One canonical block,
# compared literally, has neither problem — and unlike a text check it cannot be satisfied
# by a build whose compiler is wrong.
#
# This replaces what the base tag used to say out loud. `FROM rust:1.98.0-slim-bookworm`
# named the compiler, so a stale tag was a string a gate could read; `FROM rust:slim-
# bookworm` names a Debian release and leaves the compiler to the copied-in file.
#
# WHICH FILES DOCKER BUILDS. The gate decides that by path, through two rules, and not by
# searching the tree for a `FROM` line:
#
#   * A file whose basename is `Dockerfile`, `Dockerfile.<suffix>`, `<prefix>.Dockerfile`,
#     `Containerfile`, `Containerfile.<suffix>`, or `<prefix>.Containerfile`. `docker build`
#     reads `Dockerfile` by default, and `docker build -f` conventionally names one of the
#     others.
#   * A file the BUILT_FROM_DOCUMENTATION list below names: prose holding a container block
#     that the prose tells a reader to save and build. The block an operator runs is the
#     build, so the obligation follows the block into the prose.
#
# Prose that quotes a container build is not a container build, and an earlier revision of
# this gate could not tell the two apart. It searched every file in the tree for a
# line-initial `FROM` naming a rust image and demanded the block from whatever it found, so
# an architecture decision record or a runbook that pasted a Dockerfile's first two lines
# into a fenced block failed `enforcement / toolchain wiring`, which every pull request
# runs. That author had two ways out: paste three lines of build-time shell into the prose,
# or break the quotation so `FROM` no longer opened a line. Breaking it that way also hides
# a real container build whose author wrote a leading space.
#
# The tree-wide search survives as a classification check rather than as the discovery
# rule. A file that neither rule above covers, and that holds a `FROM` line naming a rust
# image, must appear in the QUOTES_A_CONTAINER_BUILD list below; the gate fails on a file
# that appears in neither list. A container build kept under a name Docker does not
# conventionally use is therefore still caught, and its author states which of the two the
# file is instead of rewording a sentence. A file that no `FROM` line matches needs no
# entry in either list, so ordinary prose costs an author nothing.
#
# Each list takes its entries at face value, which is the one judgement this check cannot
# make. The gate rejects the one contradiction it can see: a QUOTES_A_CONTAINER_BUILD entry
# whose basename is a name Docker builds. An entry naming a file that does not exist is
# inert, and the gate skips it rather than reporting it.
#
# WHAT THE CLASSIFICATION SEARCH DOES NOT COVER, stated rather than implied: it matches a
# whole `FROM` instruction, written to Dockerfile's grammar for that instruction, opening a
# line apart from leading whitespace, in either case. A container build that reaches the
# keyword some other way — a line continuation, a file a script generates, a Dockerfile
# packed into an archive — goes undiscovered when its name is one the first rule does not
# cover. Under-detection is that search's failure mode. The name rule carries no such gap,
# because it reads the path rather than the file's text.
#
# ── CHECK 2: the CI paths filters route a change to the jobs that build from it ──────
#
# THE CRITERION: a change to a file that decides how a CI job compiles must make that job
# run. A job guarded by `if: needs.changes.outputs.<filter> == 'true'` skips when its
# filter matches nothing, and a skipped job reports success rather than absence: the `ci`
# job that aggregates `.github/workflows/ci.yml` fails only on 'failure' or 'cancelled',
# and GitHub counts a skipped job as a pass for a required status check. A file that no
# filter routes therefore merges with every job that reads it skipped and every status
# green.
#
# WHICH WORKFLOWS THE CRITERION BINDS. Every workflow that guards a job with a paths
# filter, not `ci.yml` alone, and the gate enumerates them from the tree: each tracked
# file under `.github/workflows/` whose extension GitHub Actions runs — `.yml` or
# `.yaml`, which leaves a `.disabled` name out — and that declares a
# `dorny/paths-filter` step. Checking `ci.yml` alone left `docs.yml` free to violate the
# criterion while the gate printed OK: its `rust-docs` job runs
# `cargo doc --workspace --document-private-items`, which compiles every crate of this
# workspace on whatever the pin names, and its `docs` filter listed no toolchain file, so
# a pull request that raised the pin skipped the one job that exercises rustdoc on the new
# compiler. That workflow's own header records what an unrun `rust-docs` cost once
# already: three broken intra-doc links rode `main` for ten days.
#
# `on: pull_request: paths:` is the other way a workflow narrows what it runs, and the
# criterion does not bind it: a required check whose workflow never starts stays pending
# and blocks the merge, so that mechanism fails closed on its own.
#
# The workflows satisfy that criterion in two pieces, and this gate checks each piece
# against the repository rather than against a list of paths someone remembered to add.
#
#   2a/2b — THE PIN, ROUTED BY CONSTRUCTION. `rust-toolchain.toml` selects the compiler
#   for every lane, not only the Rust lane: `python-test` runs `maturin develop`,
#   `typescript-check` runs `cargo build -p scp-ffi-napi`, `typescript-wasm-check` and
#   `scaffold-typescript-web-check` run `wasm-pack build`, `kotlin-test` runs
#   `cargo build -p scp-ffi-uniffi`, `swift-build-test` runs `build-xcframework.sh`, and
#   `docs.yml`'s `rust-docs` runs `cargo doc`. Listing the pin in each of those filters is
#   a list that grows with the lanes. Instead each workflow declares one `toolchain`
#   filter holding the pin, and every output of its `changes` job ORs that filter in. The
#   gate reads the set of outputs out of each workflow, so a lane added later without the
#   OR fails here, and no list in this file has to learn about it.
#
#   2c — THE BUILD-CONFIGURATION FILES, CLASSIFIED EXHAUSTIVELY. THE CRITERION: a path
#   whose omission from a filter no ordinary pull request reveals. Dropping `crates/**`
#   from the `rust` filter skips the Rust lane on nearly every pull request and someone
#   notices within a day, while dropping `.clippy.toml` skips it only on the rare pull
#   request that edits a lint threshold and changes nothing else.
#
#   Two populations satisfy that criterion, and the gate enumerates both from the git tree
#   rather than from a list someone remembered to add:
#
#     * Every root-level file. A pull request that edits one of these and nothing else is
#       rare, and each one configures a build tool rather than holding source a lane
#       compiles.
#     * Every cargo configuration file, at any depth. Cargo's documented configuration
#       discovery walks from the directory a command runs in up to the filesystem root and
#       reads `.cargo/config.toml` — and the pre-2019 spelling `.cargo/config` — at each
#       step, so each such file in this tree sets rustflags, target settings, or a build
#       target for every cargo command run below it. `.cargo/config.toml` at this
#       repository's root is what selects getrandom's wasm backend, and one commit has
#       ever touched it — the one that created it — which is how it reached no filter and
#       nobody noticed.
#
#   The gate requires each member of both populations to be either routed — matched by an
#   entry of the `rust` filter or of the `toolchain` filter — or named in
#   NO_RUST_JOB_READS below. A file added to either population later is unclassified, and
#   the gate fails until someone decides which it is. That is the property a list of
#   required entries did not have: an entry nobody added was an entry nobody heard about.
#
#   2d — THE FUZZ PIN. `fuzz-build` runs `cargo check` with `working-directory: fuzz`,
#   where rustup resolves `fuzz/rust-toolchain.toml`, so the `fuzz` filter's `fuzz/**`
#   entry is what routes a change to that nightly.
#
#   2e — THE SCRIPTS A FILTERED JOB RUNS. THE CRITERION: a repository script that a
#   paths-filtered job executes is a file whose text decides what that job asserts, so a
#   change to it must make that job run. This is check 2's criterion applied to the one
#   population that closes the loop on itself, because the pull request that edits a gate
#   script is the pull request that has to run the edited gate. When no filter guarding
#   the job lists the script, that pull request leaves every one of those filter outputs
#   'false', the job skips, the `ci` aggregator counts the skip as a pass, and a gate
#   rewritten to `exit 0` merges without executing once. Every later pull request then
#   runs the disabled gate and passes.
#
#   Two jobs held that defect when this check was written. `swift-bindings-fresh` runs
#   `scripts/check-swift-bindings-fresh.sh` behind the `swift` filter, and `python-lint`
#   runs `scripts/check-python-falsy-optionals.py` behind the `python` filter, and
#   neither filter listed any path under `scripts/`.
#
#   HOW THE GATE ENUMERATES THE PAIRS, rather than reading a list someone remembered to
#   add: for each workflow a paths filter guards, it parses that workflow with PyYAML and
#   walks the jobs of the parsed document. For each job whose keys other than `steps` name
#   at least one `needs.changes.outputs.<lane>`, it collects every `scripts/<path>` token
#   the whole job holds. The entries of one of that job's lanes must match each collected
#   path, or the `toolchain` filter every lane ORs in must match it. A job added later that
#   runs a script is covered without anyone editing this file.
#
#   The lanes come from the job's keys other than `steps` because a lane named inside a
#   `run:` script would widen the set of filters this check accepts as routing a path,
#   which weakens it. Reading them from the parsed document rather than from the lines
#   above `steps:` is what makes the collection independent of key order: YAML mapping keys
#   carry no required order, and an `if:` moved below `steps:` left the earlier line
#   matcher collecting no lane at all, which dropped the job from this check entirely. The
#   workflow reader below records that rewording and five more.
#
#   WHAT 2e DOES NOT COVER, stated rather than implied. It reads what the workflow says, so
#   a script a job reaches indirectly — a build tool that shells out to one, a script that
#   sources another — stays invisible to it, and under-detection is its failure mode. It
#   over-detects in three directions deliberately: a `scripts/` path written in a step
#   `name:` or in an environment value, which the job never executes, demands a filter
#   entry; so does one written in a comment inside a `run:` block, which the parser hands
#   over as part of the script the job runs; and so does one a job names while running some
#   other script. Over-detection costs an author one line, and it fails closed.
#   Over-detection costs an author one line, and it fails closed.
#
#   Checks 2c and 2d read `ci.yml` alone, because the `rust` and `fuzz` filters they name
#   live there and guard the jobs that compile from those files. Check 2e reads every
#   paths-filtered workflow, because any one of them can guard a job that runs a script.
#
# An `OK` from check 2 is not a claim that the filters are correct. It says the pin reaches
# every lane of every paths-filtered workflow, that every root-level file and every cargo
# configuration file is classified, and that every script a filtered job runs is routed to
# that job. A `rust` filter stripped of `crates/**` still passes, and it does not need this
# gate: that omission reveals itself.
#
# ── CHECK 3: mise names no Rust version source ───────────────────────────────────────
#
# THE CRITERION. mise exports one `RUSTUP_TOOLCHAIN` for every command it runs, computed
# from the directory the shell sat in, and `RUSTUP_TOOLCHAIN` overrides a
# `rust-toolchain.toml` entirely. This repository resolves two compilers by directory —
# stable for the workspace, the nightly `fuzz/rust-toolchain.toml` names for `fuzz/` — so
# one exported value cannot serve both, and any mise Rust version source puts every command
# in `fuzz/` on the root pin.
#
# A mise configuration file gives its rust tool a version through exactly two mechanisms,
# both defined by mise's own configuration grammar: a `rust` key under the `tools` table,
# and a `rust-toolchain.toml` registered as an idiomatic version file through
# `idiomatic_version_file_enable_tools`. The gate rejects both. rustup installs Rust
# instead, reading the toolchain file of whichever directory a command runs in.
#
# HOW THE GATE ASKS. It parses `.mise.toml` with a TOML parser and reads the parsed
# document, because TOML reaches one key many ways and a line matcher reads one spelling
# per pattern. Measured against mise 2026.2.22, all eight of these resolve `rust` to
# 1.97.1 under `mise current rust`:
#
#     [tools]                  [tools]                              [tools]
#     rust = "1.97.1"          rust = { version = "1.97.1" }        "rust" = "1.97.1"
#
#     [tools.rust]             [tools."rust"]                       [tools]
#     version = "1.97.1"       version = "1.97.1"                   rust.version = "1.97.1"
#
#     tools.rust = "1.97.1"    [tools]
#                              rust = ["1.97.1"]
#
# The `grep -E '^[[:space:]]*"?rust"?[[:space:]]*='` this check ran before matched four of
# the eight and reported OK for the other four, so a mise configuration that did name a
# Rust version passed. Parsing removes the spelling question: every one of the eight puts
# the key `rust` in the table `tools`, and the parsed document answers that in one query.
#
# The parse reads `.mise.toml`, the one mise configuration file this repository tracks, and
# fails when that file is absent.
#
# ── CHECK 4: the workflow's verdict job observes every job in the workflow ───────────
#
# THE CRITERION: a job that reports a workflow's verdict to branch protection must read
# the result of every other job that workflow declares. A result it never reads cannot
# turn it red, so a job left out of its list contributes nothing to the required check.
#
# WHY A MISSING NAME IS INVISIBLE RATHER THAN LOUD. Checks 2a through 2e all rest on one
# fact about the aggregator, stated in their headers: it fails on 'failure' and on
# 'cancelled', and every other result — 'skipped', and the empty string a name no job
# carries evaluates to — passes. That is deliberate for a paths-filtered lane, whose skip
# means the filter matched nothing. It is not deliberate for the job that computes those
# filter outputs. GitHub gives a job whose dependency failed the result 'skipped', so a
# `changes` job that errors — the `dorny/paths-filter` step hitting an API error or a rate
# limit, or a syntax error in the `filters:` block of the pull request under test — skips
# every lane at once, and an aggregator that does not read `needs.changes.result` reads
# nothing but 'skipped' and 'success' and reports green. One failure then silences every
# paths-filtered gate in the workflow while the one required check passes, which is the
# whole-set version of the defect checks 2c and 2e each close one file at a time.
#
# `.github/workflows/ci.yml` held that defect when this check was written: its `ci` job
# named 49 jobs in `needs:` and read the same 49 results, and the workflow declares 52
# jobs. The two it did not name were `check-draft` and `changes` — the upstream of every
# other job in the file.
#
# A name in the aggregator's list that no job carries is the same hole read from the other
# side: `needs.rust-tests.result` for a job named `rust-test` evaluates to the empty
# string, the loop accepts it, and that job's failure never reaches the required check.
# The gate requires set equality in both directions, so neither a missing name nor an
# invented one survives.
#
# WHICH JOB IS THE VERDICT JOB, and how the gate finds it rather than reading a name
# someone remembered to add: a job whose own `if:` expression names one of the four status
# check functions GitHub Actions defines — `success()`, `always()`, `cancelled()`, or
# `failure()`. GitHub Actions applies an implicit `success()` to a job's `if:` unless that
# expression itself names one of the four, so a job that runs after a dependency does not
# succeed names one of them, and a job that names none of them never runs after a
# dependency fails or skips. That set is closed by GitHub's own expression grammar rather
# than by a list of spellings this file keeps: `always()`, `${{ always() }}`,
# `always() && github.event_name == 'push'`, `!cancelled()`, and `!failure()` all select
# the same job. The gate checks every workflow GitHub Actions runs — each tracked `.yml` or
# `.yaml` file under `.github/workflows/`, which leaves a `.disabled` name out — and a
# workflow declaring no such job is silent here. That silence is sound for a deleted
# aggregator: a required check whose job the workflow does not declare never reports, and
# GitHub blocks the merge on a pending required check.
#
# The rule over-detects in one direction deliberately. A job that runs after a failure for
# some other purpose — a step that posts a notification, say — also names one of the four,
# so this check demands that it observe every job of its workflow. That job does report a
# result branch protection can require, and demanding the full list costs its author one
# `needs:` entry per job, while the opposite error hides an aggregator. No workflow in this
# repository declares such a job today, and the two-verdict-job report is what an author
# reads when one appears.
#
# The silence is NOT sound for an aggregator the gate fails to recognise, which is why the
# discovery rule reads the parsed document rather than the file's text. An earlier revision
# required the literal string `always()` and a literal `needs.<name>.result`, and three
# rewordings that leave GitHub's reading of `.github/workflows/ci.yml` unchanged each made
# it find no verdict job and print its OK line: `if: ${{ !cancelled() }}`, a `ci:` header
# carrying a trailing comment, and `${{ join(needs.*.result, ' ') }}` in place of the 51
# per-job result expressions. The workflow reader below records all six rewordings the
# parse closes. An un-gated aggregator looks exactly like a passing one, and so does an
# unread check.
#
# `needs.*.result` reads the result of every job the verdict job's `needs:` names, because
# GitHub Actions expands that object filter over the job's own `needs:` context. The gate
# treats it as naming that whole list, so the `needs:` list stays the one set both
# comparisons run against.
#
# WHAT CHECK 4 DOES NOT COVER, stated rather than implied. It reads which results the
# aggregator's text names, not what its shell does with them. An aggregator that reads
# every result and then discards them all — a loop whose body is `true`, a comparison
# against a value GitHub never produces — satisfies this check. Set equality is the
# property a name-based check can establish, and the loop's own logic is not. That loop
# is seven lines long in `ci.yml`, and it sits in the same step as the list of results
# this check holds complete, so a reader checking one reads the other.
#
# The gate FAILS CLOSED: a missing workflow, a missing filter, a filter with no path
# entries, a `changes` job with no outputs, an empty root-file listing, an undiscoverable
# git tree, a `.mise.toml` no TOML parser accepts, no available TOML parser, a workflow no
# YAML parser accepts, no interpreter that imports PyYAML, and a workflow whose verdict job
# declares an empty `needs:` list are each failures, never skipped checks. See
# `.docs/lessons/coverage-gates-must-fail-closed.md`.
#
# Usage: bash scripts/check-toolchain-wiring.sh
set -euo pipefail

cd "$(dirname "$0")/.."

WORKFLOW_DIR=".github/workflows"
CI_WORKFLOW="$WORKFLOW_DIR/ci.yml"
MISE_CONFIG=".mise.toml"
PIN="rust-toolchain.toml"
TOOLCHAIN_FILTER="toolchain"
# A path cargo reads as configuration. Cargo's documented discovery walks from the
# directory a command runs in up to the filesystem root and reads `.cargo/config.toml` at
# each step; `config` without the extension is the spelling cargo read before 1.39 and
# still accepts.
CARGO_CONFIG_NAME='(^|/)\.cargo/config(\.toml)?$'

fail=0
report() {
    printf 'FAIL: %s\n' "$1" >&2
    fail=1
}

# ── Check 1 ──────────────────────────────────────────────────────────────────────────
#
# The canonical assertion, held here once. A container build must contain it verbatim.
# Changing it means changing this string and every container build in the same commit,
# which is what makes the change deliberate.
read -r -d '' ASSERT_BLOCK <<'BLOCK' || true
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
BLOCK
# The heredoc ends the block with a newline; a container build may end there too, and
# `$(cat …)` drops trailing newlines, so drop it here as well and compare what remains.
ASSERT_BLOCK=${ASSERT_BLOCK%$'\n'}

# Prose holding a container block that the prose tells a reader to save and build. Listing
# a file here claims that Docker builds what it holds, so the file carries the assertion.
read -r -d '' BUILT_FROM_DOCUMENTATION <<'LIST' || true
templates/personal-relay/README.md
LIST

# Prose that quotes a container build nobody builds. Listing a file here claims that no
# Docker build reads it, so the file carries no assertion.
read -r -d '' QUOTES_A_CONTAINER_BUILD <<'LIST' || true
scripts/tests/toolchain-wiring/run-tests.sh
LIST

# A `FROM` line naming a `rust` base image, matched against Dockerfile's own grammar for
# the instruction: `FROM [--flag=value]… <image>[:<tag>|@<digest>] [AS <name>]`, and
# nothing after the optional stage name but the end of the line. The keyword opens a line
# apart from leading whitespace, in either case, because Docker accepts both. A stage name
# does not match, because `FROM chef AS builder` names no image whose compiler to pin.
#
# The end-of-line anchor is what keeps an English sentence out. Docker's FROM instruction
# permits nothing after the image reference except `AS <name>`, so a line reading
# "from rust sources by uniffi." cannot be a FROM instruction, and an earlier revision of
# this expression matched it: it ended at `([[:space:]]|$)`, which accepted any text after
# the image. The phrase "from Rust" opens a sentence in fifteen tracked files, and where a
# Markdown paragraph wraps decides whether one of them starts a line, so that revision
# failed `enforcement / toolchain wiring` — the check every pull request runs — on a
# reflowed paragraph. Narrowing the expression to the instruction's grammar drops no
# container build, because a container build's FROM line follows that grammar.
#
# The remaining false-positive shape, stated rather than implied: a sentence whose line
# reads "from rust as <word>" and ends there matches, because that text is also a valid
# FROM instruction. Its author lists the file in QUOTES_A_CONTAINER_BUILD.
FROM_RUST_IMAGE='^[[:space:]]*FROM[[:space:]]+(--[a-zA-Z-]+=[^[:space:]]+[[:space:]]+)*([a-z0-9._:-]+/)*rust(:[^[:space:]]+|@[a-z0-9]+:[a-fA-F0-9]+)?([[:space:]]+AS[[:space:]]+[A-Za-z0-9._-]+)?[[:space:]]*$'

# The names `docker build` reads: its default, and the two conventional spellings `-f`
# names. Podman reads the `Containerfile` spellings, and `docker build -f` accepts them.
docker_builds_by_name() {
    case ${1##*/} in
        Dockerfile | Dockerfile.* | *.Dockerfile) return 0 ;;
        Containerfile | Containerfile.* | *.Containerfile) return 0 ;;
        *) return 1 ;;
    esac
}

# A file Docker builds carries the block when it names a `rust` base image, and carries no
# assertion otherwise: a runtime-only build runs no rustc, so the assertion would fail it.
require_assertion() {
    local f=$1 file_text
    if ! grep -qiE "$FROM_RUST_IMAGE" "$f"; then
        return 0
    fi
    # A byte-for-byte substring test over the whole file, so the block's three lines match
    # in order and unbroken. `grep -F` cannot do this: it splits a pattern holding newlines
    # into one pattern per line and matches when ANY of them matches, so a file keeping a
    # single line of the block — or all three lines reversed — satisfies it. Measured on
    # GNU grep 3.12, BSD grep 2.6.0-FreeBSD, and ugrep 7.8.4, with and without `-z`.
    file_text=$(cat "$f")
    if [[ $file_text != *"$ASSERT_BLOCK"* ]]; then
        report "$f builds from a 'rust' base image and does not carry the ASSERT-PINNED-RUSTC block verbatim, so its build never checks which compiler the image resolved. Copy the block from $PIN's own consumer, the root Dockerfile, or from the ASSERT_BLOCK definition in this gate."
    fi
}

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    report "not inside a git working tree, so the gate cannot enumerate the files Docker builds"
else
    # A quotation entry whose basename Docker builds contradicts the name rule, and it
    # would exempt a real container build from the assertion.
    while IFS= read -r quoted; do
        [[ -n $quoted ]] || continue
        if docker_builds_by_name "$quoted"; then
            report "QUOTES_A_CONTAINER_BUILD in this gate lists $quoted, whose basename is a name Docker builds. A container build cannot be declared a quotation of one. Delete the entry, and copy the ASSERT-PINNED-RUSTC block into that file."
        fi
    done <<< "$QUOTES_A_CONTAINER_BUILD"

    # `--others` matters: a container build added but not yet committed is exactly the case
    # a pre-push run has to catch, and `--cached` alone lists only what the index holds.
    tree_files=$(git ls-files --cached --others --exclude-standard 2>/dev/null || true)
    if [[ -z $tree_files ]]; then
        report "git listed no files, so the gate cannot enumerate the files Docker builds"
    else
        while IFS= read -r f; do
            [[ -n $f ]] || continue
            [[ -f $f ]] || continue
            if docker_builds_by_name "$f"; then
                require_assertion "$f"
            fi
        done <<< "$tree_files"
    fi

    while IFS= read -r doc; do
        [[ -n $doc ]] || continue
        [[ -f $doc ]] || continue
        require_assertion "$doc"
    done <<< "$BUILT_FROM_DOCUMENTATION"

    # The classification search: every remaining file holding a `FROM` line that names a
    # rust image is one the author has to classify.
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        if docker_builds_by_name "$f"; then continue; fi
        if grep -qxF -- "$f" <<< "$BUILT_FROM_DOCUMENTATION"; then continue; fi
        if grep -qxF -- "$f" <<< "$QUOTES_A_CONTAINER_BUILD"; then continue; fi
        report "$f holds a FROM line naming a 'rust' base image, and neither list in this gate classifies it. When Docker builds what this file holds — directly, or because the text tells a reader to save the block and build it — list it in BUILT_FROM_DOCUMENTATION and copy the ASSERT-PINNED-RUSTC block into it. When the text only quotes a container build for a reader, list it in QUOTES_A_CONTAINER_BUILD."
    done < <(git grep -l --untracked -iE "$FROM_RUST_IMAGE" -- . || true)
fi

# ── Check 2 ──────────────────────────────────────────────────────────────────────────
#
# Files that no job in `ci.yml` reads while it compiles anything. Every other file check 2c
# enumerates — every root-level file, and every cargo configuration file at any depth —
# must be routed by the `rust` filter or by the `toolchain` filter. Adding a file here is a
# claim that changing it cannot change what any compile produces, and the gate takes that
# claim at face value — it is the one judgement this check cannot make.
NO_RUST_JOB_READS=(
    # Documentation and licensing. No job compiles from them.
    "CHANGELOG.md"
    "CLAUDE.md"
    "CONTRIBUTING.md"
    "GETTING-STARTED.md"
    "LICENSE"
    "LICENSE-AGPL"
    "LICENSE-APACHE"
    "LICENSING.md"
    "README.md"
    "TESTING.md"
    # Local developer tooling. No CI job installs mise or runs docker compose; the
    # `docker-image` job builds `Dockerfile` directly.
    ".gitignore"
    ".mise.toml"
    "docker-compose.yml"
)

# Print the path entries of one filter, one per line.
#
# The filter block is a YAML literal scalar inside ci.yml, so read it as text: start at a
# line holding nothing but `<name>:`, take the `- <path>` lines that follow, skip comment
# and blank lines, and stop at the first line that is none of those. Each filter name
# appears exactly once in that form, because the `outputs:` block writes
# `rust: ${{ ... }}` with a value on the same line.
#
# The `sed` accepts the three ways YAML spells a scalar in a sequence — plain,
# single-quoted, double-quoted — and nothing else. An entry written in a fourth way, such
# as a flow sequence on the `<name>:` line, yields no path, and the caller then reports
# the filter as carrying none, which fails the gate rather than passing it.
filter_entries() {
    local wf=$1 name=$2
    awk -v key="$name" '
        $0 ~ "^[[:space:]]*" key ":[[:space:]]*$" { inblock = 1; next }
        inblock == 1 {
            if ($0 ~ /^[[:space:]]*#/) next
            if ($0 ~ /^[[:space:]]*$/) next
            if ($0 ~ /^[[:space:]]*-[[:space:]]/) { print; next }
            exit
        }
    ' "$wf" | sed -nE "s/^[[:space:]]*-[[:space:]]*[\"']?([^\"']*)[\"']?[[:space:]]*$/\1/p"
}

# Answer whether one path entry list routes one path.
#
# dorny/paths-filter matches an entry with picomatch, and this gate reimplements two of
# picomatch's shapes rather than its grammar: an entry that names the path exactly, and an
# entry `<prefix>/**`, which picomatch matches against every path under `<prefix>/`. Those
# are the two shapes the `rust` and `toolchain` filters use for the files check 2c
# enumerates. An entry written any other way routes nothing here, so a filter that reaches a
# file only through a third shape fails this gate rather than passing it, and its author
# writes the file's path or its directory prefix out.
#
# The `<prefix>/**` rule holds for a path whose later segments begin with a dot, such as
# `crates/scp-mls/.cargo/config.toml`, only because the action enables picomatch's `dot`
# option: `src/filter.ts` on the v3 tag defines `const MatchOptions = { dot: true }` and
# passes it to every `picomatch(...)` call it makes. Measured against picomatch 4.0.3,
# `crates/**` matches that path under `dot: true` and does not match it under picomatch's
# default. Should a future version of the action drop that option, this helper reports a
# nested cargo configuration file as routed while the filter skips it.
routed_by() {
    local path=$1 entries=$2 entry prefix
    while IFS= read -r entry; do
        [[ -n $entry ]] || continue
        if [[ $entry == "$path" ]]; then return 0; fi
        if [[ $entry == */'**' ]]; then
            prefix=${entry%'**'}
            if [[ $path == "$prefix"* ]]; then return 0; fi
        fi
    done <<< "$entries"
    return 1
}

# Print `<output name>=<expression>` for every output the `changes` job declares.
#
# Scoped to that job: start at its header, stop at the next job header, and read the lines
# of its `outputs:` mapping. Reading the names out of the workflow is what makes check 2b
# closed by construction — a lane added later declares an output here, and the gate then
# requires that output to route the pin without anyone editing this file.
changes_job_outputs() {
    local wf=$1
    awk '
        /^  changes:[[:space:]]*$/ { injob = 1; next }
        injob && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ { exit }
        injob && /^    outputs:[[:space:]]*$/ { inoutputs = 1; next }
        inoutputs {
            if ($0 ~ /^[[:space:]]*#/) next
            if ($0 ~ /^[[:space:]]*$/) next
            if ($0 ~ /^      [A-Za-z0-9_.-]+:[[:space:]]*\$\{\{/) { print; next }
            exit
        }
    ' "$wf" | sed -E 's/^[[:space:]]*([A-Za-z0-9_.-]+):[[:space:]]*(.*)$/\1=\2/'
}

# Print every workflow whose jobs a paths filter guards.
#
# GitHub Actions runs a file under `.github/workflows/` whose extension is `.yml` or
# `.yaml`, so a name ending `.disabled` starts nothing and this listing leaves it out. A
# workflow that declares a `dorny/paths-filter` step is one whose jobs skip on a filter
# result, which is the shape check 2a and check 2b read.
#
# `--others` matters for the same reason it does in check 1: a workflow added but not yet
# committed is what a pre-push run has to cover.
paths_filter_workflows() {
    local wf
    while IFS= read -r wf; do
        [[ -n $wf ]] || continue
        [[ -f $wf ]] || continue
        case $wf in
            *.yml | *.yaml) ;;
            *) continue ;;
        esac
        if grep -q 'dorny/paths-filter' "$wf"; then
            printf '%s\n' "$wf"
        fi
    done < <(git ls-files --cached --others --exclude-standard -- "$WORKFLOW_DIR" 2>/dev/null || true)
}

# 2a and 2b for one workflow: its `toolchain` filter holds the pin, and every output of its
# `changes` job ORs that filter in.
check_pin_reaches_every_lane() {
    local wf=$1 entries outputs line output_name output_expr

    # 2a — one filter holds the pin.
    entries=$(filter_entries "$wf" "$TOOLCHAIN_FILTER")
    if [[ -z $entries ]]; then
        report "$wf declares no '$TOOLCHAIN_FILTER:' paths filter with path entries, so nothing routes a change to $PIN"
    elif ! grep -qxF -- "$PIN" <<< "$entries"; then
        report "$wf: the '$TOOLCHAIN_FILTER' paths filter does not list $PIN, so a pull request that raises the pin and changes nothing else leaves every filter output 'false' and every job those filters guard skips, which each status check reports as a pass"
    fi

    # 2b — every lane's output ORs that filter in.
    outputs=$(changes_job_outputs "$wf")
    if [[ -z $outputs ]]; then
        report "$wf: the 'changes' job declares no outputs, so the gate cannot check that a pin change reaches every lane"
        return 0
    fi
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        output_name=${line%%=*}
        output_expr=${line#*=}
        # `fuzz` is the one lane the pin does not decide: `fuzz-build` runs
        # `cargo check` with `working-directory: fuzz`, where rustup resolves
        # `fuzz/rust-toolchain.toml` instead. Check 2d covers that file.
        if [[ $output_name == "fuzz" || $output_name == "$TOOLCHAIN_FILTER" ]]; then
            continue
        fi
        if [[ $output_expr != *"steps.filter.outputs.$TOOLCHAIN_FILTER"* ]]; then
            report "$wf: the 'changes' job's '$output_name' output does not read steps.filter.outputs.$TOOLCHAIN_FILTER, so a pull request that raises the pin skips every job that output guards, which each status check reports as a pass"
        fi
    done <<< "$outputs"
}

# ── The workflow reader ──────────────────────────────────────────────────────────────
#
# Checks 2e and 4 ask six questions about a workflow's jobs: which jobs the workflow
# declares, what each job's `if:` says, which jobs the `needs:` of one job names, which
# `needs.changes.outputs.<lane>` a job reads outside its steps, which `scripts/…` paths a
# job names, and which `needs.<job>.result` expressions a job holds. An interpreter that
# parses the file with PyYAML answers all six from the parsed document, and the program
# below prints those answers as one tab-separated fact per line.
#
# WHY A PARSER RATHER THAN A LINE MATCHER. YAML reaches one key many ways, and a line
# matcher reads one spelling per pattern, so an author who rewords a workflow without
# changing what GitHub Actions reads makes the matcher find nothing — and a check that
# finds nothing reports nothing. Check 3 made this same move for TOML, after a
# `grep -E` matched four of the eight spellings mise resolves. The awk this program
# replaces missed each of the six rewordings below, and GitHub Actions runs a workflow
# carrying any of them exactly as it runs the spelling the awk did match:
#
#   * `if: ${{ !cancelled() }}` in place of `if: always()`. GitHub Actions runs a job
#     guarded by `!cancelled()` after a dependency fails, exactly as it runs one guarded
#     by `always()`, so that aggregator still reports its result to branch protection.
#   * A job-level `if:` key written below that job's `steps:` key. YAML mapping keys carry
#     no required order, and check 2e collected a job's lanes only from the lines above
#     `steps:`.
#   * A job header carrying a trailing comment, `  ci:  # the verdict job`. The job
#     listing dropped that job, so nothing held the aggregator to naming it and nothing
#     recognised it as the aggregator.
#   * A job header or a job key written in quotes: `  "ci":`, or `  "if": always()`.
#   * A job whose own keys sit at six spaces of indentation rather than four.
#   * `${{ join(needs.*.result, ' ') }}` in place of one `${{ needs.<job>.result }}`
#     expression per job. GitHub Actions expands that object filter over the job's `needs:`
#     context, so the aggregator reads the same results.
#
# Each of those is one spelling, and one pattern per spelling never closes the set. PyYAML
# resolves all six to the same document, which removes the spelling question.
#
# WHAT THE PROGRAM PRINTS. One fact per line, fields separated by a tab:
#
#   job<TAB><job>                 — the workflow declares this job.
#   if<TAB><job><TAB><expression> — this job declares this `if:` value.
#   needs<TAB><job><TAB><name>    — this job's `needs:` names this other job.
#   lane<TAB><job><TAB><lane>     — a key of this job other than `steps` reads
#                                   `needs.changes.outputs.<lane>`.
#   script<TAB><job><TAB><path>   — this job names this `scripts/…` path.
#   result<TAB><job><TAB><name>   — this job reads `needs.<name>.result`; the name `*`
#                                   stands for the object filter `needs.*.result`.
#
# The lanes come from every key of the job except `steps`, which is the scope check 2e's
# criterion asks for: a lane named inside a `run:` script would widen the set of filters
# that check accepts as routing a path, which weakens it. The script paths come from the
# whole job, its steps included, because a step is what runs a script. PyYAML drops
# comments, so a comment naming a script the job never runs demands no filter entry, and
# this repository's `changes` job carries such comments.
#
# A `needs:` value that is neither a string nor a sequence yields no `needs` fact, and
# check 4 then reports that verdict job as declaring no `needs:` the gate can read, which
# fails the gate rather than passing it.
read -r -d '' WORKFLOW_FACTS_PROGRAM <<'PYTHON' || true
import re
import sys

import yaml

LANE = re.compile(r"needs\.changes\.outputs\.([A-Za-z0-9_-]+)")
SCRIPT = re.compile(r"scripts/[A-Za-z0-9_./-]+")
RESULT = re.compile(r"needs\.(\*|[A-Za-z0-9_.-]+)\.result")


def emit(*fields):
    print("\t".join(field.replace("\t", " ").replace("\n", " ") for field in fields))


# `width` disables the line wrapping `safe_dump` applies by default, which would otherwise
# split a long `scripts/…` path across two lines and hide it from the search below.
def render(value):
    return yaml.safe_dump(value, default_flow_style=False, allow_unicode=True, width=10**9)


try:
    with open(sys.argv[1], "rb") as handle:
        document = yaml.safe_load(handle)
except (OSError, yaml.YAMLError) as error:
    print(error, file=sys.stderr)
    sys.exit(2)

jobs = document.get("jobs") if isinstance(document, dict) else None
if not isinstance(jobs, dict):
    sys.exit(0)

for name, job in jobs.items():
    name = str(name)
    emit("job", name)
    if not isinstance(job, dict):
        continue
    condition = job.get("if")
    if condition is not None:
        emit("if", name, str(condition))
    needs = job.get("needs")
    if isinstance(needs, str):
        needs = [needs]
    if isinstance(needs, (list, tuple)):
        for dependency in needs:
            emit("needs", name, str(dependency))
    outside_steps = render({key: value for key, value in job.items() if key != "steps"})
    whole = render(job)
    for lane in dict.fromkeys(LANE.findall(outside_steps)):
        emit("lane", name, lane)
    for script in dict.fromkeys(SCRIPT.findall(whole)):
        emit("script", name, script)
    for result in dict.fromkeys(RESULT.findall(whole)):
        emit("result", name, result)
PYTHON

# The first interpreter that imports PyYAML. When no candidate imports it, every check
# that reads a workflow's jobs fails rather than skipping.
yaml_reader=""
for candidate in python3.12 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import yaml' >/dev/null 2>&1; then
        yaml_reader=$candidate
        break
    fi
done

# Print one workflow's facts. Exit 1 with the reason on stdout when the gate cannot read
# them; the caller reports that reason. `report` assigns a variable, so no caller runs it
# inside a command substitution, where the assignment would be lost.
workflow_facts() {
    if [[ -z $yaml_reader ]]; then
        printf 'no python3.12, python3, or python on PATH imports yaml. PyYAML is what this gate parses a workflow with, and the toolchain-wiring job installs it before running this gate.\n'
        return 1
    fi
    "$yaml_reader" -c "$WORKFLOW_FACTS_PROGRAM" "$1" 2>&1 || return 1
}

# Print the values of one job's facts of one kind, one per line.
job_facts() {
    local kind=$1 job=$2
    awk -F'\t' -v kind="$kind" -v job="$job" '$1 == kind && $2 == job { print $3 }'
}

# The opening clause of every report a workflow this gate cannot read produces.
wf_read_failure_prefix="the gate cannot read the jobs of"

# 2e for one workflow: every script a paths-filtered job runs is routed to that job.
check_filtered_jobs_route_their_scripts() {
    local wf=$1 facts=$2 wf_toolchain_entries job lanes script lane entries routed
    wf_toolchain_entries=$(filter_entries "$wf" "$TOOLCHAIN_FILTER")
    while IFS= read -r job; do
        [[ -n $job ]] || continue
        lanes=$(job_facts lane "$job" <<< "$facts" | paste -sd' ' -)
        # A job no paths filter guards names no lane, and check 2e binds the filtered jobs.
        [[ -n $lanes ]] || continue
        while IFS= read -r script; do
            [[ -n $script ]] || continue
            routed=0
            # Every lane ORs the `toolchain` filter in — check 2b is what holds that — so a
            # path listed there routes to every filtered job of the workflow.
            if [[ -n $wf_toolchain_entries ]] && routed_by "$script" "$wf_toolchain_entries"; then
                routed=1
            fi
            if [[ $routed -eq 0 ]]; then
                # The job runs when ANY lane its `if:` names is true, so ONE lane listing
                # the path is enough to make a change to that path run the job.
                for lane in $lanes; do
                    entries=$(filter_entries "$wf" "$lane")
                    if [[ -n $entries ]] && routed_by "$script" "$entries"; then
                        routed=1
                        break
                    fi
                done
            fi
            if [[ $routed -eq 0 ]]; then
                report "$wf: the '$job' job names $script, and none of the paths filters that guard it ($lanes) lists that path. A pull request that changes only $script leaves every one of those filter outputs 'false', '$job' skips, and the 'ci' aggregator job counts the skip as a pass — so the pull request that edits the script is the one that never runs it. List $script in one of those filters."
            fi
        done < <(job_facts script "$job" <<< "$facts")
    done < <(awk -F'\t' '$1 == "job" { print $2 }' <<< "$facts")
}
# 2a/2b — over every workflow a paths filter guards, `ci.yml` among them.
filtered_workflows=$(paths_filter_workflows)
if [[ -z $filtered_workflows ]]; then
    report "no workflow under $WORKFLOW_DIR/ declares a dorny/paths-filter step, so the gate cannot check that a change to $PIN reaches the jobs that compile on it"
else
    while IFS= read -r workflow; do
        [[ -n $workflow ]] || continue
        check_pin_reaches_every_lane "$workflow"
        # 2e — every script a paths-filtered job of this workflow runs is routed to it.
        if workflow_jobs=$(workflow_facts "$workflow"); then
            check_filtered_jobs_route_their_scripts "$workflow" "$workflow_jobs"
        else
            report "$wf_read_failure_prefix $workflow, so the gate cannot check that every script its paths-filtered jobs run is routed to those jobs: $workflow_jobs"
        fi
    done <<< "$filtered_workflows"
fi

# 2c/2d — the `rust` and `fuzz` filters, which live in `ci.yml` and guard the jobs that
# compile from the files those checks enumerate.
if [[ ! -f $CI_WORKFLOW ]]; then
    report "$CI_WORKFLOW does not exist, so the gate cannot check that the paths filters route a change to the jobs that build from it"
else
    toolchain_entries=$(filter_entries "$CI_WORKFLOW" "$TOOLCHAIN_FILTER")

    # 2c — every root-level file and every cargo configuration file is routed or declared
    # unread.
    rust_entries=$(filter_entries "$CI_WORKFLOW" "rust")
    if [[ -z $rust_entries ]]; then
        report "$CI_WORKFLOW declares no 'rust:' paths filter with path entries, so the gate cannot check which build-configuration files it routes"
    else
        tracked_files=$(git ls-files --cached --others --exclude-standard 2>/dev/null || true)
        root_files=$(grep -v '/' <<< "$tracked_files" || true)
        cargo_config_files=$(grep -E "$CARGO_CONFIG_NAME" <<< "$tracked_files" || true)
        if [[ -z $root_files ]]; then
            report "git listed no root-level files, so the gate cannot check that each build-configuration file is routed to a lane or declared unread"
        else
            while IFS= read -r build_file; do
                [[ -n $build_file ]] || continue
                if routed_by "$build_file" "$rust_entries"; then continue; fi
                if routed_by "$build_file" "$toolchain_entries"; then continue; fi
                declared=0
                for unread in "${NO_RUST_JOB_READS[@]}"; do
                    if [[ $build_file == "$unread" ]]; then
                        declared=1
                        break
                    fi
                done
                if [[ $declared -eq 1 ]]; then continue; fi
                # Name which population put the file in front of the reader. A file can be
                # in both, and the cargo sentence is the one that explains the reach.
                if grep -qE "$CARGO_CONFIG_NAME" <<< "$build_file"; then
                    population="is a cargo configuration file, which cargo reads for every command run below its directory, and"
                else
                    population="sits at the repository root and"
                fi
                report "$build_file $population neither the 'rust' filter nor the '$TOOLCHAIN_FILTER' filter in $CI_WORKFLOW routes it, and NO_RUST_JOB_READS in this gate does not declare it unread. A pull request that changes only that file leaves the filter output 'false', every job the filter guards skips, and the 'ci' aggregator job counts a skipped job as a pass. List it in the filter that guards the jobs it decides, or declare it in NO_RUST_JOB_READS."
            done <<< "$(printf '%s\n%s\n' "$root_files" "$cargo_config_files" | sed '/^$/d' | sort -u)"
        fi
    fi

    # 2d — the fuzz nightly reaches the job that compiles on it.
    fuzz_entries=$(filter_entries "$CI_WORKFLOW" "fuzz")
    if [[ -z $fuzz_entries ]]; then
        report "$CI_WORKFLOW declares no 'fuzz:' paths filter with path entries, so nothing routes a change to fuzz/$PIN"
    elif ! grep -qxF -- 'fuzz/**' <<< "$fuzz_entries"; then
        report "$CI_WORKFLOW: the 'fuzz' paths filter does not list fuzz/**, so a pull request that raises the nightly in fuzz/$PIN skips 'fuzz-build', the one job that compiles on it, and the 'ci' aggregator job counts the skip as a pass"
    fi
fi

# ── Check 3 ──────────────────────────────────────────────────────────────────────────

# The program that reads the parsed mise configuration. It prints one line per Rust
# version source it finds — `tools` for a `rust` key under the `tools` table, `idiomatic`
# for `rust` in `idiomatic_version_file_enable_tools` — and nothing when the document names
# neither. A document no TOML parser accepts exits 2 with the parser's message, which the
# caller reports rather than passing over.
#
# mise reads `idiomatic_version_file_enable_tools` as a setting, and TOML lets a document
# put a setting at the top level or under a `settings` table, so the program reads both
# placements.
read -r -d '' MISE_RUST_SOURCE_PROGRAM <<'PYTHON' || true
import sys
import tomllib

try:
    with open(sys.argv[1], "rb") as handle:
        document = tomllib.load(handle)
except (OSError, tomllib.TOMLDecodeError) as error:
    print(error, file=sys.stderr)
    sys.exit(2)

tools = document.get("tools")
if isinstance(tools, dict) and "rust" in tools:
    print("tools")

for table in (document, document.get("settings")):
    if not isinstance(table, dict):
        continue
    enabled = table.get("idiomatic_version_file_enable_tools")
    if isinstance(enabled, (list, tuple)) and "rust" in enabled:
        print("idiomatic")
        break
PYTHON

# The first interpreter that ships `tomllib`, which the Python standard library has held
# since 3.11. When no candidate imports it, this check fails rather than skipping.
toml_reader=""
for candidate in python3.12 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import tomllib' >/dev/null 2>&1; then
        toml_reader=$candidate
        break
    fi
done

if [[ ! -f $MISE_CONFIG ]]; then
    report "$MISE_CONFIG does not exist, so the gate cannot check that mise names no Rust version source"
elif [[ -z $toml_reader ]]; then
    report "no python3.12, python3, or python on PATH imports tomllib, so the gate cannot parse $MISE_CONFIG to check that mise names no Rust version source. tomllib has been in the Python standard library since 3.11; install Python 3.12, which .mise.toml already names."
else
    # The program merges its stderr into its stdout, so a non-zero exit carries the
    # parser's own message and the caller quotes it.
    if mise_rust_sources=$("$toml_reader" -c "$MISE_RUST_SOURCE_PROGRAM" "$MISE_CONFIG" 2>&1); then
        if grep -qxF -- 'tools' <<< "$mise_rust_sources"; then
            report "$MISE_CONFIG gives the rust tool a version: its 'tools' table holds a 'rust' key. mise then exports RUSTUP_TOOLCHAIN with that version for every command it runs, which overrides fuzz/$PIN and puts 'cd fuzz && cargo fuzz run <target>' on the workspace's stable compiler, where cargo-fuzz's -Z flags are rejected. Delete the key and let rustup read the toolchain file of each directory."
        fi
        if grep -qxF -- 'idiomatic' <<< "$mise_rust_sources"; then
            report "$MISE_CONFIG registers rust-toolchain.toml as a mise version source through idiomatic_version_file_enable_tools. mise then exports RUSTUP_TOOLCHAIN with the channel it read, which overrides fuzz/$PIN and puts 'cd fuzz && cargo fuzz run <target>' on the workspace's stable compiler, where cargo-fuzz's -Z flags are rejected. Delete 'rust' from that setting and let rustup read the toolchain file of each directory."
        fi
    else
        report "$MISE_CONFIG is not a TOML document tomllib accepts, so the gate cannot check whether mise names a Rust version source: $mise_rust_sources"
    fi
fi

# ── Check 4 ──────────────────────────────────────────────────────────────────────────

# Print every workflow GitHub Actions runs.
#
# `--others` matters for the same reason it does in checks 1 and 2: a workflow added but
# not yet committed is what a pre-push run has to cover.
runnable_workflows() {
    local wf
    while IFS= read -r wf; do
        [[ -n $wf ]] || continue
        [[ -f $wf ]] || continue
        case $wf in
            *.yml | *.yaml) printf '%s\n' "$wf" ;;
        esac
    done < <(git ls-files --cached --others --exclude-standard -- "$WORKFLOW_DIR" 2>/dev/null || true)
}

# The four status check functions GitHub Actions defines, matched as whole identifiers
# followed by their call parentheses.
#
# This set is what makes the verdict-job discovery closed by construction rather than a
# list of spellings. GitHub Actions applies an implicit `success()` to a job's `if:` unless
# that expression itself names a status check function, and it defines exactly four of
# them: `success()`, `always()`, `cancelled()`, and `failure()`. A job that runs after a
# dependency does not succeed therefore names one of the four — `always()`, `!cancelled()`,
# `!failure()`, and `!success()` all do — and a job that names none of the four never runs
# after a dependency fails or skips, so it reports no verdict on that dependency.
STATUS_CHECK_FUNCTION='(^|[^A-Za-z0-9_-])(success|always|cancelled|failure)[[:space:]]*\('

# Print the lines of stdin that hold a non-blank name, sorted and deduplicated.
#
# `comm` compares sorted lists line by line, and a blank line is a line, so a list that
# carries one compares as a member named "". Every set below passes through here, which
# keeps that member out and gives `comm` the sorted input it requires. `|| true` covers
# an empty list: `grep` exits 1 when it matches nothing, and this gate runs under
# `set -e`.
name_set() {
    grep -v '^[[:space:]]*$' | sort -u || true
}

# One workflow: its verdict job, when it declares one, reads every other job's result.
check_verdict_job_observes_every_job() {
    local wf=$1 facts=$2 job condition needs_names result_names all_names others verdict=""
    local missing_needs missing_results unknown_needs unknown_results

    all_names=$(awk -F'\t' '$1 == "job" { print $2 }' <<< "$facts")
    [[ -n $all_names ]] || return 0

    while IFS= read -r job; do
        [[ -n $job ]] || continue
        condition=$(job_facts if "$job" <<< "$facts")
        [[ -n $condition ]] || continue
        grep -qE "$STATUS_CHECK_FUNCTION" <<< "$condition" || continue
        if [[ -n $verdict ]]; then
            report "$wf declares two jobs whose 'if:' names one of GitHub Actions' status check functions — '$verdict' and '$job'. Each of them runs after a dependency does not succeed, so each can report a verdict to branch protection, and this gate cannot tell which one branch protection requires. Leave one such job in the workflow."
            return 0
        fi
        verdict=$job
    done <<< "$all_names"

    # No verdict job is not a defect: a required check whose job the workflow never
    # declares stays pending, and GitHub blocks the merge on a pending required check.
    [[ -n $verdict ]] || return 0

    needs_names=$(job_facts needs "$verdict" <<< "$facts")
    if [[ -z $needs_names ]]; then
        report "$wf: the verdict job '$verdict' declares no 'needs:' this gate can read, so nothing holds it to the jobs of this workflow. Write the list as a sequence or as a single job name."
        return 0
    fi
    needs_names=$(name_set <<< "$needs_names")
    result_names=$(job_facts result "$verdict" <<< "$facts")
    if grep -qxF -- '*' <<< "$result_names"; then
        # GitHub Actions expands the object filter `needs.*.result` over the job's own
        # `needs:` context, so that one expression reads the result of every job the
        # `needs:` list names, and the comparison below is against that list.
        result_names=$needs_names
    else
        result_names=$(name_set <<< "$result_names")
    fi
    # A workflow whose only job is the verdict job leaves this empty, and every name that
    # job reads is then unknown, which the two unknown-name reports below state.
    others=$({ grep -vxF -- "$verdict" <<< "$all_names" || true; } | name_set)

    missing_needs=$(comm -23 <(printf '%s\n' "$others") <(printf '%s\n' "$needs_names") | paste -sd' ' -)
    missing_results=$(comm -23 <(printf '%s\n' "$others") <(printf '%s\n' "$result_names") | paste -sd' ' -)
    unknown_needs=$(comm -13 <(printf '%s\n' "$others") <(printf '%s\n' "$needs_names") | paste -sd' ' -)
    unknown_results=$(comm -13 <(printf '%s\n' "$others") <(printf '%s\n' "$result_names") | paste -sd' ' -)

    if [[ -n $missing_needs ]]; then
        report "$wf: the verdict job '$verdict' does not name these jobs in its 'needs:' — $missing_needs. GitHub gives a job whose dependency failed the result 'skipped', and '$verdict' passes on 'skipped', so a failure in a job it does not name reaches the required check as green. Add each name to 'needs:' and read its result."
    fi
    if [[ -n $missing_results ]]; then
        report "$wf: the verdict job '$verdict' never reads the result of these jobs — $missing_results. A result it does not read cannot turn it red, so those jobs contribute nothing to the required check. Read \"\${{ needs.<job>.result }}\" for each one."
    fi
    if [[ -n $unknown_needs ]]; then
        report "$wf: the verdict job '$verdict' names these in its 'needs:' and this workflow declares no job by those names — $unknown_needs. Correct each name to the job it meant."
    fi
    if [[ -n $unknown_results ]]; then
        report "$wf: the verdict job '$verdict' reads 'needs.<job>.result' for these names and this workflow declares no job by them — $unknown_results. Such an expression evaluates to the empty string, which '$verdict' accepts, so the job it meant to read reaches the required check as green. Correct each name to the job it meant."
    fi
}
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    report "not inside a git working tree, so the gate cannot enumerate the workflows whose verdict job must observe every job"
else
    runnable=$(runnable_workflows)
    if [[ -z $runnable ]]; then
        report "no file under $WORKFLOW_DIR has an extension GitHub Actions runs, so the gate cannot check that a workflow's verdict job observes every job that workflow declares"
    else
        while IFS= read -r workflow_file; do
            [[ -n $workflow_file ]] || continue
            if workflow_jobs=$(workflow_facts "$workflow_file"); then
                check_verdict_job_observes_every_job "$workflow_file" "$workflow_jobs"
            else
                report "$wf_read_failure_prefix $workflow_file, so the gate cannot check that its verdict job observes every job it declares: $workflow_jobs"
            fi
        done <<< "$runnable"
    fi
fi

if [[ $fail -eq 0 ]]; then
    printf 'OK: every container build asserts it resolved the compiler %s names\n' "$PIN"
    printf 'OK: every lane of every paths-filtered workflow routes a %s change, every root-level file and cargo configuration file is routed or declared unread, and every script a paths-filtered job runs is routed to that job\n' "$PIN"
    printf 'OK: %s names no Rust version source, so rustup resolves each directory from its own toolchain file\n' "$MISE_CONFIG"
    printf "OK: every workflow's verdict job reads the result of every job that workflow declares\n"
    exit 0
fi
exit 1
