#!/usr/bin/env python3
"""Self-test for a CI gate: workflow structure, plus an aggregate's verdict.

Every assertion here corresponds to a defect where a check ran and enforced
nothing:

  timeout      No job set `timeout-minutes`, so a hung job burned a 360-minute
               per-job runner ceiling.
  coverage     Three enforcement jobs (pyi-generated, construction-pattern,
               block-in-place) were not dependencies of `ci`, one required
               status check, so their failures never blocked a merge.
  skip         An aggregate compared results against "failure" and "cancelled"
               only, so a skipped dependency and a passing dependency produced
               one verdict.
  rust-fanout  Filters named python, typescript, kotlin and swift listed only
               bindings plus their own bridge directory, so a pull request
               touching crates/scp-runtime/ alone skipped all four test jobs.
  zero-test    `cargo test <filter>` exits 0 when a filter selects no test, so
               a fail-closed lane reported success over zero assertions.
  scaled-input Two fuzz jobs pass a workflow_dispatch input to libFuzzer as
               `-max_total_time`, so an operator sets how long they run. A
               budget fixed above a scheduled run cancelled every dispatch
               asking for longer, killing a run that previously completed.
  filter-key   An aggregate read an absent `needs.changes.outputs.<key>` as "",
               which compares unequal to every literal, so one renamed filter
               held a job at `skipped` forever under a green required check.
  action-ref   fuzz.yml named `dtolnay/rust-toolchain@nightly-2026-05-03`, a
               ref that action's repository does not publish, so every
               scheduled fuzz run failed in about six seconds and every timeout
               budget this file checks on that workflow guarded nothing.
  win-shell    A job whose matrix selects windows-latest ran a `run:` script
               that declared no `shell:`, so GitHub read one script text as
               PowerShell on that leg and as bash on every other leg.
  step-filter  Job rust-test gated seven steps on `needs.changes.outputs.rust`
               and carried no job-level `if:`, so a renamed filter output
               skipped every step while that job reported success over zero
               tests. An aggregate and a filter-key check below both read
               job-level conditions only, so neither could see it.
  empty-input  Job sign-windows signed every .dll a PowerShell pipeline
               returned and uploaded the result as `windows-signed`. That
               pipeline runs zero times over an empty set and exits 0, so a
               Windows build leg that produced no binary published an artifact
               named as signed that carried nothing signed. Jobs sign-apple and
               sign-maven pipe a `find` into a `while read` loop over the same
               empty set and upload `swift-xcframework-signed` and
               `maven-signed`, so this check selects a job by the `-signed`
               suffix on an artifact name rather than by naming sign-windows.
  path-closure A `fuzz` filter listed nine of the thirteen crates a fuzz build
               reads. It omitted scp-relay-client, which fuzz/Cargo.toml
               declares as a direct dependency, and omitted scp-core,
               scp-identity and scp-platform, so a change to any of those four
               skipped job fuzz-build. A closure computed here then read a
               dependency spec carrying no `path` key as a dependency reaching
               no crate, and a `dep = { workspace = true }` entry carries its
               `path` in a workspace manifest, so an inherited crate and
               everything it reaches dropped out of a closure this check
               compares a filter against. A crate directory is also not the
               whole of what a build reads: neither filter named the root
               Cargo.toml that publishes every `workspace = true` entry, and
               the `typescript-wasm` filter named no Cargo.lock either, so a
               dependency bump touching only those two files skipped
               fuzz-build, typescript-wasm-check and
               scaffold-typescript-web-check while `ci` reported success.
  shipped-config
               Job rust-build-uniffi-production ran `cargo build` alone under a
               note calling a prod-config test lane a separate follow-up, so
               `identity_create_in_memory_rejected_without_feature` — the uniffi
               proof that a shipped build rejects `in_memory` custody with
               SCP-IDENT-1008 — executed in no lane. Every lane running uniffi
               tests enables `scp-ffi-uniffi/testing`, which compiles that test
               out. The pass that added a test step to the pyo3 twin left this
               job's note in place.
  unified-feature
               A table here paired scp-identity with job rust-test under a
               comment claiming nothing enables `scp-identity/testing`. At that
               time crates/scp-testing/Cargo.toml declared a normal dependency
               `scp-identity = { path = "../scp-identity", features =
               ["testing"] }`, and one cargo invocation resolves one feature
               set per package, so that job's `cargo nextest run --workspace`
               built scp-identity with `testing` on and compiled its two
               `#[cfg(not(feature = "testing"))]` assertions out — while the
               check reading that table reported each one running by name.
               That normal-dependency line is now the `testing` feature of the
               same manifest, which that crate's own `[dev-dependencies]` turn
               on, and crates/scp-runtime/Cargo.toml and
               crates/scp-ffi/common/Cargo.toml each carry the same edge in
               their `[dev-dependencies]`. A workspace build reads all three,
               so the pairing this entry records stays rejected.
  filter-source
               A `changes` job publishes each output from a
               `steps.filter.outputs.<key>` expression, and dorny/paths-filter
               publishes nothing under a key its `filters:` block does not
               define. Renaming `rust` to `ruts` in that expression therefore
               published the literal "false" on every run, skipped each of the
               sixteen jobs whose `if:` reads that output, and left both gates
               reading ci.yml green — the aggregate reads "false" as "this job
               was not supposed to run", the verdict a genuine docs-only change
               earns.
  event-name   An aggregate read an absent GITHUB_EVENT_NAME as "", so
               `if: github.event_name == 'pull_request'` on job cross-layer
               judged false and a skipped cross-layer passed on a pull request.
  workspace-scope
               The `docs` filter guarding job rust-docs, which runs
               `cargo doc --workspace`, named eleven crate directories one at a
               time out of the twenty-six members the root Cargo.toml lists.
               `crates/scp-event-log/src/**` matched nothing, while
               crates/scp-runtime/src/ writes 49 intra-doc links into
               `scp_event_log::*` and the root Cargo.toml forbids
               `rustdoc::broken_intra_doc_links` in every member,
               so a pull request confined to scp-event-log skipped the one job
               that compiles rustdoc across the workspace — on the pull request
               and again on the push to `main`.
  private-items
               Job rust-doc in ci.yml, the only rustdoc job the required `ci`
               aggregator depends on, ran `cargo doc` without
               `--document-private-items`. Rustdoc resolves an intra-doc link
               only inside an item it documents, so that command read no link
               written in a private module. All three links pull request #2274,
               the structured OutletErrorSurface change, broke sat in the
               private module
               crates/scp-runtime/src/context/outlets_helpers.rs: the required
               job passed and only the advisory SDK Docs workflow, which passes
               the flag and blocks no merge, went red.
  doc-flag     The `rust-docs` job of docs.yml passed
               `--document-private-items` while job rust-doc in ci.yml did not,
               so the workflow that could report the diagnostic was the one no
               ruleset requires. Pull request #2329 then repaired the three
               links and added a `push: branches: [main]` trigger to docs.yml,
               which shortened time-to-detection and left the required check
               still unable to produce the diagnostic. Reading the two flag sets
               against each other names that gap for any flag, not for
               `--document-private-items` alone.
  merge-queue  docs.yml carried a header calling its jobs safe to promote to a
               required status check while the workflow triggered on `push` and
               `pull_request` only. A merge queue evaluates a required check
               against the `merge_group` ref, so following that header would
               have left every queue entry waiting on a status no run reports.
  needs-condition
               Five jobs build one bridge artifact each and upload it, and six
               jobs download what they build instead of compiling their own.
               GitHub skips a job when any job in its `needs` list is skipped,
               so a producer whose `if:` is narrower than one consumer's skips
               that consumer wherever the gap opens. The aggregate evaluates the
               consumer's own `if:` and fails that run, but only on a pull
               request whose changed files open the gap, which is usually not
               the pull request that narrowed the producer.
               Job napi-addon is the case: bridge-parity reads
               `python || typescript || rust`, so a producer reading
               `typescript || rust` — the condition typescript-check alone
               needs — would skip the NAPI half of the parity harness on every
               change confined to bindings/python. A diff of either job alone
               shows nothing.
  downloaded-module
               Every real-FFI test module under bindings/python/tests skips
               itself when the extension does not import, and the `scp` fixture
               skips every test that requests it when `SCP(storage=...)` raises,
               so a PyO3 consumer whose downloaded module does not load leaves
               pytest exiting 0 over zero executed assertions. The check requires
               each fragment in PYO3_ASSERTION_FRAGMENTS in the `run:` text of an
               unguarded step before `pytest tests`.
  downloaded-addon
               Every real-NAPI test file under bindings/typescript/tests resolves
               to `describe.skip` or `test.skip` when the addon load throws, so a
               NAPI consumer whose downloaded addon does not load leaves
               `bun test` exiting 0 over zero executed NAPI assertions. The check
               requires each fragment in NAPI_ASSERTION_FRAGMENTS in the `run:`
               text of an unguarded step before the first `bun test` or
               `pytest tests` step.
  retention    The four bridge producers uploaded with `retention-days: 1`, and
               "Re-run failed jobs" re-runs a failed consumer without its
               producer, so a consumer re-run a day after its run started
               failed its download while GitHub still offered the re-run.
  producer-outputs
               The XCFramework upload named `if-no-files-found: error` over
               three paths, one of them the tracked ScpBindings.swift, so the
               checkout always supplied a match and the option could not fail
               the producer when build-xcframework.sh wrote nothing. The
               kotlin-test upload lists the UniFFI cdylib and the Kotlin
               bindings, and a build that wrote one of them satisfies the
               option the same way.
  lint-scope   One crate declared the lint the two rustdoc jobs exist to fire:
               crates/scp-runtime/src/lib.rs carried
               `#![deny(rustdoc::broken_intra_doc_links)]` and none of the other
               25 members did, so job rust-doc, run verbatim on the tree that
               added `--document-private-items`, exited 0 over 271 unresolved
               intra-doc links in twelve other crate directories (218 of them
               under crates/scp-ffi/). The root Cargo.toml now sets that lint to
               `forbid` under `[workspace.lints.rustdoc]`, and every member
               inherits the table through `[lints] workspace = true`. The level
               is `forbid` because rustc lets a source-level `#![allow]` lower a
               `deny` and rejects an `allow` that contradicts a `forbid`, so no
               crate can reopen the hole from inside its own source.
  doc-command  The `forbid` above made an unresolved link an error in every
               member, and the three Markdown files that hand a developer a
               `cargo doc` command to run — .docs/standards/rust.md,
               .github/workflows/README.md and .docs/specs/21-documentation.md —
               named that command without the six `--features` job rust-doc in
               ci.yml passes. Four intra-doc links in crates/scp-node name items
               those features gate, so every documented command exited 101 on an
               unmodified `main`, naming a crate the developer's change never
               touched, while the required job exited 0. That comparison reads a
               shell-labelled fenced block and nothing else, so two copies of
               the flag list written inline — the normative clause §21.10.2
               item 2 of .docs/specs/21-documentation.md, and the Tier 1
               CI-matrix row for job `doc` in .docs/standards/rust.md — reached
               no assertion. Both now sit in a fenced block or name the block
               that holds the command, and a check rejects a `cargo doc` naming
               `--features` on any Markdown line no shell fence encloses.
  profile-env  ci.yml sets `CARGO_PROFILE_DEV_DEBUG: "0"` in its workflow-level
               `env:`.
               Swatinem/rust-cache hashes every `CARGO*` environment variable
               its step sees into its cache key. A `CARGO_PROFILE_*` key in one
               job's `env:` therefore gives that job a key no other member of
               its `shared-key` group computes, so that job restores no entry
               its group saved and compiles the group's dependencies from
               scratch. A `CARGO_PROFILE_*` key in the `env:` of a step that runs
               cargo makes cargo compile that step's units under a profile the
               restored entry does not hold and rebuild each one.
               Dropping the workflow-level key returns CI's dev-profile builds
               to the root Cargo.toml's `line-tables-only` without any check
               noticing.
               compile-timings.yml times cargo builds, so the same rule holds
               there: without the key it would time builds that carry line
               tables.
  matrix-axis
               Job rust-test-optional-features runs its commands on six legs,
               two runners times three values of a matrix `group` axis, and job
               rust-clippy runs on three values of a `leg` axis. GitHub runs a
               leg whose value no step names and reports it green over none of
               the gated commands, and it skips a step whose value the axis
               lacks on every leg, so deleting `platform-testing` from the
               `group` axis would have dropped eight commands from every run
               while `ci` passed. The check reports a step gated with
               `if: matrix.<axis> == '<value>'` on an axis the job's matrix does
               not define.
  package-writers
               Job docker-image-cache writes the Docker layer cache to the
               ghcr.io tag `buildcache:docker-image` with the `docker-cache`
               environment's `GHCR_CACHE_TOKEN`, and job docker-image reads it.
               The check reports any job or workflow-level `permissions:` block
               holding `packages: write` or `write-all`, and any step, job key,
               or workflow-level `env:` reading `secrets.GHCR_CACHE_TOKEN` in
               any letter case, or reading `toJSON(secrets)`, outside a job
               declaring `environment: docker-cache`.
  push-writers
               A writer that a push skips leaves its rust-cache, bridge-artifact, Gradle or
               layer-cache entry stale with nothing going red, since the `ci`
               aggregate evaluates that writer's own `if:`; a push-only skip
               that leaks into a pull_request or merge_group run removes a gate
               the same way. The check reports a cache-writing job some
               merge_group run selects and the same push does not (for the
               setup-bun cache, whose key names no job, that no push runs any
               job writing it), a writer's
               matrix that drops on push the leg its `save-if` names, and any
               job whose `if:` answers a scenario differently from SCENARIOS.

Assertions over an aggregate's verdict read which jobs a scenario selects out
of SCENARIOS below, never out of the aggregate itself. Six of them once built
that expectation by calling `evaluate` in scripts/ci-aggregate-result.py, the
same function whose verdict they then judged, so each one agreed with that
function however it behaved.

Run: python3 scripts/tests/ci-gate/ci_gate_selftest.py
"""

from __future__ import annotations

import copy
import functools
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import NamedTuple

import yaml

REPO = Path(__file__).resolve().parents[3]
WORKFLOW = REPO / ".github/workflows/ci.yml"
COMPILE_TIMINGS = REPO / ".github/workflows/compile-timings.yml"
AGGREGATE = REPO / "scripts/ci-aggregate-result.py"

# A ci.yml job whose work is a script or a lint finishes in under a minute; one
# compiling a workspace takes about twenty. A ceiling exists so that a hang
# costs minutes rather than six hours, which GitHub allows by default.
MAX_TIMEOUT_MINUTES = 90

# Scheduled fuzz and release workflows run longer by design: fuzz-weekly passes
# `-max_total_time=7200` to libFuzzer, and a release builds every target.
MAX_TIMEOUT_MINUTES_OTHER_WORKFLOWS = 240

# CRITERION: a workflow_dispatch input is runtime-scaling when a step hands it to
# something that decides how long that step runs. Such an input turns an
# operator's choice into a job's duration, so a budget fixed above one value
# cancels every larger one — which is why each entry below records both a
# runtime-scaling input and a floor on spare minutes its budget must leave for
# setup around whatever work that input sizes.
#
# `fuzz_time` qualifies: two jobs pass it to libFuzzer as `-max_total_time`.
# `version` and `scp-core-version` do not — a SemVer string lands in env vars,
# artifact names, and a PyPI URL, none of which decide duration. `dry-run` does
# not — a boolean guards `if:` conditions that skip jobs, which can only shorten
# a run. Add an entry here whenever a new input meets that criterion; a check
# below then requires every job reading it to size its budget from it.
RUNTIME_SCALING_INPUTS = {"fuzz_time": 10}

# GitHub expressions carry no arithmetic — actionlint rejects `900 / 60` with
# "got unexpected character '/' while lexing expression". A budget that must
# track a runtime-scaling input therefore SELECTS a whole-minute value per
# option through an `X == 'v' && minutes || …` chain, and a closed option list
# on that input is what makes such a chain total.
ARM_PATTERN = re.compile(r"github\.event\.inputs\.(\w+)\s*==\s*'([^']*)'\s*&&\s*(\d+)")
FALLBACK_PATTERN = re.compile(r"\|\|\s*(\d+)\s*\}\}\s*$")

# Cargo flags consuming whichever token follows them. Any other bare token after
# `cargo test` is a test-name filter, and `cargo test` exits 0 when a filter
# selects nothing.
VALUE_FLAGS = {
    "-p",
    "--package",
    "--features",
    "--test",
    "--bin",
    "--bins",
    "--example",
    "--manifest-path",
    "--target",
    "--target-dir",
    "--profile",
    "--jobs",
    "-j",
    "--exclude",
    "--config",
    "--color",
    "--message-format",
    "-E",
    "--filter-expr",
    "--filterset",
    "-P",
}

# CRITERION: after a `--`, any token a test harness does not consume as a
# flag's value is a name filter, and a libtest harness exits 0 when its filter
# selects no test. `cargo test --release -p scp-testing -- conformance` in
# release.yml is the command that prompted reading past a `--`: a rename moving
# every conformance test out of a name carrying "conformance" would have left a
# release gate green over zero assertions.
#
# INDICATORS, not a criterion: the names below are whichever libtest and nextest
# flags take a separate value. Omitting one makes that value read as a filter
# and fails this self-test, which errs toward rejecting a command rather than
# toward passing one.
HARNESS_VALUE_FLAGS = {
    "--test-threads",
    "--skip",
    "--logfile",
    "--format",
    "--color",
    "--shuffle-seed",
    "-Z",
}

# A `${{ … }}` expression is one argument once GitHub substitutes it, so it
# collapses to one token before a command is split. Splitting it instead reads
# `matrix.target` in `--target ${{ matrix.target }}` as a name filter.
EXPRESSION = re.compile(r"\$\{\{[^}]*\}\}")

# CRITERION: a job that compiles a crate must run whenever any crate that
# crate's build reads has changed, so a path filter selecting that job lists
# every directory in that crate's path-dependency closure. Each entry names a
# filter and the manifest whose closure that filter must cover. A closure comes
# from `[dependencies]`, `[build-dependencies]` and `[target.*]` path entries in
# Cargo.toml files, which is what `cargo tree -e no-dev` walks; read against
# `cargo tree -e no-dev` for both manifests on 2026-08-17, and both agreed.
PATH_DEP_CLOSURE_FILTERS = {
    "fuzz": "fuzz/Cargo.toml",
    "typescript-wasm": "crates/scp-client-wasm/Cargo.toml",
}

# CRITERION for check_workspace_scoped_filters: a cargo command carrying
# `--workspace` compiles every member the root manifest lists, so a path filter
# deciding whether that command runs must match a change to any file of any
# member. The check reads the member list out of the root Cargo.toml rather than
# out of a list written here, so a crate added to the workspace later is covered
# without editing this file — which is the property the `docs` filter's
# hand-written list of eleven crate directories did not have.
WORKSPACE_SCOPE_FLAG = "--workspace"

# CRITERION for check_rustdoc_documents_private_items: rustdoc resolves an
# intra-doc link only inside an item it documents, so a `cargo doc` run without
# this flag applies the workspace's `forbid(rustdoc::broken_intra_doc_links)` to
# the public surface alone and reads no link a private module writes. Every
# `cargo doc` command in every workflow of this repository exists to catch such
# a link, so each one passes this flag.
DOCUMENT_PRIVATE_ITEMS_FLAG = "--document-private-items"

# CRITERION for check_rustdoc_lint_reaches_every_member: the flag above buys a
# diagnostic only where the lint level makes an unresolved link an error, and
# cargo applies a lint level per package. The root Cargo.toml sets this lint to
# `forbid` under `[workspace.lints.rustdoc]`, and a member receives that table
# only when its own manifest declares `[lints] workspace = true`, so a member
# without that declaration documents under rustdoc's default `warn` and both
# rustdoc jobs exit 0 over every link it breaks. The level is `forbid` and not
# `deny` because rustc honours a source-level `#![allow]` against a `deny` and
# rejects one against a `forbid`.
RUSTDOC_LINT = "broken_intra_doc_links"
RUSTDOC_LINT_LEVEL = "forbid"

# A FLOOR under those two criteria, not the criteria themselves. Both checks
# iterate whatever the workflows declare, so a renamed job, a `cargo doc` moved
# into a shell script, or a `--workspace` command rewritten as one `-p` per
# crate empties that iteration and leaves each check printing nothing and
# failing nothing — the zero-test defect this file's docstring records, seen
# from the reader's end rather than from cargo's. These two sets name what the
# workflows carry today. Add an entry when a workflow gains a job of either
# kind; remove one only alongside the job it names.
WORKSPACE_SCOPED_JOBS = {
    ("ci.yml", "rust-clippy"),
    ("ci.yml", "rust-doc"),
    ("ci.yml", "rust-test"),
    ("docs.yml", "rust-docs"),
}
RUSTDOC_JOBS = {("ci.yml", "rust-doc"), ("docs.yml", "rust-docs")}

# CRITERION for check_documented_rustdoc_reproduces_the_required_job: a `cargo
# doc` line inside a shell-labelled fenced block of a tracked Markdown file is a
# command this repository hands a developer to run, so that command and job
# `rust-doc` in .github/workflows/ci.yml must report the same diagnostics. A
# documented command breaks that in two directions. It omits a flag the required
# job passes, and then a developer whose local run exits 0 has proven nothing
# about the merge. Or its `--features` list differs from that job's, and then it
# reports a break the merge does not have: `.docs/standards/rust.md` named the
# command with no `--features` at all, four intra-doc links in crates/scp-node
# resolve only under the six features that job enables, and the workspace
# `forbid` this branch added turns each one into an error, so a developer who
# ran the documented command on an unmodified `main` read exit 101 naming a
# crate their change never touched. A flag outside `--features` that a
# documented command adds and the required job omits — `--open` in
# .docs/specs/21-documentation.md — decides what rustdoc does with output it
# already produced rather than which links it resolves, so it changes no
# diagnostic and this check permits it.
SHELL_FENCE_LANGUAGES = {"bash", "sh", "shell", "console"}
FEATURES_FLAG = "--features"
FEATURES_FLAG_PREFIX = f"{FEATURES_FLAG}="

# CRITERION for check_rustdoc_enumerations_sit_in_a_shell_block: Markdown text
# that writes out the flag set job `rust-doc` in .github/workflows/ci.yml passes
# sits where check_documented_rustdoc_reproduces_the_required_job compares it
# against that job, which reads shell-labelled fenced blocks and nothing else. A
# `cargo doc` carrying `--features` writes out that set, because the feature
# list is the part of the command that changes when the required job changes and
# the part no sentence about rustdoc needs. A sentence naming one flag to make a
# point about that flag — four in `.docs/lessons/`, two in
# `.claude/agent-memory/`, one in `.docs/standards/rust.md` — writes out no set
# and drifts nowhere, so this
# check reads a `--features` list as what marks an enumeration. Both enumerations
# this repository carried outside a shell block sat one edit away from going
# stale: `.docs/specs/21-documentation.md` stated the flags a second time in the
# normative clause §21.10.2 item 2, and `.docs/standards/rust.md` stated them a
# second time in the Tier 1 CI-matrix row for job `doc`. A document recording a
# feature list job `rust-doc` no longer passes — a lesson naming what a past run
# enabled — names those features without writing them as a `cargo doc
# --features` command, because a fenced block would put the stale list under the
# comparison against the current job and an inline command reaches no comparison
# at all. Neither place holds a runnable command nobody should run.

# A FLOOR under that criterion, not the criterion itself. The scan iterates
# whatever `git ls-files` returns, so a renamed file, a fence relabelled to a
# language this set does not name, or a command rewritten into prose empties the
# iteration and leaves this check printing nothing and failing nothing — the
# zero-test defect this file's docstring records. These three paths carry such a
# command today. Add an entry when a Markdown file gains one; remove one only
# alongside the command it names. check_rustdoc_enumerations_sit_in_a_shell_block
# reaches the second and third of those three moves independently of this
# constant, because it reads every line a shell fence does not enclose and
# rejects a `cargo doc` naming `--features` among them.
DOCUMENTED_RUSTDOC_FILES = {
    ".docs/specs/21-documentation.md",
    ".docs/standards/rust.md",
    ".github/workflows/README.md",
}

# Rejects an empty signing-input set. Every release.yml job that uploads an
# artifact whose name asserts a signature must run it before that upload.
GUARD_SCRIPT = "scripts/assert-nonempty-signing-set.sh"

# CRITERION for check_signing_guard: an artifact name ending in this suffix
# tells a consumer the artifact's contents are signed, so the job publishing it
# must first prove its signing loop had files to sign. Job publish-spm reads
# `swift-xcframework-signed` and writes that bundle's URL and SHA-256 into
# bindings/swift/Package.swift, so an unsigned bundle under that name reaches
# every Swift Package Manager consumer.
SIGNED_ARTIFACT_SUFFIX = "-signed"

# A FLOOR under the suffix criterion, not the criterion itself. Renaming
# `maven-signed` to `maven-release` would empty the suffix match and leave
# check_signing_guard passing over zero uploads, so these three jobs must appear
# in whatever that match finds. Add a job here when release.yml gains a fourth
# signing job.
SIGNING_JOBS = {"sign-apple", "sign-windows", "sign-maven"}

# CRITERION: a bridge's shipped-build assertion — a `#[test]` the bridge gates
# `#[cfg(not(feature = "testing"))]`, which proves that a build carrying no
# `testing` feature fails closed where a `testing` build mints an in-memory
# nullifier — must be EXECUTED by some ci.yml job. Every lane that runs a
# bridge's tests otherwise enables that bridge's `testing` feature, which
# compiles such a test out, so the only lane that can execute one is a lane
# building that bridge in its production configuration. A production-config job
# that runs `cargo build` alone compiles the assertion and runs it never.
#
# Job rust-build-uniffi-production was build-only and carried a note calling a
# prod-config test lane a separate follow-up, so
# `identity_create_in_memory_rejected_without_feature` in
# crates/scp-ffi/uniffi/src/lib.rs — the uniffi proof that a shipped build
# rejects `in_memory` custody with SCP-IDENT-1008 — ran in no lane while `ci`
# reported success and build-matrix.yml shipped that bridge in an iOS
# XCFramework and an Android AAR.
#
# Each key is a ci.yml job; each value is the set of packages whose
# shipped-build assertions that job must run.
SHIPPED_CONFIG_LANES = {
    "rust-build-pyo3-production": {"scp-ffi"},
    "rust-build-uniffi-production": {"scp-ffi-uniffi"},
    "rust-test-napi-production": {"scp-ffi-napi", "scp-ffi-common"},
}

# Packages outside SHIPPED_CONFIG_LANES that carry shipped-build assertions,
# each paired with the ci.yml job that runs them. A check below requires each
# job named here to exist, and a package carrying such an assertion while
# appearing in neither table fails that check by name — so a crate cannot gain
# one without someone recording which lane runs it.
#
# Job fail-closed-pre-rotation selects each crate with `-p` and names its two
# assertions in an `-E` filter. A workspace-wide command cannot serve as
# scp-identity's lane: three manifests turn `scp-identity/testing` on, each in
# its own `[dev-dependencies]` — crates/scp-testing/Cargo.toml,
# crates/scp-runtime/Cargo.toml and crates/scp-ffi/common/Cargo.toml — and
# one cargo invocation resolves one feature set per package, so a build reading
# any one of them compiles scp-identity's
# `#[cfg(not(feature = "testing"))]` assertions out. An earlier revision of
# this table paired scp-identity with job rust-test under a comment claiming
# nothing enables `scp-identity/testing`; command_unifies_testing below now
# reads that edge out of the manifests a command's build includes, so pairing
# a package with such a lane fails check_shipped_build_assertions_run instead
# of passing on the command's text.
NON_BRIDGE_SHIPPED_ASSERTION_LANES = {
    "scp-identity": "fail-closed-pre-rotation",
    "scp-node": "fail-closed-pre-rotation",
}

# Attributes that mark a Rust function as a test, and the attribute that
# compiles an item only into a build carrying no `testing` feature. A scan below
# reads attributes written one per line, on the lines above the `fn` they
# annotate, which is the layout `cargo fmt` produces and job rust-fmt enforces.
TEST_ATTRIBUTE = re.compile(r"^#\[(?:tokio::)?test\b")
SHIPPED_ONLY_ATTRIBUTE = '#[cfg(not(feature = "testing"))]'
RUST_FN_NAME = re.compile(r"\bfn\s+(\w+)")

# CRITERION: a `uses:` ref names a branch or a tag that action's own repository
# publishes. A ref naming anything else fails a run in about six seconds with
# "Unable to resolve action", and a job that never starts enforces nothing.
#
# dtolnay/rust-toolchain publishes seven named branches and one tag per
# released Rust version (`git ls-remote --heads --tags
# https://github.com/dtolnay/rust-toolchain`, read 2026-08-16). It takes a
# date-pinned nightly through `with: toolchain:`, never through its ref, so
# `@nightly-2026-05-03` resolves to nothing.
TOOLCHAIN_ACTION = "dtolnay/rust-toolchain"
TOOLCHAIN_REFS = {"stable", "beta", "nightly", "master", "clippy", "miri", "comment"}
TOOLCHAIN_VERSION_TAG = re.compile(r"^1\.\d+(\.\d+)?$")

# A date-pinned nightly names a toolchain no other date matches, so two
# workflows pinning two different dates compile the fuzz crate against two
# compilers — and a build check passing under one says nothing about a fuzz run
# under the other.
DATE_PINNED_NIGHTLY = re.compile(r"^nightly-\d{4}-\d{2}-\d{2}$")

# Names a filter output out of an `if:` expression, so a check below can drop
# one published output and watch an aggregate refuse to guess at it.
FILTER_REFERENCE = re.compile(r"needs\.changes\.outputs\.([\w-]+)")

# Names a key an expression reads off a `dorny/paths-filter` step, so a check
# below can compare the keys a `changes` job publishes against the keys that
# step's `filters:` block defines. `{id}` takes the step's own `id`.
FILTER_STEP_REFERENCE = r"steps\.{id}\.outputs\.([\w-]+)"

# The outputs dorny/paths-filter publishes beyond one per key its `filters:`
# block defines. Its v3 tag publishes `changes`, a JSON array naming whichever
# keys matched. It publishes `<key>_count` and `<key>_files` only for a step
# that sets `list-files`, and no step in this repository sets it, so a reference
# to either reads below as a key nothing defines — which errs toward reporting a
# gap rather than toward passing one.
PATHS_FILTER_BUILTIN_OUTPUTS = {"changes"}


class Scenario(NamedTuple):
    """One set of `changes` filter outputs, one event, and what each runs."""

    name: str
    filters: dict[str, str]
    event: str
    runs: dict[str, bool]


# CRITERION: SCENARIOS below, and nothing in scripts/ci-aggregate-result.py,
# states which jobs a scenario selects. `runs` answers that question for every
# job ci.yml gives an `if:` condition; a job carrying no `if:` condition always
# runs, which main() reads out of ci.yml rather than restating here. A check in
# main() requires each scenario's `runs` to name exactly whichever jobs carry an
# `if:` condition, so adding a conditional job to ci.yml fails this self-test
# until someone records that job's answer.
RUST_ONLY = {
    "rust": "true",
    "python": "false",
    "typescript": "false",
    "typescript-wasm": "false",
    "scaffold-typescript-web": "false",
    "kotlin": "false",
    "swift": "false",
    "fuzz": "false",
}
DOCS_ONLY = dict.fromkeys(RUST_ONLY, "false")

# Jobs whose `if:` reads `github.event_name` rather than a `changes` filter
# output, so a filter scenario decides nothing about them and each scenario
# below states them for itself. Both carry
# `if: github.event_name == 'pull_request'`, and check-cross-layer.sh is why:
# it reads a declared exemption out of a pull request's body, which a
# merge_group event does not publish. Job cross-layer runs that script as its
# own step, and job fix-round-check-selftest runs it as one of the 29 gates
# scripts/fix-round-check.sh names.
EVENT_ONLY_JOBS = ("cross-layer", "fix-round-check-selftest")

# Jobs a `changes` filter output selects whose `if:` also reads
# `github.event_name == 'push' && …`.
PUSH_ONLY_FILTER_JOBS = ("docker-image-cache",)

# Jobs whose `if:` is `github.event_name != 'push'` alone. None of
# these writes a cache, so each runs on every pull_request and merge_group run and
# skips on every push.
NOT_ON_PUSH_JOBS = (
    "agent-verdict-criterion",
    "block-in-place",
    "bridge-globals",
    "bridge-instance-lifecycle",
    "bridge-symmetry",
    "ci-workflow-selftest",
    "construction-pattern",
    "deleted-primitives",
    "doc-citations",
    "doc-includes",
    "error-codes",
    "fail-closed-pre-rotation",
    "fallback-registry",
    "handle-affinity",
    "handler-no-panic",
    "no-mutable-globals-kotlin",
    "no-mutable-globals-python",
    "no-mutable-globals-rust",
    "no-mutable-globals-ts",
    "no-panic-abort",
    "pyi-generated",
    "protocol-deps",
    "protocol-sync",
    "saga-gating-granularity",
    "sdk-coverage",
    "shipped-feature-graph",
    "toolchain-wiring",
    "wasm-protocol",
    "wasm-test",
)

# Jobs a `changes` filter output selects whose `if:` also reads
# `github.event_name != 'push' && …`. The
# filter jobs absent from this list write a cache on a push to `main` and run there
# whenever their filters select them.
NOT_ON_PUSH_FILTER_JOBS = (
    "bridge-parity",
    "bridge-parity-swift",
    "docker-image",
    "python-lint",
    "python-test",
    "rust-build-pyo3-production",
    "rust-build-uniffi-production",
    "rust-deny",
    "rust-doc",
    "rust-fmt",
    "rust-test-napi-production",
    "scaffold-typescript-web-check",
    "swift-build-test",
    "swift-lint",
    "typescript-check",
)


def on_event(filter_runs: dict[str, bool], event: str) -> dict[str, bool]:
    """Every conditional job's answer for one event, from the filter jobs' answers."""
    push = event == "push"
    runs = dict(filter_runs)
    runs |= dict.fromkeys(NOT_ON_PUSH_FILTER_JOBS if push else PUSH_ONLY_FILTER_JOBS, False)
    return (
        runs
        | dict.fromkeys(EVENT_ONLY_JOBS, event == "pull_request")
        | dict.fromkeys(NOT_ON_PUSH_JOBS, not push)
    )


# Jobs a `changes` filter output selects.
RUST_ONLY_RUNS = {
    "bridge-parity": True,
    "bridge-parity-kotlin": True,
    "bridge-parity-swift": True,
    "docker-image": True,
    "docker-image-cache": True,
    "fuzz-build": False,
    "kotlin-lint": False,
    "kotlin-test": True,
    "napi-addon": True,
    "pyo3-module": True,
    "pyo3-module-macos": True,
    "python-lint": False,
    "python-test": True,
    "rust-build-pyo3-production": True,
    "rust-build-uniffi-production": True,
    "rust-clippy": True,
    "rust-deny": True,
    "rust-doc": True,
    "rust-fmt": True,
    "rust-test": True,
    "rust-test-optional-features": True,
    "rust-test-napi-production": True,
    "scaffold-typescript-web-check": False,
    "swift-build-test": True,
    "swift-lint": False,
    "typescript-check": True,
    "typescript-wasm-check": False,
    "xcframework": True,
}
DOCS_ONLY_RUNS = dict.fromkeys(RUST_ONLY_RUNS, False)
PYTHON_ONLY = DOCS_ONLY | {"python": "true"}
PYTHON_ONLY_RUNS = DOCS_ONLY_RUNS | dict.fromkeys(
    (
        "bridge-parity",
        "bridge-parity-kotlin",
        "bridge-parity-swift",
        # Producer of the UniFFI cdylib bridge-parity-kotlin downloads.
        "kotlin-test",
        "napi-addon",
        "pyo3-module",
        "pyo3-module-macos",
        "python-lint",
        "python-test",
        "rust-build-pyo3-production",
        "xcframework",
    ),
    True,
)
# One filter per job clause: no job ORs two of swift, typescript and
# scaffold-typescript-web together, so dropping any one of those clauses from a
# job's `if:` changes that job's answer in this scenario. typescript-wasm sits
# in its own scenario because scaffold-typescript-web-check ORs it with
# scaffold-typescript-web.
SWIFT_TYPESCRIPT = DOCS_ONLY | dict.fromkeys(
    ("swift", "typescript", "scaffold-typescript-web"), "true"
)
SWIFT_TYPESCRIPT_RUNS = DOCS_ONLY_RUNS | dict.fromkeys(
    (
        "bridge-parity",
        "bridge-parity-swift",
        "napi-addon",
        "pyo3-module",
        "pyo3-module-macos",
        "scaffold-typescript-web-check",
        "swift-build-test",
        "swift-lint",
        "typescript-check",
        "xcframework",
    ),
    True,
)
WASM_ONLY = DOCS_ONLY | {"typescript-wasm": "true"}
WASM_ONLY_RUNS = DOCS_ONLY_RUNS | dict.fromkeys(
    ("scaffold-typescript-web-check", "typescript-wasm-check"), True
)

SCENARIOS = {
    "rust-only, pull_request": Scenario(
        name="rust-only, pull_request",
        filters=RUST_ONLY,
        event="pull_request",
        runs=on_event(RUST_ONLY_RUNS, "pull_request"),
    ),
    "docs-only, pull_request": Scenario(
        name="docs-only, pull_request",
        filters=DOCS_ONLY,
        event="pull_request",
        runs=on_event(DOCS_ONLY_RUNS, "pull_request"),
    ),
    "docs-only, push": Scenario(
        name="docs-only, push",
        filters=DOCS_ONLY,
        event="push",
        runs=on_event(DOCS_ONLY_RUNS, "push"),
    ),
    "rust-only, push": Scenario(
        name="rust-only, push",
        filters=RUST_ONLY,
        event="push",
        runs=on_event(RUST_ONLY_RUNS, "push"),
    ),
    "rust-only, merge_group": Scenario(
        name="rust-only, merge_group",
        filters=RUST_ONLY,
        event="merge_group",
        runs=on_event(RUST_ONLY_RUNS, "merge_group"),
    ),
    "python-only, pull_request": Scenario(
        name="python-only, pull_request",
        filters=PYTHON_ONLY,
        event="pull_request",
        runs=on_event(PYTHON_ONLY_RUNS, "pull_request"),
    ),
    "python-only, push": Scenario(
        name="python-only, push",
        filters=PYTHON_ONLY,
        event="push",
        runs=on_event(PYTHON_ONLY_RUNS, "push"),
    ),
} | {
    f"{label}, {event}": Scenario(
        name=f"{label}, {event}",
        filters=filters,
        event=event,
        runs=on_event(filter_runs, event),
    )
    for label, filters, filter_runs in (
        ("swift-and-typescript", SWIFT_TYPESCRIPT, SWIFT_TYPESCRIPT_RUNS),
        ("typescript-wasm-only", WASM_ONLY, WASM_ONLY_RUNS),
    )
    for event in ("pull_request", "merge_group")
}

failures: list[str] = []
checks = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name}{': ' + detail if detail else ''}")
        failures.append(name)


def logical_lines(script: str) -> list[str]:
    """Join backslash continuations, drop comments, and strip each command."""
    joined = script.replace("\\\n", " ")
    out = []
    for raw in joined.splitlines():
        line = " ".join(raw.split())
        if line and not line.startswith("#"):
            out.append(line)
    return out


def split_command(command: str) -> list[str]:
    """Split a shell command into tokens, keeping each `${{ … }}` whole."""
    return shlex.split(EXPRESSION.sub("EXPRESSION", command))


def bare_tokens(tokens: list[str], value_flags: set[str]) -> list[str]:
    """Return tokens that are neither a flag nor a flag's value."""
    bare, skip_next = [], False
    for token in tokens:
        if skip_next:
            skip_next = False
        elif token in value_flags:
            skip_next = True
        elif not token.startswith("-"):
            bare.append(token)
    return bare


def positional_filters(command: str) -> list[str]:
    """Return bare test-name arguments a cargo command carries.

    Reads both sides of a `--`. Cargo takes a name filter directly, and it also
    forwards every token after a `--` to a test harness, which takes a name
    filter there. Reading only a cargo side missed
    `cargo test … -- conformance`, whose harness exits 0 when no test name
    carries "conformance".
    """
    cargo_side, _, harness_side = command.partition(" -- ")
    tokens = split_command(cargo_side)
    for word in ("cargo", "test", "nextest", "run"):
        if tokens and tokens[0] == word:
            tokens.pop(0)
    filters = bare_tokens(tokens, VALUE_FLAGS)
    filters += bare_tokens(split_command(harness_side), HARNESS_VALUE_FLAGS)
    return filters


def dispatch_input_specs(doc: dict) -> dict:
    """Return workflow_dispatch input specs, keyed by input name."""
    # PyYAML parses a bare `on:` key as boolean True.
    triggers = doc.get(True) or doc.get("on") or {}
    if not isinstance(triggers, dict):
        return {}
    dispatch = triggers.get("workflow_dispatch")
    if not isinstance(dispatch, dict):
        return {}
    return dispatch.get("inputs") or {}


def check_selected_budget(label, expression, dispatch_inputs, ceiling) -> None:
    """A budget written as a selection chain must cover every permitted option.

    Each arm reads `<input> == '<seconds>' && <minutes>`, and a trailing
    `|| <minutes>` catches whatever no arm named — including a scheduled run,
    which supplies no input at all. Two properties decide correctness: every
    option resolves to some budget, and every budget leaves spare minutes above
    however long that option asks a fuzzer to run.
    """
    arms = {
        seconds: int(minutes) for _, seconds, minutes in ARM_PATTERN.findall(expression)
    }
    referenced = {name for name, _, _ in ARM_PATTERN.findall(expression)}
    fallback = FALLBACK_PATTERN.search(" ".join(expression.split()))

    check(
        f"{label} names one dispatch input in its budget",
        len(referenced) == 1,
        str(referenced),
    )
    check(
        f"{label} ends its budget chain with a fallback",
        fallback is not None,
        expression,
    )
    if len(referenced) != 1 or fallback is None:
        return

    name = referenced.pop()
    fallback_minutes = int(fallback.group(1))
    spec = dispatch_inputs.get(name) or {}
    options = [str(option) for option in (spec.get("options") or [])]
    floor = RUNTIME_SCALING_INPUTS.get(name, 0)

    check(
        f"{label} sizes its budget from a bounded input",
        bool(options),
        f"input {name!r} offers no closed option list, so no chain over it can be total",
    )

    for option in options:
        minutes = arms.get(option, fallback_minutes)
        asked = int(option) / 60
        check(
            f"{label} covers fuzz_time={option} with {minutes} minutes",
            asked + floor <= minutes <= ceiling,
            f"{option}s asks {asked:g} minutes and this leaves {minutes - asked:g} spare, "
            f"want at least {floor} and a budget at most {ceiling}",
        )

    for option in arms:
        check(
            f"{label} arm for {option} names a permitted option",
            option in options,
            f"no option {option!r} exists, so this arm can never be selected",
        )


def check_scaling_input_sizes_budget(label, job, budget) -> None:
    """A job reading a runtime-scaling input must size its budget from it."""
    script = " ".join(
        step.get("run") or "" for step in job.get("steps", []) if isinstance(step, dict)
    )
    for name in RUNTIME_SCALING_INPUTS:
        token = f"inputs.{name}"
        if token not in script:
            continue
        check(
            f"{label} reads {name} and sizes its budget from it",
            isinstance(budget, str) and token in budget,
            f"steps pass {name} to something that decides how long they run, "
            f"so a budget of {budget!r} cancels every value above it",
        )


def run_aggregate(needs: dict, event_name: str | None) -> tuple[int, str]:
    """Run an aggregate over one `needs` map. `event_name=None` unsets it."""
    env = dict(os.environ, NEEDS_JSON=json.dumps(needs))
    if event_name is None:
        env.pop("GITHUB_EVENT_NAME", None)
    else:
        env["GITHUB_EVENT_NAME"] = event_name
    proc = subprocess.run(
        [sys.executable, str(AGGREGATE), str(WORKFLOW)],
        env=env,
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def build_needs(jobs: dict, scenario: Scenario) -> dict:
    """Report a result per dependency, taking SCENARIOS as ground truth.

    A job carrying an `if:` condition reports `success` when this scenario's
    `runs` says that condition selects it, and `skipped` when it says
    otherwise. A job carrying no `if:` condition always runs, so it reports
    `success`. Nothing here consults scripts/ci-aggregate-result.py, which is
    what lets an assertion over that script's verdict fail when that script
    reads a condition wrongly.
    """
    needs = {}
    for job_id in set(jobs) - {"ci"}:
        if job_id == "check-draft":
            needs[job_id] = {"result": "success"}
            continue
        if job_id == "changes":
            needs[job_id] = {"result": "success", "outputs": scenario.filters}
            continue
        runs = scenario.runs.get(job_id, True)
        needs[job_id] = {"result": "success" if runs else "skipped"}
    return needs


def check_scenario_table_covers(jobs: dict) -> None:
    """Each scenario answers for exactly whichever jobs carry an `if:`."""
    conditional = {
        job_id
        for job_id, job in jobs.items()
        if job.get("if") is not None and job_id not in ("ci", "changes", "check-draft")
    }
    for scenario in SCENARIOS.values():
        check(
            f"{scenario.name} answers for every conditional job",
            set(scenario.runs) == conditional,
            f"unanswered {sorted(conditional - set(scenario.runs))}, "
            f"unknown {sorted(set(scenario.runs) - conditional)}",
        )


def check_toolchain_refs(path: Path, doc: dict) -> None:
    """Every rust-toolchain `uses:` names a ref that action publishes."""
    for job_id, job in sorted(doc["jobs"].items()):
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses") or ""
            if not uses.startswith(f"{TOOLCHAIN_ACTION}@"):
                continue
            ref = uses.split("@", 1)[1]
            check(
                f"{path.name}:{job_id} names a published {TOOLCHAIN_ACTION} ref",
                ref in TOOLCHAIN_REFS or bool(TOOLCHAIN_VERSION_TAG.match(ref)),
                f"{uses} — that repository publishes {sorted(TOOLCHAIN_REFS)} and a tag "
                f"per released Rust version; pass a date-pinned nightly through "
                f"`with: toolchain:` on `@master` instead",
            )


def job_runner_images(job: dict) -> set[str]:
    """Return every runner image a job can land on, matrix entries included."""
    images = {str(job.get("runs-on", ""))}
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    if isinstance(matrix, dict):
        for key, value in matrix.items():
            if key == "include" and isinstance(value, list):
                for entry in value:
                    if isinstance(entry, dict):
                        images |= {
                            str(entry[name])
                            for name in ("runner", "os")
                            if name in entry
                        }
            elif isinstance(value, list):
                images |= {str(item) for item in value}
    return images


def check_windows_shell(path: Path, doc: dict) -> None:
    """Every `run:` step a Windows runner can execute declares its shell.

    CRITERION: a step carries a `shell:` key, or its job or its workflow sets
    `defaults.run.shell`. GitHub reads an undeclared `run:` script as PowerShell
    on a Windows image and as bash on every other image, so one script text
    means two languages across one matrix.

    This states a shape a step must carry. Reading a script and guessing which
    shell its syntax needs would be a denylist that never closes, and a POSIX
    `for pkg in …; do` loop in job rust of build-matrix.yml is the case that
    prompted this check: it failed target x86_64-pc-windows-msvc before its
    first `cargo build`, so that leg uploaded no artifact and job sign-windows
    in release.yml found no DLL to Authenticode-sign.
    """
    workflow_shell = ((doc.get("defaults") or {}).get("run") or {}).get("shell")
    for job_id, job in sorted(doc["jobs"].items()):
        if "uses" in job:
            continue
        if not any("windows" in image.lower() for image in job_runner_images(job)):
            continue
        job_shell = ((job.get("defaults") or {}).get("run") or {}).get("shell")
        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict) or step.get("run") is None:
                continue
            name = step.get("name") or f"step {index}"
            check(
                f"{path.name}:{job_id} declares a shell for {name!r}",
                bool(step.get("shell") or job_shell or workflow_shell),
                "a matrix places this job on a Windows runner, where GitHub reads an "
                "undeclared `run:` script as PowerShell and reads that same script as "
                "bash on every other leg",
            )


class FilterStep(NamedTuple):
    """One `dorny/paths-filter` step: where it runs, its id, and what it defines."""

    job_id: str
    job: dict
    step_id: str | None
    filters: dict[str, list[str]]


def paths_filter_steps(doc: dict) -> list[FilterStep]:
    """Return every `dorny/paths-filter` step a workflow declares."""
    steps = []
    for job_id, job in sorted((doc.get("jobs") or {}).items()):
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            if not str(step.get("uses") or "").startswith("dorny/paths-filter"):
                continue
            steps.append(
                FilterStep(
                    job_id,
                    job,
                    step.get("id"),
                    yaml.safe_load((step.get("with") or {})["filters"]),
                )
            )
    return steps


def path_filters(jobs: dict) -> dict[str, list[str]]:
    """Return each `changes` filter name mapped to its path patterns."""
    for step in paths_filter_steps({"jobs": jobs}):
        if step.job_id == "changes":
            return step.filters
    raise AssertionError("job `changes` runs no dorny/paths-filter step")


def filter_step_references(node: object, step_id: str) -> set[str]:
    """Return every output key an expression reads off one paths-filter step.

    Walks the strings a parsed job holds, because a job reads a step output in
    an `outputs:` value, in an `if:`, in an `env:` value, and in a `run:` script,
    and each of those is a string in the same tree.
    """
    reference = re.compile(FILTER_STEP_REFERENCE.format(id=re.escape(step_id)))
    named: set[str] = set()
    pending = [node]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            named |= set(reference.findall(item))
    return named


def filter_key_disagreements(
    filters: dict, referenced: set[str]
) -> tuple[list[str], list[str]]:
    """Return the keys an expression reads but nothing defines, and the reverse.

    dorny/paths-filter publishes one output per key its `filters:` block defines
    and nothing for a key that block omits, so an expression naming an undefined
    key reads the empty string. `'' == 'true'` is false, so the `changes` job
    publishes the literal "false", every job that output guards skips, and
    scripts/ci-aggregate-result.py reads "false" as "this job was not supposed to
    run" and exits 0. A key the block defines that no expression reads gates
    nothing, which is the same rename seen from its other end.
    """
    defined = set(filters)
    undefined = sorted(referenced - defined - PATHS_FILTER_BUILTIN_OUTPUTS)
    unread = sorted(defined - referenced)
    return undefined, unread


def workspace_dependency_specs(manifest: Path) -> tuple[dict, Path]:
    """Return `[workspace.dependencies]` and a directory its paths resolve against.

    Cargo resolves a `dep = { workspace = true }` entry against the nearest
    ancestor manifest carrying a `[workspace]` table, a manifest carrying that
    table itself included, and it reads that entry's `path` relative to that
    workspace manifest's own directory rather than relative to a member's
    directory. path_dependency_closure calls this so an inherited dependency
    contributes its directory to a closure.
    """
    resolved = manifest.resolve()
    document = tomllib.loads(resolved.read_text())
    if "workspace" in document:
        return document["workspace"].get("dependencies") or {}, resolved.parent
    for directory in resolved.parent.parents:
        candidate = directory / "Cargo.toml"
        if not candidate.is_file():
            continue
        parsed = tomllib.loads(candidate.read_text())
        if "workspace" in parsed:
            return parsed["workspace"].get("dependencies") or {}, directory
    return {}, resolved.parent


def path_dependency_closure(manifest: Path, root: Path | None = None) -> set[str]:
    """Return every crate directory a manifest reaches through `path =` deps.

    Walks `[dependencies]`, `[build-dependencies]` and each `[target.*]` table,
    which together are what `cargo tree -e no-dev` walks. Skips
    `[dev-dependencies]`, because a shipped or fuzzed build does not compile
    them. Returns directories relative to `root`, so a caller compares them
    against a path filter directly.

    A `dep = { workspace = true }` entry carries its `path` in a workspace
    manifest rather than in a member manifest, so reading a member's own table
    alone drops that dependency and every crate it reaches. This walk therefore
    substitutes a workspace spec for each inherited entry, and raises on an
    inherited name no workspace publishes rather than dropping it — dropping it
    would shrink a closure and let check_path_dep_closures report a filter
    complete while that filter omitted those directories.
    """
    root = (REPO if root is None else root).resolve()
    directories: set[str] = set()
    pending = [manifest.resolve()]
    seen = {manifest.resolve()}
    while pending:
        current = pending.pop()
        document = tomllib.loads(current.read_text())
        inherited, inherited_base = workspace_dependency_specs(current)
        tables = [
            document.get("dependencies") or {},
            document.get("build-dependencies") or {},
        ]
        for target in (document.get("target") or {}).values():
            tables.append(target.get("dependencies") or {})
            tables.append(target.get("build-dependencies") or {})
        for table in tables:
            for name, spec in table.items():
                if not isinstance(spec, dict):
                    continue
                base = current.parent
                if spec.get("workspace") is True:
                    if name not in inherited:
                        raise AssertionError(
                            f"{current}: dependency {name!r} inherits from a workspace "
                            f"that publishes no {name!r} entry, so no closure can read "
                            f"its path"
                        )
                    spec = inherited[name]
                    base = inherited_base
                    if not isinstance(spec, dict):
                        continue
                if "path" not in spec:
                    continue
                child = (base / spec["path"]).resolve() / "Cargo.toml"
                directories.add(str(child.parent.relative_to(root)))
                if child not in seen:
                    seen.add(child)
                    pending.append(child)
    return directories


def pattern_covers(patterns: set[str], path: str) -> bool:
    """Report whether a dorny/paths-filter pattern set selects one file path.

    A filter lists a file either by naming it (`'Cargo.toml'`) or by naming a
    directory glob above it (`'fuzz/**'` selects `fuzz/Cargo.lock`). Those two
    shapes are the only ones the filters this file reads use, so this covers
    them and nothing else; a filter written with a `*.toml` wildcard would read
    here as not covering, which errs toward reporting a gap rather than toward
    reporting a pass.
    """
    if path in patterns:
        return True
    return any(
        pattern.endswith("/**") and path.startswith(pattern[: -len("**")])
        for pattern in patterns
    )


def resolution_manifests(manifest: Path, root: Path | None = None) -> set[str]:
    """Return every manifest and lockfile a build from `manifest` resolves against.

    path_dependency_closure returns crate DIRECTORIES, and a cargo build reads
    two files that sit in no crate it compiles:

    - The workspace manifest each crate in the closure inherits from. Every
      `crates/scp-*` manifest carries entries reading `dep = { workspace = true }`
      and `edition.workspace = true`, whose values live in the repository root
      Cargo.toml, so a change confined to `[workspace.dependencies]` changes what
      a fuzz build and a wasm32 build compile while touching no crate directory.
    - The lockfile governing the starting manifest's workspace, which pins the
      version cargo resolves for every one of those entries. fuzz/Cargo.toml
      carries its own `[workspace]` table and its own fuzz/Cargo.lock, so a
      change to the repository root Cargo.lock does NOT reach a fuzz build; this
      returns the lockfile beside the starting manifest's workspace, never the
      repository root lockfile by default.

    Returns paths relative to `root`, so a caller compares them against a path
    filter through pattern_covers.
    """
    root = (REPO if root is None else root).resolve()
    start = manifest.resolve()
    files: set[str] = set()

    _, start_workspace = workspace_dependency_specs(start)
    lockfile = start_workspace / "Cargo.lock"
    if lockfile.is_file():
        files.add(str(lockfile.relative_to(root)))

    crate_manifests = [start] + [
        (root / directory / "Cargo.toml")
        for directory in path_dependency_closure(manifest, root)
    ]
    for crate_manifest in crate_manifests:
        _, workspace_base = workspace_dependency_specs(crate_manifest)
        workspace_manifest = (workspace_base / "Cargo.toml").resolve()
        if workspace_manifest != crate_manifest.resolve():
            files.add(str(workspace_manifest.relative_to(root)))
    return files


def workspace_member_directories(root: Path | None = None) -> set[str]:
    """Return every crate directory the root manifest's `[workspace] members` lists.

    A cargo command carrying `--workspace` compiles each of these, so a path
    filter selecting such a command must match a change to any file under any of
    them. Reading the list here rather than restating it means a crate added to
    the workspace later is covered the moment its member entry lands.

    Cargo accepts a glob in a member entry, so an entry holding `*` expands
    against the tree; every entry this repository writes today is a literal path.
    """
    root = (REPO if root is None else root).resolve()
    document = tomllib.loads((root / "Cargo.toml").read_text())
    members: set[str] = set()
    for entry in document["workspace"]["members"]:
        if "*" in entry:
            members |= {
                str(match.parent.relative_to(root))
                for match in root.glob(f"{entry}/Cargo.toml")
            }
        else:
            members.add(entry)
    return members


def directory_covered(patterns: set[str], directory: str) -> bool:
    """Report whether a dorny/paths-filter pattern set selects every file below one directory.

    An entry ending in `/**` selects every file below the prefix it names, so it
    covers a directory when that prefix is the directory itself or an ancestor of
    it — `crates/**` covers `crates/scp-event-log`. An entry naming a
    subdirectory, such as `crates/scp-runtime/src/**`, selects part of the
    directory and leaves the rest of it unmatched, so it does not cover; reading
    such an entry as covering is what let a manifest-only or README-only change
    to a listed crate skip the job that compiles it.
    """
    for pattern in patterns:
        if not pattern.endswith("/**"):
            continue
        prefix = pattern[: -len("/**")]
        if directory == prefix or directory.startswith(f"{prefix}/"):
            return True
    return False


def gating_filter_keys(doc: dict, job: dict) -> set[str]:
    """Return each paths-filter key that decides whether one job runs.

    A job reads `needs.<changes>.outputs.<name>` in its `if:`, and the `changes`
    job publishes each such name from an expression reading one or more
    `steps.<id>.outputs.<key>` values off its `dorny/paths-filter` step. This
    walks that second hop, so a caller compares a job against the path patterns
    that actually gate it rather than against a filter key someone assumed.
    """
    named = set(FILTER_REFERENCE.findall(str(job.get("if") or "")))
    keys: set[str] = set()
    for step in paths_filter_steps(doc):
        if step.step_id is None:
            continue
        outputs = doc["jobs"][step.job_id].get("outputs") or {}
        reference = re.compile(FILTER_STEP_REFERENCE.format(id=re.escape(step.step_id)))
        for name in named:
            keys |= set(reference.findall(str(outputs.get(name) or "")))
    return keys


def uncovered_members(patterns: set[str], members: set[str]) -> list[str]:
    """Return every workspace member no pattern in the set selects in full."""
    return sorted(
        directory for directory in members if not directory_covered(patterns, directory)
    )


def workspace_scoped_jobs(doc: dict):
    """Yield each job running a `--workspace` cargo command under a path filter.

    Yields `(job_id, keys, patterns)`, where `keys` names the paths-filter keys
    that decide whether the job runs and `patterns` holds their path entries. A
    job carrying no filter-gated `if:` runs on every event, so it needs no
    filter and this skips it.
    """
    steps = paths_filter_steps(doc)
    if not steps:
        return
    for job_id, job in sorted((doc.get("jobs") or {}).items()):
        workspace_wide = any(
            WORKSPACE_SCOPE_FLAG in line.split()
            for step in (job.get("steps") or [])
            if isinstance(step, dict)
            for line in logical_lines(step.get("run") or "")
        )
        if not workspace_wide:
            continue
        keys = gating_filter_keys(doc, job)
        if not keys:
            continue
        patterns = {
            pattern
            for step in steps
            for key in keys
            for pattern in (step.filters.get(key) or [])
        }
        yield job_id, keys, patterns


def check_workspace_scoped_filters(path: Path, doc: dict) -> None:
    """A filter gating a `--workspace` compile matches every member crate.

    CRITERION: a cargo command carrying `--workspace` compiles every member the
    root Cargo.toml lists, so a change to any one of them changes what that
    command compiles and must select the job running it.
    """
    members = workspace_member_directories()
    for job_id, keys, patterns in workspace_scoped_jobs(doc):
        missing = uncovered_members(patterns, members)
        check(
            f"{path.name}:{job_id}: its filter covers every workspace member",
            not missing,
            f"filter keys {sorted(keys)} leave {missing} unmatched — a change confined "
            f"to one of those skips a job that compiles it, and a skipped job counts "
            f"as a pass",
        )


def check_workspace_scope_detects_a_narrowed_filter(
    documents: list[tuple[Path, dict]],
) -> None:
    """Narrowing such a filter to one crate's `src/` fails the check above.

    CRITERION: uncovered_members reports a member the filter stops matching.
    Mutating a re-parsed copy of each real workflow proves that comparison runs
    over the shape those files carry. The mutation reproduces the exact defect
    this pair closes: the `docs` filter guarding `cargo doc --workspace` listed
    eleven `crates/<name>/src/**` entries out of twenty-six members, so a change
    confined to crates/scp-event-log skipped the one job that compiles rustdoc
    across the workspace.
    """
    members = workspace_member_directories()
    for path, _ in documents:
        # Re-parsed rather than mutated in place, so this mutation reaches no
        # other check reading the same document.
        doc = yaml.safe_load(path.read_text())
        for job_id, _keys, patterns in workspace_scoped_jobs(doc):
            sample = min(members)
            narrowed = {
                pattern
                for pattern in patterns
                if not any(directory_covered({pattern}, member) for member in members)
            } | {f"{sample}/src/**"}
            # Read as a delta against the unmutated filter, so a member the real
            # filter already leaves unmatched fails check_workspace_scoped_filters
            # above and leaves this pair reporting on the narrowing alone.
            gained = set(uncovered_members(narrowed, members)) - set(
                uncovered_members(patterns, members)
            )
            check(
                f"{path.name}:{job_id}: narrowing its filter to {sample}/src/ reports "
                f"the members it stops matching",
                gained,
                "the narrowing added no member to the unmatched set, so a filter "
                "listing crate directories one at a time would pass this self-test",
            )
            check(
                f"{path.name}:{job_id}: `{sample}/src/**` does not cover {sample}",
                sample in gained,
                "reading a `<crate>/src/**` entry as covering that crate would pass a "
                "filter that skips a change to its Cargo.toml or its README",
            )


def documents_private_items(command: str) -> bool:
    """Report whether one `cargo doc` command asks rustdoc to read private items.

    Splits on whitespace rather than through shlex, because a `run:` script in
    this repository holds shell quoting that shlex rejects mid-script, and a flag
    never carries a quote of its own.
    """
    return DOCUMENT_PRIVATE_ITEMS_FLAG in command.split()


def rustdoc_commands(doc: dict):
    """Yield `(job_id, command)` for every `cargo doc` a workflow runs."""
    for job_id, job in sorted((doc.get("jobs") or {}).items()):
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            for line in logical_lines(step.get("run") or ""):
                if line.split()[:2] == ["cargo", "doc"]:
                    yield job_id, line


def rustdoc_lint_level(root_document: dict) -> str | None:
    """Return the level the root manifest's `[workspace.lints.rustdoc]` gives RUSTDOC_LINT.

    Cargo accepts either `lint = "level"` or `lint = { level = "level", .. }`;
    both spellings read to the level string. A manifest that does not name the
    lint reads to None, which is rustdoc's default `warn` seen from the
    workspace's end.
    """
    entry = (
        root_document.get("workspace", {})
        .get("lints", {})
        .get("rustdoc", {})
        .get(RUSTDOC_LINT)
    )
    if isinstance(entry, dict):
        entry = entry.get("level")
    return entry if isinstance(entry, str) else None


def inherits_workspace_lints(member_document: dict) -> bool:
    """Report whether a member manifest declares `[lints] workspace = true`."""
    return member_document.get("lints", {}).get("workspace") is True


def check_rustdoc_lint_reaches_every_member(root: Path | None = None) -> None:
    """The workspace forbids the lint and every member inherits the table.

    CRITERION: cargo applies `[workspace.lints]` to a package only through that
    package's own `[lints] workspace = true`, so the lint's reach is the set of
    members carrying that line. Before this check, one member of 26 declared
    the lint in its lib.rs and job rust-doc exited 0 over 271 unresolved links
    in the other crate directories. Reading the members out of the root
    manifest means a crate added later is held to the lint the moment its
    member entry lands.
    """
    root = (REPO if root is None else root).resolve()
    root_document = tomllib.loads((root / "Cargo.toml").read_text())
    level = rustdoc_lint_level(root_document)
    check(
        f"Cargo.toml: [workspace.lints.rustdoc] sets {RUSTDOC_LINT} to "
        f"{RUSTDOC_LINT_LEVEL}",
        level == RUSTDOC_LINT_LEVEL,
        f"the root manifest gives rustdoc::{RUSTDOC_LINT} the level {level!r}, so "
        f"a broken intra-doc link is an error in no member (a `deny` would let any "
        f"member's `#![allow]` lower it back to a warning)",
    )
    for member in sorted(workspace_member_directories(root)):
        member_document = tomllib.loads((root / member / "Cargo.toml").read_text())
        check(
            f"{member}/Cargo.toml: [lints] workspace = true",
            inherits_workspace_lints(member_document),
            f"the member does not inherit [workspace.lints], so rustdoc documents "
            f"it under the default `warn` and both rustdoc jobs exit 0 over every "
            f"intra-doc link it breaks",
        )


def check_rustdoc_lint_readers_detect_a_lowered_level() -> None:
    """A lowered level and a member without the table flip the two predicates.

    CRITERION: rustdoc_lint_level reads the level out of the manifest and
    inherits_workspace_lints reads the boolean, so a manifest carrying `warn`,
    a manifest naming no rustdoc table, and a member manifest without `[lints]`
    each read as not held to the lint. Without this pair, a reader that always
    returned the forbid level would leave check_rustdoc_lint_reaches_every_member
    printing `ok` over a workspace that never set it.
    """
    lowered = {"workspace": {"lints": {"rustdoc": {RUSTDOC_LINT: "warn"}}}}
    lowered_table = {
        "workspace": {"lints": {"rustdoc": {RUSTDOC_LINT: {"level": "deny"}}}}
    }
    absent = {"workspace": {"lints": {"clippy": {"all": "warn"}}}}
    for name, document, expected in (
        ("a `warn` string reads as warn", lowered, "warn"),
        ("a `{ level = \"deny\" }` table reads as deny", lowered_table, "deny"),
        ("a manifest naming no rustdoc table reads as None", absent, None),
    ):
        check(
            f"rustdoc_lint_level: {name}",
            rustdoc_lint_level(document) == expected,
            f"rustdoc_lint_level returned {rustdoc_lint_level(document)!r}, so it "
            f"reads something other than the manifest's lint level",
        )
    for name, document in (
        ("a member with no [lints] table", {"package": {"name": "x"}}),
        ("a member setting [lints] workspace = false", {"lints": {"workspace": False}}),
        ("a member declaring its own lints", {"lints": {"rustdoc": {RUSTDOC_LINT: "forbid"}}}),
    ):
        check(
            f"inherits_workspace_lints: {name} -> not inherited",
            not inherits_workspace_lints(document),
            "inherits_workspace_lints returned True over a manifest carrying no "
            "`[lints] workspace = true`, so it reads something other than that line",
        )


def check_rustdoc_documents_private_items(
    documents: list[tuple[Path, dict]],
) -> None:
    """Every `cargo doc` command in every workflow documents private items.

    CRITERION: rustdoc resolves an intra-doc link only inside an item it
    documents. The workspace forbids `rustdoc::broken_intra_doc_links`
    (check_rustdoc_lint_reaches_every_member holds that), and that level fires on
    a link written in a private module only when the command passes
    `--document-private-items`, so a `cargo doc` run without the flag reports
    success over links it never read.
    """
    for path, doc in documents:
        for job_id, command in rustdoc_commands(doc):
            check(
                f"{path.name}:{job_id}: {command[:58]}",
                documents_private_items(command),
                f"omits {DOCUMENT_PRIVATE_ITEMS_FLAG} — rustdoc reads no intra-doc "
                f"link written in a private module without it, which is where all "
                f"three links pull request #2274, the structured "
                f"OutletErrorSurface change, broke lived",
            )


def check_private_items_detects_a_dropped_flag(
    documents: list[tuple[Path, dict]],
) -> None:
    """Dropping the flag from a real command fails the check above.

    CRITERION: documents_private_items reads the flag out of the command text,
    so removing it flips that predicate. Without this pair, a predicate that
    always returned True would leave check_rustdoc_documents_private_items
    printing `ok` over every command in the repository.
    """
    for path, _ in documents:
        doc = yaml.safe_load(path.read_text())
        for job_id, command in rustdoc_commands(doc):
            stripped = " ".join(
                token
                for token in command.split()
                if token != DOCUMENT_PRIVATE_ITEMS_FLAG
            )
            check(
                f"{path.name}:{job_id}: the flag removed -> the predicate reports it "
                f"missing",
                not documents_private_items(stripped),
                "documents_private_items returned True over a command carrying no "
                "--document-private-items, so it reads something other than the flag",
            )


NO_CARGO_PATH = "PATH=$no_cargo_path"


def no_cargo_gradle_calls(job: dict) -> list[str]:
    """Each `./gradlew` command line in `job` that runs with cargo off PATH."""
    return [
        line
        for step in job.get("steps", [])
        for line in logical_lines(step.get("run", ""))
        if NO_CARGO_PATH in line and "./gradlew" in line
    ]


def passes_no_daemon(line: str) -> bool:
    """Report whether one `./gradlew` command line passes --no-daemon."""
    return "--no-daemon" in line.split()


def check_no_cargo_gradle_calls_skip_the_daemon(jobs: dict) -> None:
    """kotlin-lint's cargo-free Gradle calls run without the shared daemon.

    CRITERION: a Gradle daemon that an earlier step started can resolve `cargo`
    against the PATH it started with, so a call that reuses it can reach the
    `cargo metadata` fallback whatever PATH the shell passes. Each call that
    strips cargo from PATH passes --no-daemon, and stripping the flag from each
    one fails the predicate.
    """
    calls = no_cargo_gradle_calls(jobs["kotlin-lint"])
    check(
        "kotlin-lint runs ./gradlew with cargo off PATH",
        len(calls) >= 2,
        f"found {len(calls)} such calls; the skip check and the "
        f"CARGO_TARGET_DIR loop each make one",
    )
    for line in calls:
        check(
            f"kotlin-lint: {line[:58]} passes --no-daemon",
            passes_no_daemon(line),
            "a reused daemon can resolve cargo against the PATH it started with",
        )
        stripped = " ".join(t for t in line.split() if t != "--no-daemon")
        check(
            f"kotlin-lint: {line[:40]} with --no-daemon removed -> reported",
            not passes_no_daemon(stripped),
            "the predicate accepted a call that reuses the daemon",
        )
    check(
        "passes_no_daemon rejects a token that only starts with --no-daemon",
        not passes_no_daemon("./gradlew --no-daemon-x detekt"),
        "the predicate matched a prefix rather than the whole flag",
    )


def check_workspace_and_rustdoc_readers(documents: list[tuple[Path, dict]]) -> None:
    """The two checks above read the jobs this file says they read.

    CRITERION: each check asserts over a set it discovers from the workflows, and
    a discovery returning nothing prints nothing. Comparing the discovered sets
    against WORKSPACE_SCOPED_JOBS and RUSTDOC_JOBS turns an emptied iteration
    into a named failure rather than into silence.
    """
    scoped = {
        (path.name, job_id)
        for path, doc in documents
        for job_id, _keys, _patterns in workspace_scoped_jobs(doc)
    }
    check(
        "the workspace-scope check reads every job WORKSPACE_SCOPED_JOBS names",
        scoped == WORKSPACE_SCOPED_JOBS,
        f"discovered {sorted(scoped)}, want {sorted(WORKSPACE_SCOPED_JOBS)} — a job "
        f"this check no longer reads is a job whose filter nothing checks",
    )
    rustdoc = {
        (path.name, job_id)
        for path, doc in documents
        for job_id, _command in rustdoc_commands(doc)
    }
    check(
        "the private-items check reads every job RUSTDOC_JOBS names",
        rustdoc == RUSTDOC_JOBS,
        f"discovered {sorted(rustdoc)}, want {sorted(RUSTDOC_JOBS)} — a `cargo doc` "
        f"this check no longer reads is a rustdoc run nothing checks",
    )


def check_path_dep_closures(jobs: dict) -> None:
    """Each named filter lists every directory its crate's build reads."""
    filters = path_filters(jobs)
    for filter_name, manifest in sorted(PATH_DEP_CLOSURE_FILTERS.items()):
        if filter_name not in filters:
            check(
                f"filter {filter_name!r} covers its path-dependency closure",
                False,
                f"job `changes` declares no {filter_name!r} filter; PATH_DEP_CLOSURE_FILTERS "
                f"names it, so either that filter was renamed or this entry is stale",
            )
            continue
        patterns = set(filters[filter_name])
        root = str(Path(manifest).parent)
        wanted = path_dependency_closure(REPO / manifest) | {root}
        missing = sorted(
            directory for directory in wanted if f"{directory}/**" not in patterns
        )
        check(
            f"filter {filter_name!r} covers its path-dependency closure",
            not missing,
            f"missing {[directory + '/**' for directory in missing]} — a change to "
            f"one of those skips every job this filter selects",
        )
        # A crate directory is not the whole of what a build reads: the
        # workspace manifest supplying every `workspace = true` entry, and the
        # lockfile pinning what those entries resolve to, sit outside every
        # directory above. Omitting them let a dependency bump touching only
        # Cargo.toml and Cargo.lock skip fuzz-build, typescript-wasm-check and
        # scaffold-typescript-web-check under a green `ci`.
        unlisted = sorted(
            path
            for path in resolution_manifests(REPO / manifest)
            if not pattern_covers(patterns, path)
        )
        check(
            f"filter {filter_name!r} lists the manifests its build resolves against",
            not unlisted,
            f"missing {unlisted} — a change confined to one of those changes what "
            f"this filter's jobs compile while every one of them skips",
        )


def write_inheritance_fixture(root: Path, publish_leaf: bool) -> Path:
    """Write a two-crate workspace whose consumer inherits its leaf dependency.

    A consumer declares `scp-fixture-leaf = { workspace = true }`, which carries
    no `path` key of its own. `publish_leaf` decides whether a root manifest's
    `[workspace.dependencies]` publishes that leaf. Returns a consumer manifest
    path.
    """
    leaf_entry = (
        'scp-fixture-leaf = { path = "crates/scp-fixture-leaf" }\n'
        if publish_leaf
        else ""
    )
    (root / "Cargo.toml").write_text(
        "[workspace]\n"
        'members = ["crates/scp-fixture-consumer", "crates/scp-fixture-leaf"]\n\n'
        "[workspace.dependencies]\n" + leaf_entry
    )
    for name in ("scp-fixture-consumer", "scp-fixture-leaf"):
        (root / "crates" / name).mkdir(parents=True)
    (root / "crates/scp-fixture-leaf/Cargo.toml").write_text(
        '[package]\nname = "scp-fixture-leaf"\nversion = "0.1.0"\n'
    )
    consumer = root / "crates/scp-fixture-consumer/Cargo.toml"
    consumer.write_text(
        '[package]\nname = "scp-fixture-consumer"\nversion = "0.1.0"\n\n'
        "[dependencies]\nscp-fixture-leaf = { workspace = true }\n"
    )
    return consumer


def check_closure_reads_workspace_inheritance() -> None:
    """A closure covers a dependency whose `path` lives in a workspace manifest.

    CRITERION: path_dependency_closure returns a directory for every crate a
    build compiles, however that crate's dependency entry is written. Cargo
    accepts two spellings — `path =` in a member manifest, and `workspace =
    true` resolved against a workspace manifest — and reading only a member's
    own table drops a crate written in a second spelling, along with every
    crate it reaches. check_path_dep_closures would then report a path filter
    complete while that filter omitted those directories, which is the defect
    that check exists to catch.
    """
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch) / "inherits"
        root.mkdir()
        consumer = write_inheritance_fixture(root, publish_leaf=True)
        reached = path_dependency_closure(consumer, root=root)
        check(
            "a closure covers a dependency inherited from a workspace manifest",
            reached == {"crates/scp-fixture-leaf"},
            f"reached {sorted(reached)}, want ['crates/scp-fixture-leaf'] — a "
            f"`workspace = true` entry carries its path in a workspace manifest",
        )

        unpublished = Path(scratch) / "unpublished"
        unpublished.mkdir()
        orphan = write_inheritance_fixture(unpublished, publish_leaf=False)
        raised = False
        try:
            path_dependency_closure(orphan, root=unpublished)
        except AssertionError:
            raised = True
        check(
            "an inherited name no workspace publishes stops a closure",
            raised,
            "path_dependency_closure returned a set instead of raising, so an "
            "unreadable entry would shrink a closure rather than fail this self-test",
        )


def check_resolution_manifests_reach_the_workspace() -> None:
    """The files a build resolves against include its workspace manifest and lock.

    CRITERION: resolution_manifests returns every file cargo reads to decide
    what a build compiles, beyond the crate directories path_dependency_closure
    already returns. A member crate carrying `dep = { workspace = true }` reads
    that entry's version out of a workspace manifest and its resolved version
    out of that workspace's lockfile, so a change confined to either changes
    what the build compiles while touching no crate directory.

    Two negative cases hold the boundary. A crate whose own manifest carries the
    `[workspace]` table contributes no separate workspace manifest, because
    `fuzz/**` already covers fuzz/Cargo.toml. A workspace holding no Cargo.lock
    contributes no lockfile, because a filter cannot list a file the tree does
    not carry.
    """
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch) / "inherits"
        root.mkdir()
        consumer = write_inheritance_fixture(root, publish_leaf=True)

        without_lock = resolution_manifests(consumer, root=root)
        check(
            "a build resolving against a workspace manifest lists that manifest",
            without_lock == {"Cargo.toml"},
            f"returned {sorted(without_lock)}, want ['Cargo.toml'] — a "
            f"`workspace = true` entry reads its version out of that manifest",
        )

        (root / "Cargo.lock").write_text("version = 4\n")
        with_lock = resolution_manifests(consumer, root=root)
        check(
            "a build lists the lockfile of the workspace it resolves in",
            with_lock == {"Cargo.toml", "Cargo.lock"},
            f"returned {sorted(with_lock)}, want ['Cargo.lock', 'Cargo.toml'] — a "
            f"lockfile pins what every inherited entry resolves to",
        )

        # A standalone crate carrying its own `[workspace]` table, the shape
        # fuzz/Cargo.toml has. Its own manifest and its own lockfile sit inside
        # the directory a filter already names, so neither is returned; the
        # enclosing workspace's lockfile must not be returned either, because
        # this crate never resolves against it.
        standalone = root / "standalone"
        standalone.mkdir()
        (standalone / "Cargo.toml").write_text(
            '[package]\nname = "scp-fixture-standalone"\nversion = "0.0.0"\n\n'
            "[workspace]\n\n"
            "[dependencies]\n"
            'scp-fixture-leaf = { path = "../crates/scp-fixture-leaf" }\n'
        )
        reached = resolution_manifests(standalone / "Cargo.toml", root=root)
        check(
            "a crate carrying its own workspace table lists no enclosing lockfile",
            reached == {"Cargo.toml"},
            f"returned {sorted(reached)}, want ['Cargo.toml'] — this crate resolves "
            f"in its own workspace, and its leaf dependency inherits from the "
            f"enclosing one",
        )


def cargo_test_commands(job: dict) -> list[list[str]]:
    """Return every `cargo test` / `cargo nextest run` command a job's steps run.

    Each command comes back as a token list with every `${{ … }}` collapsed to
    one token. A `--no-run` command drops out: it compiles a test binary and
    executes no assertion, so it cannot satisfy a criterion about running one.
    """
    commands = []
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        for line in logical_lines(step.get("run") or ""):
            if not line.startswith(("cargo test ", "cargo nextest run ")):
                continue
            tokens = split_command(line)
            if "--no-run" in tokens:
                continue
            commands.append(tokens)
    return commands


def command_packages(tokens: list[str]) -> set[str]:
    """Return the packages a cargo command selects by `-p` or `--package`."""
    packages, take_next = set(), False
    for token in tokens:
        if take_next:
            packages.add(token)
            take_next = False
        elif token in {"-p", "--package"}:
            take_next = True
    return packages


def command_excludes(tokens: list[str]) -> set[str]:
    """Return the packages a cargo command drops with `--exclude`."""
    excluded, take_next = set(), False
    for token in tokens:
        if take_next:
            excluded.add(token)
            take_next = False
        elif token == "--exclude":
            take_next = True
    return excluded


def command_covers_package(tokens: list[str], package: str) -> bool:
    """Whether a cargo command compiles and runs `package`'s tests.

    A command names a package with `-p`/`--package`, or takes every workspace
    member with `--workspace`/`--all` and drops members with `--exclude`.
    Reading `-p` alone reported job rust-test's `cargo nextest run --workspace`
    as running no package at all, which would have left scp-identity's two
    shipped-build assertions unchecked.
    """
    if package in command_excludes(tokens):
        return False
    if package in command_packages(tokens):
        return True
    return bool({"--workspace", "--all"} & set(tokens))


def command_enables_testing(tokens: list[str], package: str) -> bool:
    """Whether a cargo command's own text turns `testing` on for `package`.

    Reads each `--features` value (cargo splits one value on commas and on
    spaces) and `--all-features`, which enables every feature `package`
    declares, `testing` included. A `testing` feature a MANIFEST turns on is
    invisible in a command's text, so check_shipped_build_assertions_run pairs
    this reader with command_unifies_testing, which reads the manifests a
    command's build includes.
    """
    if "--all-features" in tokens:
        return True
    for index, token in enumerate(tokens):
        if token != "--features" or index + 1 >= len(tokens):
            continue
        for feature in tokens[index + 1].replace(",", " ").split():
            if feature in {"testing", f"{package}/testing"}:
                return True
    return False


# Every dependency section a Cargo manifest may carry. testing_edge scans all
# three in every manifest it reads, although a dev-dependency joins feature
# unification only when cargo builds that manifest's own test targets. Its
# callers use a found edge to REJECT a lane, so counting a dev section in a
# crate the build reaches as a plain dependency errs toward reporting a gap
# rather than toward passing one.
DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def testing_edge(manifest: Path, package: str) -> str | None:
    """Return how `manifest` turns `package`'s `testing` feature on, or None.

    Two spellings count: a dependency entry on `package` whose `features` list
    names `testing` (its own list, or the list of the `[workspace.dependencies]`
    entry it inherits), and a `[features]` table value naming
    `"<package>/testing"`. A feature-table value fires only when its own
    feature is enabled, and an `optional = true` dependency only when some
    feature activates it; this reader counts both unconditionally, which errs
    toward reporting a gap rather than toward passing one.
    """
    document = tomllib.loads(manifest.read_text())
    inherited, _ = workspace_dependency_specs(manifest)
    tables = [document.get(section) or {} for section in DEPENDENCY_SECTIONS]
    for target in (document.get("target") or {}).values():
        tables += [target.get(section) or {} for section in DEPENDENCY_SECTIONS]
    for table in tables:
        for name, spec in table.items():
            if not isinstance(spec, dict):
                continue
            features = list(spec.get("features") or [])
            renamed = spec.get("package")
            if spec.get("workspace") is True and isinstance(
                inherited.get(name), dict
            ):
                features += inherited[name].get("features") or []
                renamed = renamed or inherited[name].get("package")
            if (renamed or name) != package:
                continue
            if "testing" in features:
                return (
                    f"{manifest} declares a dependency on {package} with "
                    f'`features = ["testing"]`'
                )
    for feature, implies in (document.get("features") or {}).items():
        for entry in implies:
            if str(entry).replace("?", "") == f"{package}/testing":
                return (
                    f"{manifest} feature {feature!r} names "
                    f'"{package}/testing"'
                )
    return None


def member_manifests(root: Path) -> dict[str, Path]:
    """Return each workspace member's package name mapped to its manifest.

    Reads the literal entries of the root manifest's `[workspace] members`
    list. Cargo also accepts glob patterns there; this repository writes none,
    and a glob entry names no directory holding a Cargo.toml, so reading one
    raises here — a future glob fails this self-test loudly rather than
    dropping members from every scan built on this map.
    """
    document = tomllib.loads((root / "Cargo.toml").read_text())
    members: dict[str, Path] = {}
    for entry in document["workspace"]["members"]:
        manifest = root / entry / "Cargo.toml"
        name = tomllib.loads(manifest.read_text())["package"]["name"]
        members[name] = manifest
    return members


def dev_path_dependency_manifests(manifest: Path) -> set[Path]:
    """Return the manifest of every crate `manifest`'s dev sections reach by path."""
    inherited, inherited_base = workspace_dependency_specs(manifest)
    document = tomllib.loads(manifest.read_text())
    tables = [document.get("dev-dependencies") or {}]
    for target in (document.get("target") or {}).values():
        tables.append(target.get("dev-dependencies") or {})
    found: set[Path] = set()
    for table in tables:
        for name, spec in table.items():
            if not isinstance(spec, dict):
                continue
            base = manifest.parent
            if spec.get("workspace") is True:
                if not isinstance(inherited.get(name), dict):
                    continue
                spec, base = inherited[name], inherited_base
            if "path" in spec:
                found.add((base / spec["path"]).resolve() / "Cargo.toml")
    return found


def test_build_manifests(manifest: Path, root: Path) -> set[Path]:
    """Return every manifest a `cargo test`/`cargo nextest run` over
    `manifest`'s package reads: the manifest itself, each crate its dev
    sections reach by path, and the no-dev path-dependency closure of each of
    those — which together are the crates cargo compiles for that package's
    test targets.
    """
    manifests = {manifest.resolve()}
    for start in {manifest} | dev_path_dependency_manifests(manifest):
        manifests.add(start.resolve())
        for directory in path_dependency_closure(start, root):
            manifests.add((root / directory / "Cargo.toml").resolve())
    return manifests


def command_unifies_testing(
    tokens: list[str], package: str, root: Path = REPO
) -> str | None:
    """Return the manifest edge turning `package/testing` on in this command's
    build, or None when no manifest that build includes carries one.

    One cargo invocation resolves ONE feature set per package, so a build that
    includes any manifest enabling `package/testing` compiles that package's
    `#[cfg(not(feature = "testing"))]` tests out, whatever the command's own
    text says — crates/scp-testing/Cargo.toml did exactly that to
    scp-identity's two fail-closed assertions in job rust-test's workspace
    lane. A `--workspace`/`--all` build includes every non-excluded member's
    test-build manifests (an `--exclude`d member still gets built, and
    scanned, when a selected member depends on it), and a `-p` build includes
    each named package's. A `-p` package no workspace member declares comes
    back as its own finding rather than as a pass.
    """
    members = member_manifests(root)
    if {"--workspace", "--all"} & set(tokens):
        selected = [
            manifest
            for name, manifest in members.items()
            if name not in command_excludes(tokens)
        ]
    else:
        selected = []
        for name in sorted(command_packages(tokens)):
            if name not in members:
                return (
                    f"no workspace member is named {name}, so no manifest "
                    f"scan can prove `testing` off for its build"
                )
            selected.append(members[name])
    manifests: set[Path] = set()
    for manifest in selected:
        manifests |= test_build_manifests(manifest, root)
    for manifest in sorted(manifests):
        edge = testing_edge(manifest, package)
        if edge is not None:
            return edge
    return None


# A filterset this reader models: one or more `test(SUBSTRING)` predicates
# joined by `+` or `|`, which are nextest's two union operators. A union selects
# a test that any one predicate selects, so reading each predicate on its own
# decides the whole expression.
#
# CRITERION for what this reader accepts: the expression must be a union of
# `test()` predicates and nothing else. nextest also offers `-` (difference),
# `not`, `and`, `&`, and set functions such as `all()` and `binary()`, and each
# of those can REMOVE a test a `test()` predicate selected. Reading one of them
# as a union would report a test as running that nextest never runs, so
# check_shipped_build_assertions_run fails a job whose filterset this pattern
# does not match rather than guessing at its meaning.
NEXTEST_UNION_FILTERSET = re.compile(
    r"^\s*test\(([^()]*)\)\s*(?:[+|]\s*test\(([^()]*)\)\s*)*$"
)
NEXTEST_TEST_PREDICATE = re.compile(r"test\(([^()]*)\)")


def filterset_patterns(text: str) -> list[str] | None:
    """Return the substrings a `-E` filterset matches on, or None if unmodelled.

    Returns None when `text` is anything other than a union of `test()`
    predicates, so a caller fails loud instead of reading a difference or a
    negation as a union.
    """
    if not NEXTEST_UNION_FILTERSET.match(text):
        return None
    return [m.group(1).strip() for m in NEXTEST_TEST_PREDICATE.finditer(text)]


def command_filters(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Return (name substrings this command filters on, unmodelled filtersets).

    An empty pair means the command runs every test its packages compile.
    """
    patterns: list[str] = []
    unmodelled: list[str] = []
    for index, token in enumerate(tokens):
        if token in {"-E", "--filter-expr", "--filterset"} and index + 1 < len(tokens):
            parsed = filterset_patterns(tokens[index + 1])
            if parsed is None:
                unmodelled.append(tokens[index + 1])
            else:
                patterns += parsed
    patterns += positional_filters(" ".join(shlex.quote(t) for t in tokens))
    return patterns, unmodelled


def command_selects(tokens: list[str], test_name: str) -> bool:
    """Whether a cargo command runs `test_name`, given it covers its package.

    A command carrying no name filter runs every test its package compiles.
    Every filter nextest and libtest take — a positional argument, and the
    argument of a `test()` predicate — is a SUBSTRING of a test's full name, so
    a filter selects `test_name` when `test_name` CONTAINS it. Reading the
    containment the other way round (the filter text naming the test in full)
    reported job fail-closed-pre-rotation's
    `-E 'test(pre_rotation_severance)'` as selecting neither scp-node
    assertion, which is why this check formerly skipped that job's package
    outright.
    """
    patterns, unmodelled = command_filters(tokens)
    if unmodelled:
        return False
    if not patterns:
        return True
    return any(pattern in test_name for pattern in patterns)


def owning_package(source: Path) -> str:
    """Return the package name of the nearest ancestor manifest of `source`.

    Resolves a file to a package by walking up to the first Cargo.toml carrying
    a `[package]` table, rather than by matching a directory prefix: a prefix
    map put crates/scp-ffi/tests/ in no package, and a bridge assertion added
    there would have gone unscanned.
    """
    for directory in source.parents:
        manifest = directory / "Cargo.toml"
        if manifest.is_file():
            table = tomllib.loads(manifest.read_text()).get("package")
            if table and "name" in table:
                return str(table["name"])
        # The root manifest declares a virtual workspace and no package, so the
        # walk stops here rather than leaving this repository.
        if directory == REPO:
            break
    raise SystemExit(f"{source}: no ancestor Cargo.toml declares a package")


def package_test_functions() -> dict[str, dict[str, tuple[Path, bool]]]:
    """Return every test function under crates/, by package and function name.

    Each entry maps a test-function name to its file and to whether the
    function carries SHIPPED_ONLY_ATTRIBUTE, which is the attribute that
    compiles the function into a build carrying no `testing` feature and out of
    every other build. Reads attributes written one per line above the `fn`
    they annotate, in either order and with other attributes and comment lines
    between them, which is the layout `cargo fmt` produces. Reads every `.rs`
    file under crates/, so a package this repository adds later is scanned
    without editing this file.
    """
    found: dict[str, dict[str, tuple[Path, bool]]] = {}
    for source in sorted((REPO / "crates").rglob("*.rs")):
        attributes: list[str] = []
        for line in source.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#["):
                attributes.append(stripped)
                continue
            if not stripped or stripped.startswith("//"):
                continue
            name = RUST_FN_NAME.search(stripped)
            if name and any(TEST_ATTRIBUTE.match(a) for a in attributes):
                package = owning_package(source)
                found.setdefault(package, {})[name.group(1)] = (
                    source,
                    SHIPPED_ONLY_ATTRIBUTE in attributes,
                )
            attributes = []
    return found


def shipped_build_assertions() -> dict[str, dict[str, Path]]:
    """Return each package's shipped-build assertions, by test-function name.

    A shipped-build assertion is a test function carrying
    SHIPPED_ONLY_ATTRIBUTE. Filters package_test_functions above rather than
    scanning again, so both readers agree on which functions are tests.
    """
    found: dict[str, dict[str, Path]] = {}
    for package, tests in package_test_functions().items():
        assertions = {
            name: source for name, (source, shipped_only) in tests.items() if shipped_only
        }
        if assertions:
            found[package] = assertions
    return found


def check_shipped_assertion_readers() -> None:
    """Drive the four readers check_shipped_build_assertions_run rests on.

    That check decides whether a fail-closed proof executes anywhere, and it
    decides it by asking command_covers_package, filterset_patterns, and
    command_selects about a command's tokens, and package_test_functions which
    tests a package defines. A reader that answered "yes" to every question
    would leave that check reporting success over work it did not do, so each
    case below states an input whose answer is known and asserts the reader
    returns it. The synthetic tokens are written here rather than read from
    ci.yml, so a workflow edit cannot make a case vacuous.
    """
    uniffi_tests = package_test_functions().get("scp-ffi-uniffi", {})
    gated = uniffi_tests.get("shipped_build_reaches_every_callback_custody_identity_op")
    ungated = uniffi_tests.get("ucan_mint_works_over_callback_custody")
    check(
        "package_test_functions marks a `cfg(not(testing))` test shipped-only",
        gated is not None and gated[1],
        "job rust-build-uniffi-production's first filterset names only tests a "
        "`testing` flip deletes, and reading this one as surviving that flip "
        "would let an un-gated test join that filterset unreported",
    )
    check(
        "package_test_functions marks an un-gated test as surviving a flip",
        ungated is not None and not ungated[1],
        "this test carries no cfg attribute, so a reader that reported it "
        "shipped-only would accept it in the filterset that must empty when "
        "`testing` turns on",
    )
    workspace = split_command("cargo nextest run --workspace")
    excluded = split_command("cargo nextest run --workspace --exclude scp-identity")
    named = split_command("cargo nextest run -p scp-node --lib")
    check(
        "command_covers_package reads --workspace as covering a member",
        command_covers_package(workspace, "scp-identity"),
        "job rust-test runs `cargo nextest run --workspace`, so reading -p alone "
        "would leave scp-identity's assertions checked by nothing",
    )
    check(
        "command_covers_package reads --exclude as dropping a member",
        not command_covers_package(excluded, "scp-identity"),
        "--exclude removes the package from the run, so reporting it covered "
        "would claim an assertion runs that nextest never compiles",
    )
    check(
        "command_covers_package reads a package a command never names as uncovered",
        not command_covers_package(named, "scp-identity"),
        "this command names scp-node alone",
    )

    prefix_filter = split_command(
        "cargo nextest run --no-tests=fail -p scp-node --lib "
        "-E 'test(pre_rotation_severance)'"
    )
    check(
        "command_selects reads a test() predicate as nextest does, by substring",
        command_selects(prefix_filter, "pre_rotation_severance_generate_fails_closed"),
        "nextest's test(SUBSTRING) matches every test whose name contains "
        "SUBSTRING, so a filter naming a prefix does select this assertion",
    )
    check(
        "command_selects rejects a name its filter's substring does not appear in",
        not command_selects(
            prefix_filter, "generate_fails_closed_without_pre_rotation_backend"
        ),
        "renaming an assertion out of a lane's -E filter must red this check; "
        "the lane itself stays green because a sibling keeps the selection "
        "non-empty under --no-tests=fail",
    )
    check(
        "command_selects reads an unfiltered command as running every test",
        command_selects(workspace, "pre_rotation_severance_generate_fails_closed"),
        "`cargo nextest run --workspace` carries no name filter",
    )

    check(
        "command_enables_testing reads --all-features as enabling `testing`",
        command_enables_testing(
            split_command("cargo test -p scp-ffi --all-features"), "scp-ffi"
        ),
        "--all-features turns every declared feature on, `testing` included, "
        "so a lane carrying it proves nothing about a shipped build",
    )
    check(
        "filterset_patterns reads a union of test() predicates",
        filterset_patterns("test(alpha) + test(beta)") == ["alpha", "beta"],
        "the pyo3 lane joins two predicates with +",
    )
    difference = split_command("cargo nextest run -p scp-node -E 'all() - test(alpha)'")
    check(
        "filterset_patterns refuses a filterset it does not model",
        filterset_patterns("all() - test(alpha)") is None,
        "a difference removes tests a test() predicate selected, so reading it "
        "as a union would report an assertion running that nextest skips",
    )
    check(
        "command_selects reports no selection for a filterset it does not model",
        not command_selects(difference, "alpha_fails_closed"),
        "an unmodelled filterset must fail this check by name rather than pass "
        "on a guess about what it selects",
    )


def write_unification_fixture(root: Path) -> None:
    """Write a five-crate workspace holding each spelling of a manifest edge
    that turns a sibling's `testing` feature on.

    leaf     declares the feature and no dependencies.
    enabler  depends on leaf with `features = ["testing"]` — the
             dependency-entry spelling that crates/scp-runtime/Cargo.toml and
             crates/scp-ffi/common/Cargo.toml write against scp-identity in
             their `[dev-dependencies]`; testing_edge reads the three
             dependency sections identically.
    implier  declares a feature naming `"leaf/testing"`, the spelling
             crates/scp-identity/Cargo.toml's `testing` feature carries against
             scp-dht.
    middle   depends on enabler and never names leaf.
    selfdev  dev-depends on itself with `features = ["testing"]`, the spelling
             crates/scp-dht/Cargo.toml uses to turn its own feature on in its
             tests.
    """
    (root / "Cargo.toml").write_text(
        "[workspace]\n"
        'members = ["leaf", "enabler", "implier", "middle", "selfdev"]\n'
    )
    bodies = {
        "leaf": "[features]\ntesting = []\n",
        "enabler": (
            "[dependencies]\n"
            'leaf = { path = "../leaf", features = ["testing"] }\n'
        ),
        "implier": (
            '[features]\nhelpers = ["leaf/testing"]\n\n'
            "[dependencies]\n"
            'leaf = { path = "../leaf" }\n'
        ),
        "middle": '[dependencies]\nenabler = { path = "../enabler" }\n',
        "selfdev": (
            "[features]\ntesting = []\n\n"
            "[dev-dependencies]\n"
            'selfdev = { path = ".", features = ["testing"] }\n'
        ),
    }
    for name, body in bodies.items():
        (root / name).mkdir(parents=True)
        (root / name / "Cargo.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "0.1.0"\n\n{body}'
        )


def check_testing_unification_readers() -> None:
    """Drive command_unifies_testing over a fixture workspace and this one.

    check_shipped_build_assertions_run rests on this reader to reject a lane
    whose BUILD turns a paired package's `testing` feature on through a
    manifest the command's text never mentions. A reader answering "no edge"
    to every question would re-green the pairing this file's unified-feature
    entry records: scp-identity paired with job rust-test, whose workspace
    build reads every manifest turning `scp-identity/testing` on — the
    `[dev-dependencies]` of crates/scp-testing/Cargo.toml,
    crates/scp-runtime/Cargo.toml and crates/scp-ffi/common/Cargo.toml — and
    compiles both of scp-identity's
    fail-closed assertions out.
    """
    workspace = split_command("cargo nextest run --workspace")
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch) / "unify"
        root.mkdir()
        write_unification_fixture(root)
        check(
            "a --workspace build scans every member for a `testing` edge",
            command_unifies_testing(workspace, "leaf", root) is not None,
            "member `enabler` turns leaf/testing on and the reader missed it",
        )
        check(
            "a -p build over the package alone proves `testing` off",
            command_unifies_testing(
                split_command("cargo nextest run -p leaf --lib"), "leaf", root
            )
            is None,
            "no manifest in leaf's own build enables leaf/testing, so "
            "reporting an edge here would red every honest -p lane",
        )
        check(
            "a -p build reaches a `testing` edge through its dependency closure",
            command_unifies_testing(
                split_command("cargo test -p middle"), "leaf", root
            )
            is not None,
            "middle's build compiles enabler, whose manifest turns "
            "leaf/testing on",
        )
        check(
            "a self dev-dependency counts against its own package",
            command_unifies_testing(
                split_command("cargo test -p selfdev"), "selfdev", root
            )
            is not None,
            "selfdev's dev-dependency on itself turns selfdev/testing on in "
            "every `cargo test -p selfdev` build",
        )
        check(
            "--exclude does not un-build a member a selected member depends on",
            command_unifies_testing(
                split_command("cargo nextest run --workspace --exclude enabler"),
                "leaf",
                root,
            )
            is not None,
            "middle still compiles enabler, so excluding enabler removes no "
            "edge from the build",
        )
        check(
            "excluding every member that reaches the edge clears it",
            command_unifies_testing(
                split_command(
                    "cargo nextest run --workspace --exclude enabler "
                    "--exclude implier --exclude middle"
                ),
                "leaf",
                root,
            )
            is None,
            "leaf and selfdev remain, and neither reaches enabler's manifest "
            "nor implier's feature table",
        )
        check(
            "a feature-table value naming `leaf/testing` is an edge",
            command_unifies_testing(
                split_command("cargo test -p implier"), "leaf", root
            )
            is not None,
            "implier's `helpers` feature names \"leaf/testing\", the spelling "
            "crates/scp-identity/Cargo.toml's `testing` feature carries "
            "against scp-dht",
        )
        check(
            "a -p package no workspace member declares is a finding, not a pass",
            command_unifies_testing(
                split_command("cargo test -p ghost"), "leaf", root
            )
            is not None,
            "an unresolvable package must fail toward reporting a gap",
        )

    # This repository is the live fixture for the defect this reader exists to
    # catch: the edge is real, and so is the lane that avoids it.
    live_edge = command_unifies_testing(workspace, "scp-identity")
    scp_testing_manifest = REPO / "crates" / "scp-testing" / "Cargo.toml"
    # Two conjuncts, each able to go red on its own. The first asks whether a
    # workspace build reads any manifest edge turning scp-identity/testing on.
    # Which edge command_unifies_testing returns is an artifact of sorted-path
    # order — crates/scp-ffi/common/Cargo.toml and crates/scp-runtime/Cargo.toml
    # sort ahead of crates/scp-testing/Cargo.toml — so the second conjunct names
    # the manifest this entry records by asking testing_edge, the one-manifest
    # reader command_unifies_testing is built on, about that manifest alone.
    # Whether scp-testing's own `testing` feature compiles src/helpers.rs is a
    # fact of the build cargo resolves, not of manifest text, and job
    # rust-test-optional-features checks it with
    # `cargo check -p scp-testing --lib --features testing`.
    scp_testing_edge = testing_edge(scp_testing_manifest, "scp-identity")
    check(
        "a workspace build turns scp-identity/testing on through scp-testing",
        live_edge is not None and scp_testing_edge is not None,
        f"got workspace edge {live_edge!r} and scp-testing edge "
        f"{scp_testing_edge!r} — crates/scp-testing/Cargo.toml gives its "
        f'`[dev-dependencies]` entry on scp-identity the feature "testing", and '
        f"a reader that misses it re-greens pairing scp-identity's assertions "
        f"with a workspace lane",
    )
    check(
        "a -p scp-identity build leaves scp-identity/testing off",
        command_unifies_testing(
            split_command(
                "cargo nextest run --no-tests=fail -p scp-identity --lib "
                "-E 'test(fails_closed_without_pre_rotation_backend)'"
            ),
            "scp-identity",
        )
        is None,
        "job fail-closed-pre-rotation's scp-identity step rests on a -p "
        "selection leaving scp-testing out of the build",
    )


def check_shipped_build_assertions_run(jobs: dict) -> None:
    """Every bridge's shipped-build assertions run in a production-config lane.

    CRITERION: stated at SHIPPED_CONFIG_LANES. Two checks carry it, and both
    read SHIPPED_CONFIG_LANES and NON_BRIDGE_SHIPPED_ASSERTION_LANES at one
    strength. The first requires each job either table names to run a test
    command over each package it is paired with, whose build leaves that
    package's `testing` feature off — off in the command's `--features` text
    (command_enables_testing), and enabled by no manifest that build includes
    (command_unifies_testing) — a FLOOR, so a package holding no
    shipped-build assertion today still gets a lane that would run one
    tomorrow. The second scans every `.rs` file under crates/ and requires each
    shipped-build assertion it finds to be SELECTED BY NAME by a command in the
    job its package is paired with. The third requires each such command that
    carries a name filter to select shipped-build assertions ALONE, so that
    turning `testing` on empties its selection and `--no-tests=fail` exits 4: a
    filtered command that also selects a test surviving that flip exits 0 over
    an empty set of proofs.

    The second check formerly skipped every package in
    NON_BRIDGE_SHIPPED_ASSERTION_LANES, asking only whether that table's job
    id was defined. Renaming `pre_rotation_severance_generate_fails_closed` out
    of job fail-closed-pre-rotation's `-E 'test(pre_rotation_severance)'` filter
    would then have left that assertion running in no lane while this check and
    that job both reported success — a check reporting success over work it did
    not do, which is the defect the pull request holding this file exists to
    remove.
    """
    # package -> every job id either table pairs it with. A set, not one id, so
    # listing a package under two lanes reads both jobs' commands instead of
    # letting whichever sorted last silently replace the other.
    lanes: dict[str, set[str]] = {}
    for job_id, packages in sorted(SHIPPED_CONFIG_LANES.items()):
        for package in sorted(packages):
            lanes.setdefault(package, set()).add(job_id)
    for package, job_id in sorted(NON_BRIDGE_SHIPPED_ASSERTION_LANES.items()):
        present = job_id in jobs
        check(
            f"{job_id}, which runs {package}'s shipped-build assertions, exists",
            present,
            f"ci.yml defines no job {job_id}",
        )
        if present:
            lanes.setdefault(package, set()).add(job_id)

    executing: dict[str, list[list[str]]] = {}
    for package, job_ids in sorted(lanes.items()):
        for job_id in sorted(job_ids):
            # Looked up by key so a renamed job raises a KeyError here rather
            # than leaving this check running over nothing and reporting a pass.
            selecting: list[list[str]] = []
            rejected: list[str] = []
            for tokens in cargo_test_commands(jobs[job_id]):
                if not command_covers_package(tokens, package):
                    continue
                if command_enables_testing(tokens, package):
                    rejected.append(
                        f"`{' '.join(tokens)}` names `testing` for {package} "
                        f"in its own text"
                    )
                    continue
                edge = command_unifies_testing(tokens, package)
                if edge is not None:
                    rejected.append(f"`{' '.join(tokens)}`: {edge}")
                    continue
                selecting.append(tokens)
            executing.setdefault(package, []).extend(selecting)
            check(
                f"{job_id} runs {package}'s tests with `testing` off",
                bool(selecting),
                f"this job runs no `cargo test`/`cargo nextest run` whose build "
                f"leaves `testing` off for {package}, so every "
                f'`#[cfg(not(feature = "testing"))]` test in {package} compiles '
                f"in a lane that never executes it"
                + ("; rejected: " + "; ".join(rejected) if rejected else ""),
            )

    # CRITERION: a command carrying a name filter and selecting a shipped-build
    # assertion selects shipped-build assertions ALONE. `--no-tests=fail` fires
    # only on an EMPTY selection, so a sibling that stays compiled when
    # `testing` flips on keeps that command's selection non-empty, the run exits
    # 0, and every fail-closed proof the command exists to run executed nowhere.
    # Measured on this tree: adding four un-gated
    # `ucan_*_over_callback_custody` tests to job
    # rust-build-uniffi-production's one filterset made that command select at
    # least four tests in every feature configuration.
    #
    # A command carrying NO name filter is outside this criterion, and job
    # rust-test-napi-production's `cargo test -p scp-ffi-common` is one: it runs
    # every test the package compiles, so no filter can be written that empties
    # on a flip, and it claims no `--no-tests=fail` tripwire.
    # command_unifies_testing above reads that command's build for a `testing`
    # edge, and it reads it out of manifest TEXT, which means enumerating the
    # spellings cargo accepts — a denylist, and one this repository has already
    # watched fail to converge (.docs/lessons/
    # ast-gate-checks-definition-not-name-resolution.md). Two spellings escape
    # it today: `default = ["testing"]` and any other feature list naming
    # `"testing"`, both written inside scp-ffi-common's own manifest, where the
    # reader looks for a dependency entry on scp-ffi-common and for the string
    # "scp-ffi-common/testing" and finds neither. So that reader is a fast
    # secondary, not the guarantee. check_shipped_assertion_tripwires below
    # states the guarantee: every package carrying shipped-build assertions is
    # also run by a `--no-tests=fail` command that selects those assertions
    # alone, which empties and exits 4 on any spelling because it reads the
    # build cargo resolved rather than a manifest.
    all_tests = package_test_functions()
    for package, commands in sorted(executing.items()):
        tests = all_tests.get(package, {})
        for tokens in commands:
            patterns, unmodelled = command_filters(tokens)
            if not patterns or unmodelled:
                continue
            selected = {name for name in tests if command_selects(tokens, name)}
            assertions_selected = sorted(n for n in selected if tests[n][1])
            others = sorted(n for n in selected if not tests[n][1])
            if not assertions_selected:
                continue
            check(
                f"{package}: `{' '.join(tokens)[:58]}` empties on a `testing` flip",
                not others,
                f"it runs shipped-build assertions {assertions_selected} "
                f"alongside {others}, which carry no "
                f'`#[cfg(not(feature = "testing"))]`, so turning `testing` on '
                f"deletes every assertion while those keep the selection "
                f"non-empty and `--no-tests=fail` never fires; run them under a "
                f"separate `cargo nextest run` instead",
            )

    for package, assertions in sorted(shipped_build_assertions().items()):
        check(
            f"{package}'s shipped-build assertions belong to a lane this check reads",
            package in lanes,
            f"{package} defines {sorted(assertions)} and appears in neither "
            f"SHIPPED_CONFIG_LANES nor NON_BRIDGE_SHIPPED_ASSERTION_LANES, so no "
            f"entry here states which job runs them",
        )
        named = sorted(lanes.get(package, set())) or ["(no lane named)"]
        for test_name, source in sorted(assertions.items()):
            check(
                f"{source.relative_to(REPO)}:{test_name} runs in a shipped-config lane",
                any(
                    command_selects(tokens, test_name)
                    for tokens in executing.get(package, [])
                ),
                f"no command in {named} selects it, so this fail-closed proof "
                f"executes nowhere",
            )


def check_shipped_assertion_tripwires(jobs: dict) -> None:
    """Every package with shipped-build assertions is run by an empty-selection
    tripwire: a `--no-tests=fail` command selecting those assertions alone.

    CRITERION: for each package that shipped_build_assertions names, some job
    either lane table pairs it with runs a command that carries
    `--no-tests=fail`, carries a name filter this file models, selects at least
    one of that package's shipped-build assertions, and selects no test that
    survives a `testing` flip. Such a command decides the question from the
    build cargo resolved: a shipped-build assertion compiles into a build
    carrying no `testing` feature and out of every other build, so a build that
    turned the feature on selects zero tests and nextest exits 4.

    WHY THIS CHECK EXISTS BESIDE check_shipped_build_assertions_run. That check
    asks whether a lane's command leaves `testing` off, and answers it with
    command_enables_testing (the command's own `--features` text) and
    command_unifies_testing (the manifests the build reads). The second reader
    parses manifest text, so it answers correctly only for the spellings it
    enumerates, and two spellings escape it — a package's own
    `default = ["testing"]`, and any other feature of that package whose list
    names `"testing"`, neither of which is a dependency entry on the package
    nor the string `"<package>/testing"`. A tripwire cannot be escaped that
    way, because it reads no manifest.

    Four of the five packages shipped_build_assertions names already had one:
    job rust-build-pyo3-production for scp-ffi, job
    rust-build-uniffi-production for scp-ffi-uniffi, and job
    fail-closed-pre-rotation for scp-identity and scp-node. scp-ffi-common had
    only the unfiltered `cargo test -p scp-ffi-common` of job
    rust-test-napi-production, which exits 0 over the package's un-gated tests
    when both of its assertions compiled out. This check is what keeps the
    command that closed that hole from being deleted again.
    """
    lanes: dict[str, set[str]] = {}
    for job_id, packages in sorted(SHIPPED_CONFIG_LANES.items()):
        for package in sorted(packages):
            lanes.setdefault(package, set()).add(job_id)
    for package, job_id in sorted(NON_BRIDGE_SHIPPED_ASSERTION_LANES.items()):
        lanes.setdefault(package, set()).add(job_id)

    all_tests = package_test_functions()
    for package, assertions in sorted(shipped_build_assertions().items()):
        tests = all_tests.get(package, {})
        job_ids = sorted(lanes.get(package, set()))
        # Looked up by key so a renamed job raises a KeyError here rather than
        # leaving this check running over no commands and reporting a pass.
        tripwires: list[str] = []
        for job_id in job_ids:
            for tokens in cargo_test_commands(jobs[job_id]):
                if "--no-tests=fail" not in tokens:
                    continue
                if not command_covers_package(tokens, package):
                    continue
                patterns, unmodelled = command_filters(tokens)
                if not patterns or unmodelled:
                    continue
                selected = {name for name in tests if command_selects(tokens, name)}
                if not selected & set(assertions):
                    continue
                if any(not tests[name][1] for name in selected):
                    continue
                tripwires.append(" ".join(tokens))
        check(
            f"{package}'s shipped-build assertions run under an empty-selection tripwire",
            bool(tripwires),
            f"no command in {job_ids or ['(no lane named)']} carries "
            f"`--no-tests=fail`, a name filter, and a selection holding "
            f"{sorted(assertions)} and nothing that survives a `testing` flip, "
            f"so a build that turned `{package}/testing` on by a spelling "
            f"command_unifies_testing does not parse would compile every one of "
            f"those assertions out and still exit 0",
        )


def check_filter_keys_agree(path: Path, doc: dict) -> None:
    """A `changes` output reads a key its paths-filter step defines, and no other.

    CRITERION: for each `dorny/paths-filter` step, the set of keys the enclosing
    job's expressions read off that step equals the set of keys that step's
    `filters:` block defines, PATHS_FILTER_BUILTIN_OUTPUTS aside.

    check_filter_outputs_gate_jobs below reads the consumer side of this wiring,
    `needs.changes.outputs.<key>`, and scripts/ci-aggregate-result.py exits 2 on
    a job condition naming an output `changes` did not publish. Neither reads the
    producer side: nine expressions in ci.yml and one in docs.yml read
    `steps.filter.outputs.<key>`, and a key misspelled there yields the empty
    string, so that output publishes "false" on every run. The aggregate then
    reads "false" as "this job was not supposed to run" and exits 0, which is the
    same verdict it gives a genuine docs-only change.
    """
    for step in paths_filter_steps(doc):
        label = f"{path.name}:{step.job_id}"
        check(
            f"{label}: its dorny/paths-filter step carries an `id`",
            step.step_id is not None,
            "a step publishes its outputs under its own id, so a step carrying no "
            "id publishes nothing any expression can read",
        )
        if step.step_id is None:
            continue
        referenced = filter_step_references(step.job, step.step_id)
        undefined, unread = filter_key_disagreements(step.filters, referenced)
        check(
            f"{label}: every filter output it reads is a filter it defines",
            not undefined,
            f"reads {undefined} off step {step.step_id!r}, whose `filters:` block "
            f"defines {sorted(step.filters)} — dorny/paths-filter publishes nothing "
            f"under a key it does not define, so each of those reads the empty "
            f"string and publishes 'false' on every run, which skips every job it "
            f"gates under a green `ci`",
        )
        check(
            f"{label}: every filter it defines reaches an output",
            not unread,
            f"defines {unread}, which no expression in job {step.job_id} reads, so "
            f"no job can be gated on {unread} and each of those filters selects "
            f"nothing",
        )


def check_filter_key_agreement_detects_a_rename(
    documents: list[tuple[Path, dict]],
) -> None:
    """Renaming a filter key without its output expression fails the check above.

    CRITERION: filter_key_disagreements reports a renamed key from both ends —
    the output expression then reads a key nothing defines, and the `filters:`
    block then defines a key no output reads. Mutating a re-parsed copy of each
    real workflow proves that comparison runs over the shape those files carry:
    `rust` renamed to `ruts` in ci.yml's `outputs:` mapping left both gates that
    read that file green, which is the defect this pair closes.
    """
    for path, _ in documents:
        # Re-parsed rather than mutated in place, so this mutation reaches no
        # other check reading the same document.
        for step in paths_filter_steps(yaml.safe_load(path.read_text())):
            if step.step_id is None:
                continue
            referenced = filter_step_references(step.job, step.step_id)
            shared = sorted(referenced & set(step.filters))
            if not shared:
                continue
            target = shared[0]
            renamed = dict(step.filters)
            renamed[f"{target}-renamed"] = renamed.pop(target)
            # Read as a delta against the unmutated document, so that a
            # disagreement this workflow already carries fails
            # check_filter_keys_agree above and leaves this pair reporting on
            # the rename alone.
            before = filter_key_disagreements(step.filters, referenced)
            after = filter_key_disagreements(renamed, referenced)
            undefined = set(after[0]) - set(before[0])
            unread = set(after[1]) - set(before[1])
            check(
                f"{path.name}:{step.job_id}: renaming filter {target!r} reports a "
                f"key nothing defines",
                undefined == {target},
                f"the rename added {sorted(undefined)} to the keys nothing defines, "
                f"want [{target!r}] — an output expression reading a renamed key "
                f"would otherwise pass this self-test",
            )
            check(
                f"{path.name}:{step.job_id}: renaming filter {target!r} reports a "
                f"filter nothing reads",
                unread == {f"{target}-renamed"},
                f"the rename added {sorted(unread)} to the filters nothing reads, "
                f"want ['{target}-renamed'] — a filter no output reads gates no job",
            )


def check_filter_outputs_gate_jobs(jobs: dict) -> None:
    """A `changes` filter output appears only in a job-level `if:`.

    CRITERION: every `needs.changes.outputs.*` reference in this workflow sits
    in a job's own `if:`. A step-level reference produces a job that reports
    success having run nothing, and scripts/ci-aggregate-result.py judges a
    dependency by reading that dependency's job-level `if:`, so it reads such a
    job as a job that ran. Job rust-test carried seven step-level references and
    no job-level `if:`, which made a renamed filter output green over zero
    tests.
    """
    for job_id, job in sorted(jobs.items()):
        offenders = []
        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            named = sorted(set(FILTER_REFERENCE.findall(str(step.get("if") or ""))))
            if named:
                name = step.get("name") or step.get("uses") or f"step {index}"
                offenders.append(f"{name!r} names {named}")
        check(
            f"{job_id}: no step gates on a filter output",
            not offenders,
            "; ".join(offenders)
            + " — a step-level filter condition makes this job report success over "
            "zero work when that output changes; gate the job instead",
        )


def check_signing_guard(documents: list[tuple[Path, dict]]) -> None:
    """Every job publishing a `-signed` artifact rejects an empty input set first.

    CRITERION: in release.yml, a job that uploads an artifact whose name ends in
    SIGNED_ARTIFACT_SUFFIX runs GUARD_SCRIPT at a step index below that upload.
    Each of the three signing loops iterates whatever a file search returned, and
    a search matching nothing makes the loop run zero times and exit 0, after
    which the upload publishes an artifact whose name asserts a signature the
    artifact does not carry.

    The suffix is a mechanical proxy for that criterion, so SIGNING_JOBS holds a
    floor under it: renaming an artifact out of the suffix would otherwise leave
    this check passing over zero uploads.

    This pins wiring and nothing else. Whether GUARD_SCRIPT rejects an empty set
    is a separate question, which scripts/tests/signing-guard/run-tests.sh
    answers by running it against fixture directories.
    """
    # Looked up by key, not filtered for: a renamed workflow raises a KeyError
    # here rather than leaving this check running over nothing and reporting a
    # pass.
    jobs = {path.name: doc for path, doc in documents}["release.yml"]["jobs"]

    guarded_jobs = set()
    for job_id, job in sorted(jobs.items()):
        steps = job.get("steps") or []
        uploads = [
            index
            for index, step in enumerate(steps)
            if isinstance(step, dict)
            and str(step.get("uses") or "").startswith("actions/upload-artifact")
            and str((step.get("with") or {}).get("name", "")).endswith(
                SIGNED_ARTIFACT_SUFFIX
            )
        ]
        if not uploads:
            continue
        guarded_jobs.add(job_id)
        guard = [
            index
            for index, step in enumerate(steps)
            if isinstance(step, dict) and GUARD_SCRIPT in str(step.get("run") or "")
        ]
        names = [
            str((steps[index].get("with") or {}).get("name", "")) for index in uploads
        ]
        check(
            f"release.yml:{job_id} runs {GUARD_SCRIPT} before it uploads {', '.join(names)}",
            bool(guard) and min(guard) < min(uploads),
            f"guard at steps {guard}, upload at steps {uploads} — an empty "
            f"signing set otherwise reaches {', '.join(names)}",
        )

    missing = sorted(SIGNING_JOBS - guarded_jobs)
    check(
        "release.yml: every known signing job publishes a "
        f"{SIGNED_ARTIFACT_SUFFIX} artifact this check can see",
        not missing,
        f"{', '.join(missing)} uploads no artifact whose name ends in "
        f"{SIGNED_ARTIFACT_SUFFIX}, so the suffix criterion above ran over zero "
        "of its uploads",
    )


def cargo_doc_commands(doc: dict) -> list[tuple[str, str]]:
    """Return (job_id, command) for every `cargo doc` a workflow's steps run."""
    found = []
    for job_id, job in sorted((doc.get("jobs") or {}).items()):
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            for line in logical_lines(step.get("run") or ""):
                if line.startswith("cargo doc ") or line == "cargo doc":
                    found.append((job_id, line))
    return found


def command_flags(command: str) -> set[str]:
    """Return a command's flags, each carrying its value when it takes one.

    A flag written `--features a,b` and one written `--features=a,b` normalize
    to the same members, and a comma-separated value splits into one member per
    element, so a command enabling fewer features compares as a subset rather
    than as a difference.
    """
    flags: set[str] = set()
    pending: str | None = None
    for token in split_command(command):
        if pending is not None:
            name, value = pending, token
            pending = None
        elif token in VALUE_FLAGS:
            pending = token
            continue
        elif token.startswith("-"):
            name, _, value = token.partition("=")
        else:
            continue
        if not value:
            flags.add(name)
        else:
            flags.update(f"{name}={element}" for element in value.split(","))
    if pending is not None:
        flags.add(pending)
    return flags


def required_rustdoc_flags(documents: list[tuple[Path, dict]]) -> set[str]:
    """Return the flags every `cargo doc` in the required workflow passes."""
    flags: set[str] = set()
    for path, doc in documents:
        if path == WORKFLOW:
            for _, command in cargo_doc_commands(doc):
                flags |= command_flags(command)
    return flags


def rustdoc_surface_gaps(
    documents: list[tuple[Path, dict]], required: set[str]
) -> list[tuple[Path, str, set[str]]]:
    """Return each rustdoc outside the required workflow and the flags it adds.

    A returned entry names a `cargo doc` command, and the flags it passes that
    `required` does not carry. Each such flag enlarges what rustdoc resolves in
    that command alone, so a diagnostic it produces reaches no required status
    check.
    """
    gaps = []
    for path, doc in documents:
        if path == WORKFLOW:
            continue
        for job_id, command in cargo_doc_commands(doc):
            gaps.append((path, job_id, command_flags(command) - required))
    return gaps


def check_required_rustdoc_surface(documents: list[tuple[Path, dict]]) -> None:
    """The required check's rustdoc reads whatever any other workflow's reads.

    THE CRITERION: a rustdoc diagnostic that any workflow in this repository
    can produce, `ci` can produce. `ci` is the sole required status check on the
    Default ruleset, so a diagnostic only an advisory workflow produces blocks
    no merge, and a pull request carrying that diagnostic merges under a green
    required check.

    A `cargo doc` flag decides which items rustdoc resolves links on, so a flag
    one command carries and the required check's command omits names a
    diagnostic class the required check cannot produce. This check compares the
    two flag sets rather than naming `--document-private-items`, so a flag added
    to docs.yml later fails here until ci.yml carries it too.
    """
    required = required_rustdoc_flags(documents)
    check(
        f"{WORKFLOW.name} runs rustdoc",
        bool(required),
        "no `cargo doc` command — a required check running no rustdoc produces "
        "no rustdoc diagnostic",
    )
    for path, job_id, missing in rustdoc_surface_gaps(documents, required):
        check(
            f"{path.name}:{job_id} rustdoc surface reaches {WORKFLOW.name}",
            not missing,
            f"{sorted(missing)} enlarge what rustdoc reads in a workflow the "
            f"ruleset does not require, and nothing in `ci` reads it",
        )


def check_rustdoc_surface_detects_a_dropped_flag(
    documents: list[tuple[Path, dict]],
) -> None:
    """Dropping a flag from the required rustdoc fails the check above.

    CRITERION: rustdoc_surface_gaps reports a flag that an advisory workflow's
    rustdoc passes and the required workflow's rustdoc does not. Dropping one
    flag at a time from the required set proves the comparison runs over the
    commands these workflows carry rather than over an empty set — a comparison
    that read no command would report no gap and pass the check above, which is
    the shape ci.yml carried while `--document-private-items` sat in docs.yml
    alone.
    """
    required = required_rustdoc_flags(documents)
    elsewhere = {
        flag
        for path, doc in documents
        if path != WORKFLOW
        for _, command in cargo_doc_commands(doc)
        for flag in command_flags(command)
    }
    shared = sorted(required & elsewhere)
    check(
        "a rustdoc outside the required workflow shares a flag with it",
        bool(shared),
        "no shared flag — this mutation would drop nothing and report nothing",
    )
    # Read as a delta against the unmutated set, so that a gap these workflows
    # already carry fails check_required_rustdoc_surface above and leaves this
    # mutation reporting on the dropped flag alone.
    baseline = {
        missing_flag
        for _, _, missing in rustdoc_surface_gaps(documents, required)
        for missing_flag in missing
    }
    for flag in shared:
        reported = {
            missing_flag
            for _, _, missing in rustdoc_surface_gaps(documents, required - {flag})
            for missing_flag in missing
        } - baseline
        check(
            f"dropping {flag} from {WORKFLOW.name}'s rustdoc reports it",
            reported == {flag},
            f"reported {sorted(reported)}, want [{flag!r}] — a required check "
            f"omitting that flag would otherwise pass this self-test",
        )


def tracked_markdown_paths() -> list[str]:
    """Return every Markdown file this repository tracks, repository-relative."""
    proc = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted(name for name in proc.stdout.split("\0") if name)


def fenced_shell_blocks(text: str) -> list[str]:
    """Return the body of each fenced block whose label names a shell.

    A fence opens on a line whose first three non-space characters are three
    backticks followed by a language label, and closes on the next line opening
    with three backticks. A block whose label names no shell — `rust`, `yaml`,
    an empty label — returns nothing, because a reader does not run its contents.
    The label is the first word after the backticks, so an attribute a renderer
    accepts after it (```bash title="x") leaves the language readable.
    """
    blocks: list[str] = []
    language: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            if language is None:
                label = stripped[3:].strip().lower().split()
                language = label[0] if label else ""
            else:
                if language in SHELL_FENCE_LANGUAGES:
                    blocks.append("\n".join(body))
                language, body = None, []
            continue
        if language is not None:
            body.append(line)
    return blocks


def documented_rustdoc_commands() -> list[tuple[str, str]]:
    """Return (path, command) for each `cargo doc` a Markdown shell block runs."""
    found = []
    for path in tracked_markdown_paths():
        text = (REPO / path).read_text(encoding="utf-8")
        if "cargo doc" not in text:
            continue
        for block in fenced_shell_blocks(text):
            for line in logical_lines(block):
                if line.startswith("cargo doc ") or line == "cargo doc":
                    found.append((path, line))
    return found


def documented_rustdoc_gaps(
    commands: list[tuple[str, str]], required: set[str]
) -> list[tuple[str, str, set[str], set[str]]]:
    """Return each documented rustdoc, the flags it drops, and the ones it adds.

    A returned entry names a command, the required job's flags it omits, and the
    `--features` members it passes that the required job does not. The first set
    is what makes a green local run prove less than the merge waits on; the
    second is what makes a red local run report a break the merge does not have.
    """
    gaps = []
    for path, command in commands:
        flags = command_flags(command)
        extra_features = {
            flag for flag in flags - required if flag.startswith(FEATURES_FLAG_PREFIX)
        }
        gaps.append((path, command, required - flags, extra_features))
    return gaps


def check_documented_rustdoc_reproduces_the_required_job(
    documents: list[tuple[Path, dict]],
) -> None:
    """A `cargo doc` this repository documents reports what the merge waits on.

    THE CRITERION: a developer who copies a `cargo doc` command out of a
    Markdown shell block and runs it reads the diagnostics job `rust-doc` in
    .github/workflows/ci.yml produces, and reads no others. `ci` is the sole
    required status check on the Default ruleset, so that job's output is what
    decides a merge, and a documented command reporting anything else sends the
    developer after a break the merge does not have or hides one it does.
    """
    required = required_rustdoc_flags(documents)
    commands = documented_rustdoc_commands()
    carriers = {path for path, _ in commands}
    check(
        "every file DOCUMENTED_RUSTDOC_FILES names documents a rustdoc command",
        carriers == DOCUMENTED_RUSTDOC_FILES,
        f"found {sorted(carriers)}, want {sorted(DOCUMENTED_RUSTDOC_FILES)} — a "
        f"documented `cargo doc` this scan no longer reads is a command nothing "
        f"compares against {WORKFLOW.name}",
    )
    for path, command, missing, extra in documented_rustdoc_gaps(commands, required):
        check(
            f"{path} documents a rustdoc that reproduces {WORKFLOW.name}'s",
            not missing and not extra,
            f"{command!r} omits {sorted(missing)} and adds {sorted(extra)} — a "
            f"developer running it reads a different diagnostic set than the one "
            f"a merge waits on",
        )


def check_documented_rustdoc_detects_a_feature_drift(
    documents: list[tuple[Path, dict]],
) -> None:
    """Perturbing the required flag set fails the check above.

    CRITERION: documented_rustdoc_gaps reports a flag the required job passes
    and a documented command omits, and reports a `--features` member the
    documented command passes and the required job omits. Adding one flag to the
    required set and removing one from it proves the comparison runs over the
    commands these Markdown files carry rather than over an empty set — a
    comparison reading no command reports no gap and passes the check above,
    which is the shape every check in this file's docstring shares.
    """
    required = required_rustdoc_flags(documents)
    commands = documented_rustdoc_commands()
    check(
        "the documented-rustdoc scan reads at least one command",
        bool(commands),
        "no `cargo doc` in any Markdown shell block — this mutation would "
        "perturb nothing and report nothing",
    )
    invented = "--nonexistent-rustdoc-flag"
    reported = {
        flag
        for _, _, missing, _ in documented_rustdoc_gaps(commands, required | {invented})
        for flag in missing
    }
    check(
        f"a required flag no documented command carries reports as {invented}",
        reported == {invented},
        f"reported {sorted(reported)}, want [{invented!r}] — a documented command "
        f"omitting a required flag would otherwise pass the check above",
    )
    features = sorted(
        flag for flag in required if flag.startswith(FEATURES_FLAG_PREFIX)
    )
    check(
        f"{WORKFLOW.name}'s rustdoc passes a feature this mutation can withdraw",
        bool(features),
        "no `--features` member — this mutation would withdraw nothing",
    )
    for feature in features:
        reported = {
            flag
            for _, _, _, extra in documented_rustdoc_gaps(
                commands, required - {feature}
            )
            for flag in extra
        }
        check(
            f"withdrawing {feature} from {WORKFLOW.name}'s rustdoc reports it",
            reported == {feature},
            f"reported {sorted(reported)}, want [{feature!r}] — a documented "
            f"command enabling a feature the required job does not would "
            f"otherwise pass the check above",
        )


def lines_outside_shell_blocks(text: str) -> list[tuple[int, str]]:
    """Return (line number, text) for each Markdown line no shell block encloses.

    A fence line returns nothing, and so does every line a fence this file's
    shell set labels encloses, because documented_rustdoc_commands already reads
    those. A fence labelled anything else keeps its body, so relabelling a
    `cargo doc` block from ```bash to ```text moves the command into this
    scan rather than out of every scan in this file.

    A line ending in a backslash joins the line after it and reports under the
    first line's number, because a shell command written across two Markdown
    lines names its command on one and its flags on the next.
    """
    kept: list[tuple[int, str]] = []
    language: str | None = None
    pending: tuple[int, str] | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            if language is None:
                label = stripped[3:].strip().lower().split()
                language = label[0] if label else ""
            else:
                language = None
            continue
        if language is not None and language in SHELL_FENCE_LANGUAGES:
            continue
        if pending is None:
            start, joined = number, stripped
        else:
            start, joined = pending[0], f"{pending[1]} {stripped}"
        if joined.endswith("\\"):
            pending = (start, joined[:-1].rstrip())
            continue
        kept.append((start, joined))
        pending = None
    if pending is not None:
        kept.append(pending)
    return kept


def rustdoc_enumerations_outside_shell_blocks(text: str) -> list[tuple[int, str]]:
    """Return each line writing a `cargo doc` with `--features` outside a block."""
    return [
        (number, line)
        for number, line in lines_outside_shell_blocks(text)
        if "cargo doc" in line and FEATURES_FLAG in line
    ]


def unheld_rustdoc_enumerations() -> list[tuple[str, int, str]]:
    """Return every rustdoc flag enumeration in Markdown that no check reads."""
    found: list[tuple[str, int, str]] = []
    for path in tracked_markdown_paths():
        text = (REPO / path).read_text(encoding="utf-8")
        if "cargo doc" not in text:
            continue
        for number, line in rustdoc_enumerations_outside_shell_blocks(text):
            found.append((path, number, line))
    return found


def check_rustdoc_enumerations_sit_in_a_shell_block() -> None:
    """Every rustdoc flag enumeration in Markdown sits where a check reads it.

    THE CRITERION, stated at FEATURES_FLAG above: Markdown text writing out the
    flag set job `rust-doc` in .github/workflows/ci.yml passes sits inside a
    shell-labelled fenced block, which is the only place
    check_documented_rustdoc_reproduces_the_required_job compares a documented
    command against that job. An enumeration outside such a block reaches no
    comparison, so a later edit to the required job's `--features` list leaves it
    stating flags the merge no longer waits on while this file reports every
    assertion passing.
    """
    unheld = unheld_rustdoc_enumerations()
    check(
        "every rustdoc `--features` enumeration in Markdown sits in a shell block",
        not unheld,
        "; ".join(f"{path}:{number} writes {line!r}" for path, number, line in unheld)
        + " — a `cargo doc` naming `--features` outside a shell-labelled fence "
        "reaches no comparison against the required job, so its flags drift while "
        "this self-test stays green",
    )


def check_enumeration_scan_reads_the_text_it_is_given() -> None:
    """Perturbing a document reports through the check above.

    CRITERION: rustdoc_enumerations_outside_shell_blocks reports a `cargo doc`
    written with `--features` in running text, in a table cell, in a fence
    labelled for a language nobody runs, and across a backslash continuation,
    and reports nothing for the same command inside a shell block. A scan whose
    match never fires reports nothing on every document and leaves the check
    above passing over zero lines — the zero-test defect this file's docstring
    records. The scan reads the tree through tracked_markdown_paths, so this
    check also asserts that iteration reaches a file naming `cargo doc`.
    """
    carriers = [
        path
        for path in tracked_markdown_paths()
        if "cargo doc" in (REPO / path).read_text(encoding="utf-8")
    ]
    check(
        "the enumeration scan reads at least one Markdown file naming `cargo doc`",
        bool(carriers),
        "no tracked Markdown file names `cargo doc` — the check above would "
        "iterate nothing and report nothing",
    )
    command = (
        "cargo doc --workspace --document-private-items --features scp-core/testing"
    )
    cases: list[tuple[str, str, list[int]]] = [
        (
            "running text naming a rustdoc with `--features` reports",
            f"Generate with `{command}` before pushing.\n",
            [1],
        ),
        (
            "a table cell naming a rustdoc with `--features` reports",
            f"| doc | ubuntu-latest | `{command}` |\n",
            [1],
        ),
        (
            "a rustdoc with `--features` in a fence naming no shell reports",
            f"```text\n{command}\n```\n",
            [2],
        ),
        (
            "a rustdoc whose `--features` sits after a backslash reports",
            "Run `cargo doc --workspace \\\n--features scp-core/testing`.\n",
            [1],
        ),
        (
            "the same rustdoc inside a shell block reports nothing",
            f"```bash\n{command}\n```\n",
            [],
        ),
        (
            "a rustdoc naming no `--features` reports nothing",
            "The job ran `cargo doc --workspace --document-private-items`.\n",
            [],
        ),
    ]
    for name, document, want in cases:
        reported = rustdoc_enumerations_outside_shell_blocks(document)
        got = [number for number, _ in reported]
        check(
            name,
            got == want,
            f"reported lines {got}, want {want} — {document!r}",
        )


def workflow_triggers(doc: dict) -> set[str]:
    """Return the event names a workflow triggers on.

    PyYAML resolves the unquoted key `on` to the boolean True, so a caller
    reading `doc["on"]` reads nothing on every workflow in this repository.
    """
    node = doc.get(True, doc.get("on"))
    if isinstance(node, (dict, list)):
        return set(node)
    return {node} if isinstance(node, str) else set()


def check_merge_queue_triggers(documents: list[tuple[Path, dict]]) -> None:
    """A workflow written to be required also runs on the merge_group event.

    CRITERION: a merge queue evaluates every required status check against the
    `merge_group` ref, so a workflow that never runs on that event reports no
    check there and every queue entry waits on a status that never arrives.
    INDICATOR that a workflow is written for that role: it skips its jobs
    through a `dorny/paths-filter` output instead of failing them, which is the
    shape that exists so a skipped job reports success to branch protection.
    The header of .github/workflows/docs.yml states that reason in those words.
    """
    for path, doc in documents:
        triggers = workflow_triggers(doc)
        if "pull_request" not in triggers or not paths_filter_steps(doc):
            continue
        check(
            f"{path.name} runs on merge_group",
            "merge_group" in triggers,
            f"triggers on {sorted(triggers)} — its jobs skip to a success status "
            f"so branch protection can require them, and a required check that "
            f"never runs on the merge_group ref holds every queue entry pending",
        )


def collect_pinned_nightlies(doc: dict) -> set[str]:
    """Return every date-pinned nightly a workflow's steps request."""
    pinned = set()
    for job in doc["jobs"].values():
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            requested = str((step.get("with") or {}).get("toolchain", ""))
            if DATE_PINNED_NIGHTLY.match(requested):
                pinned.add(requested)
    return pinned


# One token of an `if:` expression: an operator, a parenthesis, a quoted literal, a
# dotted name, or a whole number. A `!` standing alone matches nothing here, and a
# function call's name followed by `(` fails the grammar in parse_condition.
CONDITION_TOKEN = re.compile(r"&&|\|\||==|!=|\(|\)|'[^']*'|[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+")
CONDITION_OPERATORS = frozenset(("&&", "||", "==", "!=", "(", ")"))


@functools.lru_cache(maxsize=None)
def parse_condition(expression: str) -> tuple:
    """Parse one `if:` expression into a tree, raising ValueError outside the grammar.

    A node is ("or" | "and", parts) or ("==" | "!=", left, right). The grammar is
    the one every `if:` in these workflows uses: comparisons with `==` or `!=`,
    joined by `&&` and `||`, with `&&` binding tighter, as it does in GitHub's
    expression language, and parentheses grouping.
    """
    text = " ".join(str(expression).split())
    tokens: list[str] = []
    rest = text.lstrip()
    while rest:
        match = CONDITION_TOKEN.match(rest)
        if match is None:
            raise ValueError(f"expression this check cannot read: {text!r}")
        tokens.append(match.group(0))
        rest = rest[match.end() :].lstrip()
    if not tokens:
        raise ValueError(f"empty expression this check cannot read: {text!r}")

    def chain(index: int, joiner: str, inner) -> tuple[tuple, int]:
        node, index = inner(index)
        parts = [node]
        while index < len(tokens) and tokens[index] == joiner:
            node, index = inner(index + 1)
            parts.append(node)
        if len(parts) == 1:
            return parts[0], index
        return ("or" if joiner == "||" else "and", tuple(parts)), index

    def either(index: int) -> tuple[tuple, int]:
        return chain(index, "||", both)

    def both(index: int) -> tuple[tuple, int]:
        return chain(index, "&&", comparison)

    def comparison(index: int) -> tuple[tuple, int]:
        if index < len(tokens) and tokens[index] == "(":
            node, index = either(index + 1)
            if index >= len(tokens) or tokens[index] != ")":
                raise ValueError(f"unbalanced parenthesis this check cannot read: {text!r}")
            return node, index + 1
        if index + 3 > len(tokens):
            raise ValueError(f"comparison this check cannot read: {text!r}")
        left, operator, right = tokens[index : index + 3]
        if (
            operator not in ("==", "!=")
            or left in CONDITION_OPERATORS
            or right in CONDITION_OPERATORS
        ):
            raise ValueError(f"comparison this check cannot read: {text!r}")
        return (operator, left, right), index + 3

    tree, index = either(0)
    if index != len(tokens):
        raise ValueError(f"expression this check cannot read past {tokens[index]!r}: {text!r}")
    return tree


def selects(expression: str, outputs: dict[str, str], event_name: str) -> bool:
    """Report whether one `if:` expression selects a job under one set of inputs.

    Written here rather than imported from scripts/ci-aggregate-result.py for the
    reason this file's closing paragraph gives: an assertion that calls the function
    it judges agrees with that function however it behaves. parse_condition states
    the grammar. An expression outside it raises, which stops this check rather than
    guessing. Every operand is resolved whatever the other comparisons answer, so a
    filter output `changes` never published raises even behind a false
    `github.event_name != 'push' &&`.
    """

    def operand(token: str) -> str:
        quoted = re.fullmatch(r"'([^']*)'", token)
        if quoted:
            return quoted.group(1)
        if token in ("true", "false"):
            return token
        if token == "github.event_name":
            return event_name
        if token == "github.event.pull_request.draft":
            # Held at false, so the enumeration covers the runs in which check-draft
            # runs. On a draft pull request check-draft skips, every job that needs it
            # skips with it, and scripts/ci-aggregate-result.py returns 0 on exactly
            # that state, because GitHub blocks merging a draft and a merge queue
            # re-runs this workflow on a merge_group event where the gate applies. A
            # draft run therefore has no job whose skip a merge could ride, which is
            # the state this check looks for.
            return "false"
        prefix = "needs.changes.outputs."
        if token.startswith(prefix):
            key = token[len(prefix) :]
            if key not in outputs:
                raise ValueError(f"filter output `changes` never published: {key!r}")
            return outputs[key]
        raise ValueError(f"operand this check cannot read: {token!r}")

    def value(node: tuple) -> bool:
        kind = node[0]
        if kind in ("or", "and"):
            results = [value(part) for part in node[1]]
            return any(results) if kind == "or" else all(results)
        left, right = operand(node[1]), operand(node[2])
        return (left == right) if kind == "==" else (left != right)

    return value(parse_condition(expression))


def condition_assignments(doc: dict) -> list[tuple[dict[str, str], str]]:
    """Every (filter-output assignment, event) pair a run of one workflow can present."""
    keys = sorted((doc["jobs"].get("changes") or {}).get("outputs") or {})
    events = ("pull_request", "push", "merge_group")
    assignments = []
    for mask in range(2 ** len(keys)):
        outputs = {
            key: "true" if mask >> index & 1 else "false"
            for index, key in enumerate(keys)
        }
        assignments.extend((outputs, event) for event in events)
    return assignments


# GitHub applies `success()` to every job that does not name a status check function,
# and a skipped dependency fails `success()`, so skip propagation reaches every job
# except the two this pattern matches: `always()` evaluates true whatever every
# dependency reported, and `!cancelled()` evaluates true unless someone cancelled the
# run. `success()`, `failure()` and `cancelled()` each evaluate false over a skipped
# dependency, so a job naming one of those three still skips when a job in its `needs`
# list skips. Job `ci` is the only job
# in ci.yml that names a status check function today: it aggregates results and has to
# run over a skipped dependency to judge it, so it writes `always()`.
#
# A job whose `if:` this pattern does not match, and that `selects` cannot parse,
# reaches the report branch below rather than an exemption, which is why this pattern
# names the two expressions that defeat skip propagation instead of every expression
# that contains a status check function.
RUNS_OVER_A_SKIPPED_DEPENDENCY = re.compile(r"always\s*\(|!\s*cancelled\s*\(")


def dependency_condition_gaps(doc: dict) -> list[str]:
    """Return every (dependant, dependency) pair whose conditions can disagree.

    CRITERION: wherever a job's own `if:` selects it, the `if:` of every job in its
    `needs` list must select that job too.

    WHY: GitHub skips a job when any job in its `needs` list is skipped, so a
    dependency selected by a narrower condition than its dependant skips the
    dependant. scripts/ci-aggregate-result.py evaluates the dependant's own `if:`,
    finds it true, and fails that run, but it judges only the filter outputs of the
    run in front of it: the pull request that narrowed the dependency passes when
    its own changed files do not open the gap, and a later, unrelated pull request
    goes red. This check evaluates every filter assignment, so it reports the gap
    on the pull request that introduces it. The shape this
    check exists for is a producer job that builds an artifact for several consumers:
    its condition has to be the union of theirs, and an edit that narrows it, or that
    widens one consumer's, is invisible in a diff of either job alone.

    SCOPE: ci.yml, the workflow this file's aggregate judges, because that aggregate
    is the required status check that fails on the skip. A
    condition inside it that this grammar cannot read is reported rather than
    stepped over, so the check cannot pass by failing to parse.
    """
    jobs = doc["jobs"]
    gaps: list[str] = []
    for job_id, job in sorted(jobs.items()):
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else list(needs)
        if not needs:
            continue
        condition = job.get("if")
        if condition is None:
            # A job that carries no `if:` runs on every run of this workflow, so the
            # criterion binds hardest on it: every job in its `needs` list has to run
            # on every such run too. Stepping over it would exempt exactly the case
            # the criterion states, so substitute the constant-true expression,
            # written in the grammar `selects` reads, and compare normally.
            condition = "true == 'true'"
        if RUNS_OVER_A_SKIPPED_DEPENDENCY.search(str(condition)):
            continue
        for dependency in needs:
            upstream = jobs.get(dependency, {}).get("if")
            if upstream is None:
                continue
            try:
                pairs = [
                    (outputs, event)
                    for outputs, event in condition_assignments(doc)
                    if selects(condition, outputs, event)
                    and not selects(upstream, outputs, event)
                ]
            except ValueError as unreadable:
                gaps.append(
                    f"{job_id} needs {dependency} and this check cannot decide whether "
                    f"{dependency} runs wherever {job_id} does ({unreadable})"
                )
                continue
            if pairs:
                outputs, event = pairs[0]
                selected = sorted(key for key, on in outputs.items() if on == "true")
                gaps.append(
                    f"{job_id} runs and {dependency} skips on event {event} with "
                    f"filters {selected or ['none']} true, which skips {job_id} "
                    f"and fails the `ci` aggregate on every such pull request"
                )
    return gaps


def check_dependency_conditions(doc: dict) -> None:
    gaps = dependency_condition_gaps(doc)
    check(
        "ci.yml: every job's `needs` are selected wherever the job is",
        not gaps,
        "; ".join(gaps),
    )


def narrow_condition(expression: str, clause_fragment: str) -> str:
    """Drop every `||` clause of one `if:` expression that names a fragment.

    Splitting on `||` rather than on newlines, because `if: >-` folds an expression
    onto one line before yaml.safe_load returns it: a line-wise filter deletes the
    whole expression, and an empty expression makes `selects` raise, which
    `dependency_condition_gaps` reports as a clause it cannot read. A control whose
    mutant reaches that branch passes however the union comparison behaves, so it
    proves nothing about the comparison it exists to guard.
    """
    kept = [
        clause
        for clause in str(expression).split("||")
        if clause_fragment not in clause
    ]
    narrowed = " || ".join(clause.strip() for clause in kept)
    if not narrowed or narrowed == " ".join(str(expression).split()):
        raise ValueError(
            f"narrowing {expression!r} by {clause_fragment!r} dropped every clause or "
            f"none, and a mutant has to stay readable and has to differ"
        )
    return narrowed


def check_dependency_conditions_detect_a_narrowed_producer(doc: dict) -> None:
    """Narrowing one producer's condition by one clause is caught above.

    Each (producer, clause) pair below is a producer whose `if:` carries that clause
    for bridge-parity-kotlin alone: kotlin-test's own tests need `kotlin || rust`, so
    its `python` clause is the one an edit scoped to the Kotlin lane would drop.
    """
    for producer_id, clause in (
        ("pyo3-module", "outputs.kotlin"),
        ("kotlin-test", "outputs.python"),
    ):
        narrowed = copy.deepcopy(doc)
        producer = narrowed["jobs"][producer_id]
        producer["if"] = narrow_condition(producer["if"], clause)
        gaps = dependency_condition_gaps(narrowed)
        check(
            f"dropping the {clause} clause from {producer_id} is reported",
            any(
                f"bridge-parity-kotlin runs and {producer_id} skips" in gap
                for gap in gaps
            ),
            f"a producer that no longer covers bridge-parity-kotlin went unreported: "
            f"{gaps}",
        )
        # The mutant has to reach the union comparison, not the branch that reports an
        # expression this grammar cannot read: that branch names every dependant of
        # the mutated job whatever the comparison answers, which would let this
        # control pass over a comparison that had been deleted.
        check(
            f"the narrowed {producer_id} is reported by the comparison, not by a "
            f"parse refusal",
            not any("cannot decide" in gap for gap in gaps),
            f"the mutant expression went unread: {gaps}",
        )


def check_dependency_conditions_detect_a_conditionless_consumer(doc: dict) -> None:
    """A job with no `if:` whose dependency carries one is compared, not exempted."""
    mutated = copy.deepcopy(doc)
    # Job error-codes carries `needs: [check-draft]`. Removing its `if:` makes it run on
    # every run, and pointing it at a producer selected by one filter output gives the
    # shape a later change would create by having a gate job download a built artifact.
    del mutated["jobs"]["error-codes"]["if"]
    mutated["jobs"]["error-codes"]["needs"] = ["check-draft", "pyo3-module"]
    gaps = dependency_condition_gaps(mutated)
    check(
        "a conditionless job whose dependency can skip is reported",
        any("error-codes runs and pyo3-module skips" in gap for gap in gaps),
        f"a job with no `if:` was exempted from the comparison: {gaps}",
    )


def check_dependency_conditions_read_a_status_guarded_consumer(doc: dict) -> None:
    """Only `always()` and `!cancelled()` exempt a consumer from the comparison.

    A consumer that writes `success()`, `failure()` or `cancelled()` still skips when
    a job in its `needs` list skips, because each of those three evaluates false over
    a skipped dependency. Exempting such a consumer would let the gap through to a
    later pull request's red aggregate exactly as an unexempted gap would, and would
    let it through silently, since the exemption runs before the branch that reports an expression this grammar
    cannot read. Job `error-codes` carries `needs: [check-draft]`; replacing its `if:`
    and adding a producer selected by one filter output gives each mutant a pair to
    compare.
    """
    for expression, exempt in (
        ("success()", False),
        ("failure()", False),
        ("cancelled()", False),
        ("always()", True),
        ("!cancelled()", True),
    ):
        mutated = copy.deepcopy(doc)
        mutated["jobs"]["error-codes"]["needs"] = ["check-draft", "pyo3-module"]
        mutated["jobs"]["error-codes"]["if"] = expression
        gaps = dependency_condition_gaps(mutated)
        named = [gap for gap in gaps if "error-codes" in gap]
        if exempt:
            check(
                f"a consumer written `if: {expression}` is exempted",
                not named,
                f"an expression that runs over a skipped dependency was "
                f"compared: {named}",
            )
        else:
            check(
                f"a consumer written `if: {expression}` is still compared",
                bool(named),
                "a consumer that skips with its dependency was exempted, and "
                "the gate reported nothing about it",
            )


# The file each bridge producer uploads, named by the build that writes it rather
# than by the artifact name a workflow author chooses. maturin writes the PyO3
# extension module that `bindings/python/scp_sdk/__init__.py` imports as
# `_scp_core`, and crates/scp-ffi/napi links its cdylib as `scp_ffi_napi`, so a
# producer's `path:` carries the substring below whatever it calls the artifact.
PYO3_UPLOAD_FILENAME = "_scp_core"
NAPI_UPLOAD_FILENAME = "scp_ffi_napi"


def uploaded_artifact_names(doc: dict, filename: str) -> tuple[str, ...]:
    """Return every artifact name `doc` uploads whose path carries `filename`.

    CRITERION: an artifact holds a bridge binary when the `actions/upload-artifact`
    step that publishes it names a path carrying that binary's filename.

    WHY: the two consumer gates below select the jobs they judge by matching a
    download step's artifact name. Reading those names off ci.yml's own upload steps
    closes the set by construction: a producer added under a name nobody wrote here
    still publishes `_scp_core` or `scp_ffi_napi`, so the gate selects its consumers.
    A tuple written in this file instead holds the names somebody remembered to list,
    and says nothing about a producer added later.
    """
    names = set()
    for job in doc["jobs"].values():
        for step in job.get("steps") or []:
            if not str(step.get("uses") or "").startswith("actions/upload-artifact"):
                continue
            uploaded = step.get("with") or {}
            if uploaded.get("name") and filename in str(uploaded.get("path") or ""):
                names.add(str(uploaded["name"]))
    return tuple(sorted(names))


def check_a_bridge_upload_reaches_the_gate(
    doc: dict, filename: str, artifacts: tuple[str, ...]
) -> None:
    """A derivation returning nothing selects no consumer and reports nothing."""
    check(
        f"ci.yml uploads at least one artifact carrying {filename}",
        bool(artifacts),
        f"no `actions/upload-artifact` step names a path carrying {filename!r}, so "
        f"the gate over its consumers selects no job and reports nothing",
    )


def a_step_that_runs_and_can_fail_its_job(step: dict) -> bool:
    """Return whether `step` runs on every run of its job and a failure stops the job.

    A step that carries an `if:` may be skipped, and a step whose `continue-on-error`
    is anything but false lets the job pass when it fails, so neither guards the tests
    that follow it.
    """
    return "if" not in step and step.get("continue-on-error") in (None, False, "false")


# The text fragments a PyO3 consumer's steps must contain before pytest.
PYO3_ASSERTION_FRAGMENTS = (
    "import scp_sdk._scp_core",
    "SCP(storage=",
    "relay_start_in_memory",
    "fullstack_create_node",
)


def pyo3_consumers_missing_an_assertion_fragment(
    doc: dict, artifacts: tuple[str, ...]
) -> list[str]:
    r"""Return every PyO3-downloading job that lacks a fragment before `pytest tests`.

    CRITERION: in every job that downloads an artifact named in `artifacts`, each
    fragment in PYO3_ASSERTION_FRAGMENTS occurs in the `run:` text of a step that
    comes before the first step whose `run:` text matches `\bpytest tests` and that
    carries no `if:` and no `continue-on-error` other than false.

    WHY: every real-FFI test module under bindings/python/tests skips itself when its
    import of the extension raises ImportError, and the `scp` fixture in
    bindings/python/tests/conftest.py skips every test that requests it when
    `scp_sdk` does not import or `SCP(storage=...)` raises anything. A consumer whose
    downloaded module never reached the import path, failed to load, or was built
    without a feature a module calls therefore leaves pytest exiting 0 over zero
    executed assertions in every one of these jobs at once, which is the `zero-test`
    shape this file names. `crates/scp-ffi/` compiles `fullstack_create_node` only
    under `testing` and `relay_start_in_memory` only under `server`.
    """
    gaps: list[str] = []
    for job_id, job in sorted(doc["jobs"].items()):
        steps = job.get("steps") or []
        if not any(
            str(step.get("uses") or "").startswith("actions/download-artifact")
            and (step.get("with") or {}).get("name") in artifacts
            for step in steps
        ):
            continue
        found = dict.fromkeys(PYO3_ASSERTION_FRAGMENTS, False)
        for step in steps:
            script = str(step.get("run") or "")
            if re.search(r"\bpytest tests", script):
                break
            if not a_step_that_runs_and_can_fail_its_job(step):
                continue
            for fragment in PYO3_ASSERTION_FRAGMENTS:
                found[fragment] = found[fragment] or fragment in script
        missing = [fragment for fragment, present in found.items() if not present]
        if missing:
            gaps.append(
                f"{job_id} downloads a PyO3 module and no unguarded step before "
                f"pytest contains {', '.join(repr(m) for m in missing)}"
            )
    return gaps


def check_pyo3_consumer_assertion_fragments(
    doc: dict, artifacts: tuple[str, ...]
) -> None:
    gaps = pyo3_consumers_missing_an_assertion_fragment(doc, artifacts)
    check(
        "ci.yml: every job downloading a PyO3 module has each PyO3 assertion fragment "
        "in an unguarded step before pytest",
        not gaps,
        "; ".join(gaps),
    )


# The text fragments a NAPI consumer's steps must contain before its tests.
NAPI_ASSERTION_FRAGMENTS = (
    "loadNativeAddon(",
    "new NativeScp(",
    "relayStartInMemory",
    "fullstackCreateNode",
)


def napi_consumers_missing_an_assertion_fragment(
    doc: dict, artifacts: tuple[str, ...]
) -> list[str]:
    r"""Return every NAPI-downloading job that lacks a fragment before its tests.

    CRITERION: in every job that downloads an artifact named in `artifacts`, each
    fragment in NAPI_ASSERTION_FRAGMENTS occurs in the `run:` text of a step that
    comes before the first step whose `run:` text matches `\bbun test\b` or
    `\bpytest tests` and that carries no `if:` and no `continue-on-error` other
    than false.

    WHY: every real-NAPI test file under bindings/typescript/tests wraps its addon load
    and its first construction in one `try`, writes the caught error into a skip reason,
    and resolves its whole `describe` block to `describe.skip` or to a lone `test.skip`
    — tests/real-napi.test.ts, tests/e2e-fullstack.test.ts and tests/persistence.test.ts
    among them. A downloaded addon that does not load therefore leaves `bun test`
    exiting 0 over zero executed NAPI assertions, which is the same `zero-test` shape
    the PyO3 criterion above names.
    """
    gaps: list[str] = []
    for job_id, job in sorted(doc["jobs"].items()):
        steps = job.get("steps") or []
        if not any(
            str(step.get("uses") or "").startswith("actions/download-artifact")
            and (step.get("with") or {}).get("name") in artifacts
            for step in steps
        ):
            continue
        found = dict.fromkeys(NAPI_ASSERTION_FRAGMENTS, False)
        for step in steps:
            script = str(step.get("run") or "")
            if re.search(r"\bbun test\b|\bpytest tests", script):
                break
            if not a_step_that_runs_and_can_fail_its_job(step):
                continue
            for fragment in NAPI_ASSERTION_FRAGMENTS:
                found[fragment] = found[fragment] or fragment in script
        missing = [fragment for fragment, present in found.items() if not present]
        if missing:
            gaps.append(
                f"{job_id} downloads a NAPI addon and no unguarded step before its "
                f"tests contains {', '.join(repr(m) for m in missing)}"
            )
    return gaps


def check_napi_consumer_assertion_fragments(
    doc: dict, artifacts: tuple[str, ...]
) -> None:
    gaps = napi_consumers_missing_an_assertion_fragment(doc, artifacts)
    check(
        "ci.yml: every job downloading a NAPI addon has each NAPI assertion fragment "
        "in an unguarded step before its tests",
        not gaps,
        "; ".join(gaps),
    )


def check_napi_assertion_control(
    doc: dict, artifacts: tuple[str, ...], job_id: str, fragment: str
) -> None:
    """Deleting every line of job `job_id` that contains `fragment` is reported."""
    mutated = copy.deepcopy(doc)
    steps = mutated["jobs"][job_id]["steps"]
    hits = [step for step in steps if fragment in str(step.get("run") or "")]
    if len(hits) != 1:
        check(
            f"the control can delete {fragment!r} from {job_id}",
            False,
            f"{len(hits)} steps carry {fragment!r}, so the mutant is not the one intended",
        )
        return
    hits[0]["run"] = "\n".join(
        line for line in str(hits[0]["run"]).splitlines() if fragment not in line
    )
    gaps = napi_consumers_missing_an_assertion_fragment(mutated, artifacts)
    check(
        f"a {job_id} whose steps no longer contain {fragment!r} is reported",
        any(
            f"{job_id} downloads a NAPI addon" in gap and repr(fragment) in gap
            for gap in gaps
        ),
        f"deleting {fragment!r} went unreported: {gaps}",
    )


def check_pyo3_assertion_control(
    doc: dict, artifacts: tuple[str, ...], job_id: str, fragment: str
) -> None:
    """Deleting every line of job `job_id` that contains `fragment` is reported."""
    mutated = copy.deepcopy(doc)
    steps = mutated["jobs"][job_id]["steps"]
    hits = [step for step in steps if fragment in str(step.get("run") or "")]
    if len(hits) != 1:
        check(
            f"the control can delete {fragment!r} from {job_id}",
            False,
            f"{len(hits)} steps carry {fragment!r}, so the mutant is not the one intended",
        )
        return
    hits[0]["run"] = "\n".join(
        line for line in str(hits[0]["run"]).splitlines() if fragment not in line
    )
    gaps = pyo3_consumers_missing_an_assertion_fragment(mutated, artifacts)
    check(
        f"a {job_id} whose steps no longer contain {fragment!r} is reported",
        any(
            f"{job_id} downloads a PyO3 module" in gap and repr(fragment) in gap
            for gap in gaps
        ),
        f"deleting {fragment!r} went unreported: {gaps}",
    )


def check_assertion_step_guard_controls(
    doc: dict, artifacts: tuple[str, ...], job_id: str, bridge: str
) -> None:
    """An assertion step in `job_id` that may be skipped or may fail open is reported.

    `bridge` is "PyO3" or "NAPI". Each mutant sets one key on every step of the job
    that carries one of the bridge's fragments; the last sets `continue-on-error:
    false`, which leaves the step able to fail its job, and requires no report.
    """
    if bridge == "PyO3":
        fragments = PYO3_ASSERTION_FRAGMENTS
        gate = pyo3_consumers_missing_an_assertion_fragment
    else:
        fragments = NAPI_ASSERTION_FRAGMENTS
        gate = napi_consumers_missing_an_assertion_fragment
    prefix = f"{job_id} downloads a {bridge} "
    for key, value, reported in (
        ("continue-on-error", True, True),
        ("continue-on-error", "${{ github.event_name == 'pull_request' }}", True),
        ("if", "github.event_name == 'push'", True),
        ("continue-on-error", False, False),
    ):
        mutated = copy.deepcopy(doc)
        for step in mutated["jobs"][job_id]["steps"]:
            if any(fragment in str(step.get("run") or "") for fragment in fragments):
                step[key] = value
        hit = any(gap.startswith(prefix) for gap in gate(mutated, artifacts))
        check(
            f"a {job_id} whose {bridge} assertion step sets `{key}: {value}` is "
            f"{'reported' if reported else 'not reported'}",
            hit == reported,
            f"the gate {'missed' if reported else 'reported'} that mutant",
        )


def artifact_consumers(doc: dict, artifact: str) -> list[str]:
    """Return every job id that downloads the artifact named `artifact`."""
    return sorted(
        job_id
        for job_id, job in doc["jobs"].items()
        if any(
            str(step.get("uses") or "").startswith("actions/download-artifact")
            and (step.get("with") or {}).get("name") == artifact
            for step in (job.get("steps") or [])
        )
    )


def artifact_names_without_a_consumer(
    doc: dict, artifacts: tuple[str, ...]
) -> list[str]:
    """Return every name in `artifacts` that no job in `doc` downloads.

    CRITERION: each artifact name a bridge producer in ci.yml uploads is a name some
    job in ci.yml passes to `actions/download-artifact`.

    WHY: both gates above select the jobs they judge by matching a download step's
    `name` against the names `uploaded_artifact_names` reads off ci.yml's upload
    steps. A download renamed away from the upload that publishes it therefore leaves
    the gate selecting no job for that artifact, and leaves the producer building a
    binary no job reads, while the self-test stays green — the silent drop-out the
    gates exist to prevent. `pyo3-module-macos` reaches exactly one consumer,
    bridge-parity-swift, so renaming that one download deletes a whole job from the
    checked set.
    """
    return [artifact for artifact in artifacts if not artifact_consumers(doc, artifact)]


def check_artifact_names_reach_a_consumer(
    doc: dict, artifacts: tuple[str, ...], filename: str
) -> None:
    unreached = artifact_names_without_a_consumer(doc, artifacts)
    check(
        f"ci.yml: every artifact uploading {filename} reaches a job that downloads it",
        not unreached,
        f"no job downloads {unreached}, so the gate over consumers of {filename} "
        f"checks no job for that artifact",
    )


def check_artifact_name_control(
    doc: dict, artifacts: tuple[str, ...], artifact: str
) -> None:
    """Renaming every download of one artifact is reported."""
    mutated = copy.deepcopy(doc)
    renamed = f"{artifact}-renamed-by-the-control"
    for job in mutated["jobs"].values():
        for step in job.get("steps") or []:
            if (
                str(step.get("uses") or "").startswith("actions/download-artifact")
                and (step.get("with") or {}).get("name") == artifact
            ):
                step["with"]["name"] = renamed
    check(
        f"renaming every download of {artifact} is reported",
        artifact in artifact_names_without_a_consumer(mutated, artifacts),
        f"a ci.yml that downloads {renamed} instead of {artifact} went unreported",
    )


# GitHub permits re-running a workflow run, or its failed jobs, for 30 days after the
# run starts. A re-run of failed jobs leaves a producer that passed alone, so its
# consumers download the copy the first attempt uploaded.
RERUN_WINDOW_DAYS = 30


def shared_uploads_expiring_inside_the_rerun_window(doc: dict) -> list[str]:
    """Return every job:artifact pair whose shared upload expires before re-runs end.

    CRITERION: an `actions/upload-artifact` step in ci.yml whose artifact name a job
    in ci.yml downloads sets `retention-days` to at least RERUN_WINDOW_DAYS.

    WHY: "Re-run failed jobs" re-runs the failed consumer and not the producer that
    passed, so the consumer's download reads the first attempt's upload. An upload
    that expired first fails that download, and the consumer fails over a binary it
    could have tested. An omitted `retention-days` falls back to a repository
    setting this file cannot read, so this check reports an omission too.
    """
    downloaded = {
        (step.get("with") or {}).get("name")
        for job in doc["jobs"].values()
        for step in job.get("steps") or []
        if str(step.get("uses") or "").startswith("actions/download-artifact")
    }
    short: list[str] = []
    for job_id, job in sorted(doc["jobs"].items()):
        for step in job.get("steps") or []:
            if not str(step.get("uses") or "").startswith("actions/upload-artifact"):
                continue
            inputs = step.get("with") or {}
            if inputs.get("name") not in downloaded:
                continue
            days = inputs.get("retention-days")
            if not isinstance(days, int) or days < RERUN_WINDOW_DAYS:
                short.append(f"{job_id}:{inputs.get('name')} ({days!r} days)")
    return short


def check_shared_uploads_outlive_the_rerun_window(doc: dict) -> None:
    short = shared_uploads_expiring_inside_the_rerun_window(doc)
    check(
        f"ci.yml: every downloaded artifact is kept {RERUN_WINDOW_DAYS} days",
        not short,
        f"{short} expire while GitHub still offers 'Re-run failed jobs', so a "
        f"consumer re-run after they expire fails its download",
    )
    # Control: every shared upload, lowered to one day in turn, is reported.
    for job_id, job in doc["jobs"].items():
        for index, step in enumerate(job.get("steps") or []):
            inputs = step.get("with") or {}
            if not str(step.get("uses") or "").startswith("actions/upload-artifact"):
                continue
            if not artifact_consumers(doc, inputs.get("name")):
                continue
            mutated = copy.deepcopy(doc)
            mutated["jobs"][job_id]["steps"][index]["with"]["retention-days"] = 1
            label = f"{job_id}:{inputs.get('name')}"
            check(
                f"lowering {label} to one day of retention is reported",
                any(
                    gap.startswith(label + " ")
                    for gap in shared_uploads_expiring_inside_the_rerun_window(mutated)
                ),
                f"a ci.yml keeping {label} for one day went unreported",
            )


# The workflow-level key check_profile_env_is_workflow_level requires, and the value
# that key must carry. See the `profile-env` entry in this file's docstring.
WORKFLOW_PROFILE_KEY = "CARGO_PROFILE_DEV_DEBUG"
WORKFLOW_PROFILE_VALUE = "0"
CARGO_PROFILE_PREFIX = "CARGO_PROFILE_"


def profile_env_gaps(doc: dict) -> list[str]:
    """Return each way a workflow's `CARGO_PROFILE_*` environment breaks the rule.

    CRITERION: the workflow-level `env:` sets WORKFLOW_PROFILE_KEY to
    WORKFLOW_PROFILE_VALUE, and no job-level or step-level `env:` sets any key
    starting with CARGO_PROFILE_PREFIX.

    WHY: rust-cache hashes every `CARGO*` variable into its key, so a
    `CARGO_PROFILE_*` value that differs between jobs splits a `shared-key`
    group into entries no other member restores.
    """
    gaps: list[str] = []
    workflow_env = doc.get("env") or {}
    value = workflow_env.get(WORKFLOW_PROFILE_KEY)
    if value is None or str(value) != WORKFLOW_PROFILE_VALUE:
        gaps.append(
            f"workflow env: {WORKFLOW_PROFILE_KEY}={value!r}, "
            f"expected {WORKFLOW_PROFILE_VALUE!r}"
        )
    for job_id, job in sorted((doc.get("jobs") or {}).items()):
        for key in sorted(job.get("env") or {}):
            if str(key).startswith(CARGO_PROFILE_PREFIX):
                gaps.append(f"job {job_id}: env sets {key}")
        for index, step in enumerate(job.get("steps") or []):
            for key in sorted(step.get("env") or {}):
                if str(key).startswith(CARGO_PROFILE_PREFIX):
                    label = step.get("name") or f"step {index}"
                    gaps.append(f"job {job_id}, {label}: env sets {key}")
    return gaps


def check_profile_env_is_workflow_level(doc: dict, name: str) -> None:
    gaps = profile_env_gaps(doc)
    check(
        f"{name}: {WORKFLOW_PROFILE_KEY} is set at workflow level and no job or "
        f"step sets a {CARGO_PROFILE_PREFIX}* key",
        not gaps,
        f"{gaps}: a per-job value splits a rust-cache group, and a missing "
        f"workflow-level value restores debug info to CI's dev-profile builds",
    )
    # Controls: each mutation below breaks one half of the rule and must be reported.
    job_id = next(job_id for job_id, job in doc["jobs"].items() if job.get("steps"))
    mutated = copy.deepcopy(doc)
    mutated["jobs"][job_id].setdefault("env", {})[WORKFLOW_PROFILE_KEY] = "1"
    check(
        f'a job-level {WORKFLOW_PROFILE_KEY}: "1" on {job_id} is reported',
        any(
            gap == f"job {job_id}: env sets {WORKFLOW_PROFILE_KEY}"
            for gap in profile_env_gaps(mutated)
        ),
        f"a {name} setting {WORKFLOW_PROFILE_KEY} on job {job_id} went unreported",
    )
    mutated = copy.deepcopy(doc)
    mutated["jobs"][job_id]["steps"][0].setdefault("env", {})[
        "CARGO_PROFILE_TEST_OPT_LEVEL"
    ] = "1"
    check(
        f"a step-level CARGO_PROFILE_TEST_OPT_LEVEL on {job_id} is reported",
        any(
            gap.startswith(f"job {job_id}, ")
            and gap.endswith("env sets CARGO_PROFILE_TEST_OPT_LEVEL")
            for gap in profile_env_gaps(mutated)
        ),
        f"a {name} setting a CARGO_PROFILE_* key on a step of {job_id} went unreported",
    )
    mutated = copy.deepcopy(doc)
    (mutated.get("env") or {}).pop(WORKFLOW_PROFILE_KEY, None)
    check(
        f"removing the workflow-level {WORKFLOW_PROFILE_KEY} is reported",
        any(gap.startswith("workflow env: ") for gap in profile_env_gaps(mutated)),
        f"a {name} without a workflow-level {WORKFLOW_PROFILE_KEY} went unreported",
    )
    mutated = copy.deepcopy(doc)
    mutated.setdefault("env", {})[WORKFLOW_PROFILE_KEY] = "2"
    check(
        f'a workflow-level {WORKFLOW_PROFILE_KEY}: "2" is reported',
        any(gap.startswith("workflow env: ") for gap in profile_env_gaps(mutated)),
        f"a {name} setting {WORKFLOW_PROFILE_KEY} to 2 went unreported",
    )


def package_write_holders(doc: dict) -> list[str]:
    """Return `workflow` and every job id whose own `permissions:` grants package write.

    Job docker-image-cache writes the Docker layer cache tag with the `docker-cache`
    environment's token, so no `GITHUB_TOKEN` in this workflow needs
    `packages: write`. `write-all` grants `packages: write`.
    """

    def grants_package_write(permissions: object) -> bool:
        if isinstance(permissions, str):
            return permissions == "write-all"
        return isinstance(permissions, dict) and permissions.get("packages") == "write"

    holders = ["workflow"] if grants_package_write(doc.get("permissions")) else []
    return holders + sorted(
        job_id
        for job_id, job in doc["jobs"].items()
        if grants_package_write(job.get("permissions"))
    )


# GitHub matches secret names and expression property names without regard to case,
# and `toJSON(secrets)` hands a step every secret its job can read.
CACHE_TOKEN_READ = re.compile(
    r"secrets\s*(\.\s*GHCR_CACHE_TOKEN\b|\[\s*['\"]GHCR_CACHE_TOKEN['\"]\s*\])"
    r"|toJSON\s*\(\s*secrets\s*\)",
    re.IGNORECASE,
)


def cache_token_reads_outside_environment(doc: dict) -> list[str]:
    """Return every reader of `secrets.GHCR_CACHE_TOKEN` outside a `docker-cache` job.

    A reader is a step, a job-level key other than `steps:`, or the workflow-level
    `env:`; the workflow-level `env:` reaches every job, so it is always reported.
    """

    def reads(value: object) -> bool:
        return bool(CACHE_TOKEN_READ.search(json.dumps(value)))

    found = ["workflow.env"] if reads(doc.get("env")) else []
    for job_id, job in doc["jobs"].items():
        environment = job.get("environment")
        if isinstance(environment, dict):
            environment = environment.get("name")
        if environment == "docker-cache":
            continue
        found += [
            f"{job_id}.{key}"
            for key, value in job.items()
            if key != "steps" and reads(value)
        ]
        found += [
            f"{job_id}.steps[{index}]"
            for index, step in enumerate(job.get("steps") or [])
            if reads(step)
        ]
    return found


def check_package_write_and_cache_token(doc: dict) -> None:
    """No block grants `packages: write`; the cache token is read only in `docker-cache`."""
    check(
        "no job and no workflow-level block holds `packages: write` or `write-all`",
        package_write_holders(doc) == [],
        f"blocks granting package write: {package_write_holders(doc)}",
    )
    check(
        "every reader of `secrets.GHCR_CACHE_TOKEN` is in a job declaring "
        "`environment: docker-cache`",
        cache_token_reads_outside_environment(doc) == [],
        f"readers outside the environment: {cache_token_reads_outside_environment(doc)}",
    )
    write_mutants = (
        (
            "a docker-image-cache job granted `packages: write` is reported",
            lambda d: d["jobs"]["docker-image-cache"]["permissions"].update(
                packages="write"
            ),
            ["docker-image-cache"],
        ),
        (
            "a docker-image job with `permissions: write-all` is reported",
            lambda d: d["jobs"]["docker-image"].update(permissions="write-all"),
            ["docker-image"],
        ),
        (
            "a workflow-level `packages: write` is reported",
            lambda d: d["permissions"].update(packages="write"),
            ["workflow"],
        ),
        (
            "a workflow-level `permissions: write-all` is reported",
            lambda d: d.update(permissions="write-all"),
            ["workflow"],
        ),
        (
            "`permissions: read-all` at both levels is not reported",
            lambda d: (
                d.update(permissions="read-all"),
                d["jobs"]["docker-image"].update(permissions="read-all"),
            ),
            [],
        ),
    )
    for name, mutate, expected in write_mutants:
        mutant = copy.deepcopy(doc)
        mutate(mutant)
        check(
            name,
            package_write_holders(mutant) == expected,
            f"reported {package_write_holders(mutant)}, expected {expected}",
        )
    image_steps = len(doc["jobs"]["docker-image"]["steps"])
    cache_readers = [
        f"docker-image-cache.steps[{index}]"
        for index, step in enumerate(doc["jobs"]["docker-image-cache"]["steps"])
        if CACHE_TOKEN_READ.search(json.dumps(step))
    ]
    check(
        "a docker-image-cache step reads `secrets.GHCR_CACHE_TOKEN`, so the two "
        "environment mutants below have a reader to expose",
        cache_readers != [],
        "no docker-image-cache step reads the token",
    )
    login = {
        "uses": "docker/login-action@v3",
        "with": {"password": "${{ secrets.GHCR_CACHE_TOKEN }}"},
    }
    token_mutants = (
        (
            "a docker-image-cache job without `environment:` is reported",
            lambda d: d["jobs"]["docker-image-cache"].pop("environment"),
            cache_readers,
        ),
        (
            "a docker-image-cache job in another environment is reported",
            lambda d: d["jobs"]["docker-image-cache"].update(environment="production"),
            cache_readers,
        ),
        (
            "`environment: {name: docker-cache}` is accepted",
            lambda d: d["jobs"]["docker-image-cache"].update(
                environment={"name": "docker-cache"}
            ),
            [],
        ),
        (
            "a docker-image step reading the token is reported",
            lambda d: d["jobs"]["docker-image"]["steps"].append(login),
            [f"docker-image.steps[{image_steps}]"],
        ),
        (
            "a docker-image job-level `env:` reading the token by index is reported",
            lambda d: d["jobs"]["docker-image"].update(
                env={"T": "${{ secrets['GHCR_CACHE_TOKEN'] }}"}
            ),
            ["docker-image.env"],
        ),
        (
            "a docker-image step reading the token in lowercase is reported",
            lambda d: d["jobs"]["docker-image"]["steps"].append(
                {"with": {"password": "${{ secrets.ghcr_cache_token }}"}}
            ),
            [f"docker-image.steps[{image_steps}]"],
        ),
        (
            "a docker-image step reading `toJSON(secrets)` is reported",
            lambda d: d["jobs"]["docker-image"]["steps"].append(
                {"run": "echo '${{ toJSON(secrets) }}'"}
            ),
            [f"docker-image.steps[{image_steps}]"],
        ),
        (
            "a docker-image step reading another secret is not reported",
            lambda d: d["jobs"]["docker-image"]["steps"].append(
                {"with": {"password": "${{ secrets.GHCR_CACHE_TOKEN_OLD }}"}}
            ),
            [],
        ),
        (
            "a workflow-level `env:` reading the token is reported",
            lambda d: d.setdefault("env", {}).update(
                T="${{ secrets.GHCR_CACHE_TOKEN }}"
            ),
            ["workflow.env"],
        ),
    )
    for name, mutate, expected in token_mutants:
        mutant = copy.deepcopy(doc)
        mutate(mutant)
        found = cache_token_reads_outside_environment(mutant)
        check(name, found == expected, f"reported {found}, expected {expected}")


# Each entry is (text the restore key must carry, the input that text stands for).
# The file patterns are `hashFiles` arguments; the expressions are `${{ }}` contexts.
ARTIFACT_KEY_FILE_INPUTS = (
    ("rust-toolchain.toml", "the compiler version"),
    ("Cargo.lock", "every dependency version"),
    ("**/Cargo.toml", "every manifest's features, profiles and inheritance"),
    (".cargo/**", "the repository's cargo config"),
    ("crates/**", "the sources of every crate a bridge reaches"),
)
# The build input outside crates/ that one producer reads, keyed by job id.
ARTIFACT_KEY_JOB_FILE_INPUTS = {
    "pyo3-module": (("bindings/python/pyproject.toml", "the [tool.maturin] features"),),
    "pyo3-module-macos": (
        ("bindings/python/pyproject.toml", "the [tool.maturin] features"),
    ),
    "xcframework": (
        ("bindings/swift/build-xcframework.sh", "the script that runs the build"),
    ),
    "kotlin-test": (
        (
            "scripts/generate-uniffi-kotlin.sh",
            "the script that generates the Kotlin bindings",
        ),
    ),
}
ARTIFACT_KEY_EXPRESSION_INPUTS = (
    ("runner.os", "the runner OS"),
    ("runner.arch", "the runner architecture"),
    ("github.job", "the producer's job id"),
    ("steps.artifact-inputs.outputs.digest", "the job definition and tool versions"),
)
ARTIFACT_KEY_VERSION = re.compile(r"^bridge-artifact-v\d+-")
HASH_FILES_CALL = re.compile(r"hashFiles\(([^)]*)\)")


def step_paths(step: dict) -> list[str]:
    return str((step.get("with") or {}).get("path") or "").split()


def bridge_producers(doc: dict) -> list[str]:
    """Return every ci.yml job that uploads an artifact another job downloads."""
    return sorted(
        job_id
        for job_id, job in doc["jobs"].items()
        if any(
            str(step.get("uses") or "").startswith("actions/upload-artifact")
            and artifact_consumers(doc, (step.get("with") or {}).get("name"))
            for step in job.get("steps") or []
        )
    )


def artifact_cache_key_gaps(doc: dict) -> list[str]:
    """Return one line per input a bridge producer's artifact cache key omits.

    CRITERION: every ci.yml job that uploads an artifact another ci.yml job downloads
    restores that artifact with `actions/cache/restore` under a key that names the
    version literal, each file pattern in ARTIFACT_KEY_FILE_INPUTS and the job's
    entries in ARTIFACT_KEY_JOB_FILE_INPUTS inside a `hashFiles` call, and each context in ARTIFACT_KEY_EXPRESSION_INPUTS; computes the
    digest that key reads in a step before the restore that hashes the job's own
    definition out of ci.yml; restores, saves and uploads one path list; and saves under the key it
    restored. Each entry in ARTIFACT_KEY_JOB_FILE_INPUTS for the job is listed, or
    covered by a `/**` entry, under a paths-filter key that gates the job.

    WHY: on a key hit the producer skips its build and uploads what an earlier run
    built. A key that omits one input restores that earlier build after the input
    changes, and every consumer then tests a stale binary and passes.
    """
    gaps: list[str] = []
    for job_id in bridge_producers(doc):
        steps = [
            step for step in doc["jobs"][job_id]["steps"] if isinstance(step, dict)
        ]
        uploads = [
            step
            for step in steps
            if str(step.get("uses") or "").startswith("actions/upload-artifact")
            and artifact_consumers(doc, (step.get("with") or {}).get("name"))
        ]
        restores = [
            step
            for step in steps
            if str(step.get("uses") or "").startswith("actions/cache/restore")
        ]
        if len(restores) != 1:
            gaps.append(
                f"{job_id}: {len(restores)} actions/cache/restore steps, want 1"
            )
            continue
        restore = restores[0]
        key = str((restore.get("with") or {}).get("key") or "")
        hashed = {
            argument.strip().strip("'\"")
            for call in HASH_FILES_CALL.findall(key)
            for argument in call.split(",")
        }
        if not ARTIFACT_KEY_VERSION.search(key):
            gaps.append(
                f"{job_id}: key carries no bridge-artifact-v<N> version literal"
            )
        for pattern, meaning in (
            ARTIFACT_KEY_FILE_INPUTS + ARTIFACT_KEY_JOB_FILE_INPUTS.get(job_id, ())
        ):
            if pattern not in hashed:
                gaps.append(f"{job_id}: key hashes no {pattern} ({meaning})")
        routed = {
            entry
            for step in paths_filter_steps(doc)
            for key in gating_filter_keys(doc, doc["jobs"][job_id])
            for entry in (step.filters.get(key) or [])
        }
        for pattern, meaning in ARTIFACT_KEY_JOB_FILE_INPUTS.get(job_id, ()):
            if pattern not in routed and not directory_covered(routed, pattern):
                gaps.append(
                    f"{job_id}: no paths filter gating the job lists {pattern} ({meaning})"
                )
        expressions = re.findall(r"\$\{\{\s*([^}]*?)\s*\}\}", key)
        for context, meaning in ARTIFACT_KEY_EXPRESSION_INPUTS:
            if context not in expressions:
                gaps.append(f"{job_id}: key reads no {context} ({meaning})")
        digest = next(
            (step for step in steps if step.get("id") == "artifact-inputs"), None
        )
        digest_run = str((digest or {}).get("run") or "")
        if digest is not None and steps.index(digest) > steps.index(restore):
            gaps.append(
                f"{job_id}: the artifact-inputs step runs after the restore that reads its digest"
            )
        if (
            "GITHUB_JOB" not in digest_run
            or ".github/workflows/ci.yml" not in digest_run
        ):
            gaps.append(
                f"{job_id}: no artifact-inputs step hashes the job's definition in ci.yml"
            )
        saves = [
            step
            for step in steps
            if str(step.get("uses") or "").startswith("actions/cache/save")
        ]
        restore_id = restore.get("id")
        if len(saves) != 1:
            gaps.append(f"{job_id}: {len(saves)} actions/cache/save steps, want 1")
        else:
            saved_key = str((saves[0].get("with") or {}).get("key") or "")
            if saved_key not in (
                key,
                f"${{{{ steps.{restore_id}.outputs.cache-primary-key }}}}",
            ):
                gaps.append(
                    f"{job_id}: the save key {saved_key!r} is not the restore key"
                )
            if step_paths(saves[0]) != step_paths(restore):
                gaps.append(f"{job_id}: the save and the restore name different paths")
        for upload in uploads:
            if step_paths(upload) != step_paths(restore):
                gaps.append(
                    f"{job_id}: the restore paths {step_paths(restore)} are not the "
                    f"upload paths {step_paths(upload)}"
                )
    return gaps


def without_key_input(key: str, text: str) -> str:
    """Return `key` with one input removed: a hashFiles argument, a context, or the version."""
    if text == "version":
        return ARTIFACT_KEY_VERSION.sub("bridge-artifact-", key)
    quoted = f"'{text}'"
    if quoted in key:
        return (
            key.replace(f"{quoted}, ", "")
            .replace(f", {quoted}", "")
            .replace(quoted, "")
        )
    return re.sub(r"\$\{\{\s*" + re.escape(text) + r"\s*\}\}-?", "", key)


def check_artifact_cache_keys(doc: dict) -> None:
    gaps = artifact_cache_key_gaps(doc)
    check(
        "ci.yml: every bridge producer keys its artifact cache on every input",
        not gaps,
        f"{gaps}; a key missing an input restores a stale artifact after that input "
        f"changes",
    )
    producers = bridge_producers(doc)
    check(
        "ci.yml: the artifact cache check reads all five bridge producers",
        {"kotlin-test", "napi-addon", "pyo3-module", "pyo3-module-macos", "xcframework"}
        <= set(producers),
        f"found {producers}",
    )
    # Control: each producer, with each input removed from its key in turn, is reported.
    for job_id in producers:
        removable = (
            [pattern for pattern, _ in ARTIFACT_KEY_FILE_INPUTS]
            + [pattern for pattern, _ in ARTIFACT_KEY_JOB_FILE_INPUTS.get(job_id, ())]
            + [context for context, _ in ARTIFACT_KEY_EXPRESSION_INPUTS]
            + ["version"]
        )
        for index, step in enumerate(doc["jobs"][job_id]["steps"]):
            if not str(step.get("uses") or "").startswith("actions/cache/restore"):
                continue
            for text in removable:
                mutated = copy.deepcopy(doc)
                inputs = mutated["jobs"][job_id]["steps"][index]["with"]
                stripped = without_key_input(inputs["key"], text)
                inputs["key"] = stripped
                named = "bridge-artifact-v<N>" if text == "version" else text
                check(
                    f"{job_id}: a key without {text} is reported",
                    stripped != step["with"]["key"]
                    and any(
                        gap.startswith(f"{job_id}: ") and named in gap
                        for gap in artifact_cache_key_gaps(mutated)
                    ),
                    f"a ci.yml whose {job_id} key omits {text} went unreported",
                )
        # Control: each job file input dropped from the filters gating the job is reported.
        for pattern, _ in ARTIFACT_KEY_JOB_FILE_INPUTS.get(job_id, ()):
            mutated = copy.deepcopy(doc)
            for job in mutated["jobs"].values():
                for step in job.get("steps") or []:
                    if not str(step.get("uses") or "").startswith("dorny/paths-filter"):
                        continue
                    filters = yaml.safe_load(step["with"]["filters"])
                    step["with"]["filters"] = yaml.safe_dump(
                        {
                            key: [
                                entry
                                for entry in entries
                                if entry != pattern
                                and not directory_covered({entry}, pattern)
                            ]
                            for key, entries in filters.items()
                        }
                    )
            check(
                f"{job_id}: a filter set that does not route {pattern} is reported",
                any(
                    gap.startswith(f"{job_id}: no paths filter") and pattern in gap
                    for gap in artifact_cache_key_gaps(mutated)
                ),
                f"a ci.yml whose filters omit {pattern} went unreported for {job_id}",
            )
        # Control: the artifact-inputs step moved after the restore is reported.
        mutated = copy.deepcopy(doc)
        moved = mutated["jobs"][job_id]["steps"]
        digest_index = next(
            i for i, s in enumerate(moved) if s.get("id") == "artifact-inputs"
        )
        moved.append(moved.pop(digest_index))
        check(
            f"{job_id}: an artifact-inputs step after the restore is reported",
            any(
                gap == f"{job_id}: the artifact-inputs step runs after the restore "
                "that reads its digest"
                for gap in artifact_cache_key_gaps(mutated)
            ),
            f"a ci.yml whose {job_id} computes its digest after the restore went "
            f"unreported",
        )


ARTIFACT_INPUT_TOOLS = (
    "git",
    "python",
    "maturin",
    "ldd",
    "cc",
    "dpkg-query",
    "xcodebuild",
    "xcrun",
)
# A line the harness adds to the workflow-level env: block, which every build inherits.
ARTIFACT_ENV_PROBE = "  RUSTFLAGS: -C debug-assertions=on\n"


def run_artifact_inputs_step(
    step: dict,
    job_id: str,
    failing: str | None,
    *,
    script: str | None = None,
    workflow: str | None = None,
    image_os: str | None = "stub-image",
    image_version: str | None = "stub-build",
) -> tuple[int, str]:
    """Run an artifact-inputs step with every tool stubbed and `failing` exiting 1.

    `script` replaces the step's own `run:` text, `workflow` the ci.yml the step
    reads, and `image_os=None` and `image_version=None` leave ImageOS and
    ImageVersion unset. Return the exit code and what
    the step wrote to GITHUB_OUTPUT.
    """
    with tempfile.TemporaryDirectory() as root:
        tree = Path(root, "tree")
        (tree / ".github/workflows").mkdir(parents=True)
        (tree / ".github/workflows/ci.yml").write_text(
            WORKFLOW.read_text() if workflow is None else workflow
        )
        (tree / ".venv/bin").mkdir(parents=True)
        (tree / ".venv/bin/activate").write_text("")
        stubs = Path(root, "stubs")
        stubs.mkdir()
        for tool in ARTIFACT_INPUT_TOOLS:
            body = "exit 1" if tool == failing else f"echo {tool}-stub"
            (stubs / tool).write_text(f"#!/bin/sh\n{body}\n")
            (stubs / tool).chmod(0o755)
        runner_temp = Path(root, "runner-temp")
        runner_temp.mkdir()
        output = Path(root, "github-output")
        output.write_text("")
        script_file = Path(root, "step.sh")
        script_file.write_text(str(step.get("run") or "") if script is None else script)
        env = {
            **os.environ,
            "PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}",
            "GITHUB_JOB": job_id,
            "GITHUB_OUTPUT": str(output),
            "RUNNER_TEMP": str(runner_temp),
        }
        env.pop("ImageOS", None)
        env.pop("ImageVersion", None)
        if image_os is not None:
            env["ImageOS"] = image_os
        if image_version is not None:
            env["ImageVersion"] = image_version
        # GitHub runs a step that names no `shell:` under `bash -e {0}`, and a step
        # that names `shell: bash` under `bash --noprofile --norc -eo pipefail {0}`.
        if step.get("shell") == "bash":
            shell = ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
        else:
            shell = ["bash", "-e"]
        code = subprocess.run(
            [*shell, str(script_file)],
            cwd=tree,
            env=env,
            capture_output=True,
            check=False,
        ).returncode
        return code, output.read_text()


def check_artifact_input_digests_fail_closed(doc: dict) -> None:
    """Run each producer's artifact-inputs step with each tool it calls failing.

    CRITERION: each bridge producer's `artifact-inputs` step exits non-zero when any
    command in ARTIFACT_INPUT_TOOLS whose output it hashes fails or when ImageOS or
    ImageVersion is unset, exits 0 and writes a digest when every command succeeds, and writes a
    different digest when the workflow-level env: block changes, at its top or below
    the column-0 comments that follow it, or when the job's own definition changes
    below a comment indented as a job key.

    WHY: a tool that fails puts nothing into the digest, so the key stops encoding
    that tool's version, and a later change to the tool restores an artifact the
    earlier version built. The same holds for the runner image name and build and
    for the workflow env every build inherits.
    """
    workflow = WORKFLOW.read_text()
    probed = workflow.replace("\nenv:\n", f"\nenv:\n{ARTIFACT_ENV_PROBE}", 1)
    # YAML keeps env: open across the column-0 comments below it, so a variable
    # written just above `jobs:` is still inherited by every build.
    probed_low = workflow.replace("\njobs:\n", f"\n{ARTIFACT_ENV_PROBE}jobs:\n", 1)
    for job_id in bridge_producers(doc):
        steps = doc["jobs"][job_id]["steps"]
        step = next((s for s in steps if s.get("id") == "artifact-inputs"), None) or {}
        script = str(step.get("run") or "")
        tools = [
            tool
            for tool in ARTIFACT_INPUT_TOOLS
            if re.search(rf"^\s*{re.escape(tool)}\b", script, re.MULTILINE)
        ]
        code, output = run_artifact_inputs_step(step, job_id, None)
        check(
            f"{job_id}: the artifact-inputs step writes a digest when every tool runs",
            bool(tools)
            and code == 0
            and re.fullmatch(r"digest=[0-9a-f]{64}\n", output) is not None,
            f"exit {code}, output {output!r}, tools {tools}",
        )
        for tool in tools:
            code, _ = run_artifact_inputs_step(step, job_id, tool)
            check(
                f"{job_id}: the artifact-inputs step fails when {tool} fails",
                code != 0,
                f"the step hashed a failed {tool} and exited 0",
            )
            # Control: the harness adds no pipefail of its own, so a piped tool's
            # failure is caught only by the step's own `set -o pipefail`.
            if re.search(rf"^\s*{re.escape(tool)}\b[^\n]*\|", script, re.MULTILINE):
                unpiped = script.replace("set -euo pipefail", "set -eu")
                code, _ = run_artifact_inputs_step(step, job_id, tool, script=unpiped)
                check(
                    f"{job_id}: without the step's pipefail a failed {tool} passes "
                    f"the harness",
                    unpiped != script and code == 0,
                    f"the harness failed a step without pipefail on {tool} "
                    f"(exit {code}), so it supplies the pipefail the check credits "
                    f"to the step",
                )
        code, _ = run_artifact_inputs_step(step, job_id, None, image_os=None)
        check(
            f"{job_id}: the artifact-inputs step fails when ImageOS is unset",
            code != 0,
            "the step hashed a missing runner image name and exited 0",
        )
        code, _ = run_artifact_inputs_step(step, job_id, None, image_version=None)
        check(
            f"{job_id}: the artifact-inputs step fails when ImageVersion is unset",
            code != 0,
            "the step hashed a missing runner image build and exited 0",
        )
        _, other_build = run_artifact_inputs_step(
            step, job_id, None, image_version="other-build"
        )
        check(
            f"{job_id}: a different runner image build changes the digest",
            other_build != output,
            f"changing ImageVersion left the digest at {output!r}",
        )
        _, probed_output = run_artifact_inputs_step(step, job_id, None, workflow=probed)
        check(
            f"{job_id}: a change to the workflow-level env changes the digest",
            probed != workflow and probed_output != output,
            f"adding {ARTIFACT_ENV_PROBE.strip()!r} to the workflow env left the "
            f"digest at {output!r}",
        )
        _, low_output = run_artifact_inputs_step(step, job_id, None, workflow=probed_low)
        check(
            f"{job_id}: an env variable below the comments after env: changes the digest",
            probed_low != workflow and low_output != output,
            f"adding {ARTIFACT_ENV_PROBE.strip()!r} above jobs: left the digest at "
            f"{output!r}",
        )
        # A job key written below a comment at job-key indent is still part of the
        # job, so two values of that key must give two digests.
        header = f"\n  {job_id}:\n"
        job_probes = [
            workflow.replace(
                header, f"{header}  # probe\n    continue-on-error: {value}\n", 1
            )
            for value in ("false", "true")
        ]
        job_outputs = [
            run_artifact_inputs_step(step, job_id, None, workflow=w)[1]
            for w in job_probes
        ]
        check(
            f"{job_id}: a job key below a job-indent comment changes the digest",
            job_probes[0] != workflow and job_outputs[0] != job_outputs[1],
            f"changing a key below a comment in job {job_id} left the digest at "
            f"{job_outputs[0]!r}",
        )
        # Control: extraction that stops at any column-0 or job-indent line, comments
        # included, misses both probes above.
        comment_stop = script.replace("/^[^ #]/", "/^[^ ]/").replace(
            "/^  [^ #]/", "/^  [^ ]/"
        )
        _, stop_plain = run_artifact_inputs_step(step, job_id, None, script=comment_stop)
        _, stop_low = run_artifact_inputs_step(
            step, job_id, None, script=comment_stop, workflow=probed_low
        )
        stop_jobs = [
            run_artifact_inputs_step(
                step, job_id, None, script=comment_stop, workflow=w
            )[1]
            for w in job_probes
        ]
        check(
            f"{job_id}: a step whose extraction stops at a comment is reported",
            comment_stop != script
            and stop_low == stop_plain
            and stop_jobs[0] == stop_jobs[1],
            "extraction that stops at a comment still saw a variable or job key "
            "written below one",
        )
        # Control: the step with its workflow-env line removed is reported.
        without_env = "\n".join(
            line for line in script.splitlines() if '"$workflow_env"' not in line
        )
        _, plain = run_artifact_inputs_step(step, job_id, None, script=without_env)
        _, plain_probed = run_artifact_inputs_step(
            step, job_id, None, script=without_env, workflow=probed
        )
        check(
            f"{job_id}: a step that hashes no workflow env is reported",
            without_env != script and plain == plain_probed,
            "removing the workflow env from the digest still changed the digest",
        )


# Each producer whose upload lists several paths, with the artifact it uploads, the
# marker file the job touches before its build under RUNNER_TEMP, the uploaded paths the
# checkout tracks (a cache hit that leaves a tracked path out cannot be detected,
# because the checkout supplies it), and whether its verify step rejects a
# zero-byte output (kotlin-test's two paths are files; the xcframework's include
# directories).
MULTI_PATH_PRODUCERS = (
    (
        "xcframework",
        "swift-xcframework-dev",
        "xcframework-build-start",
        ("bindings/swift/Sources/SCP/Internal/ScpBindings.swift",),
        False,
    ),
    ("kotlin-test", "uniffi-kotlin-linux", "uniffi-kotlin-build-start", (), True),
)
# Uploaded paths that name a file rather than a directory.
UPLOADED_FILE_SUFFIXES = (".swift", ".so", ".kt")


def multi_path_producer_gaps(doc: dict) -> list[str]:
    """Name each job whose upload lists several paths but is not in the tuple, or
    sits in the tuple with no such upload."""
    uploaders = {
        job_id
        for job_id, job in (doc.get("jobs") or {}).items()
        for step in job.get("steps") or []
        if str(step.get("uses") or "").startswith("actions/upload-artifact")
        and len(str((step.get("with") or {}).get("path") or "").split()) > 1
    }
    listed = {row[0] for row in MULTI_PATH_PRODUCERS}
    return [
        f"{job_id} uploads several paths and is missing from MULTI_PATH_PRODUCERS"
        for job_id in sorted(uploaders - listed)
    ] + [
        f"{job_id} is in MULTI_PATH_PRODUCERS and has no upload listing several paths"
        for job_id in sorted(listed - uploaders)
    ]


def check_multi_path_producers_are_listed(doc: dict) -> None:
    """MULTI_PATH_PRODUCERS holds exactly the jobs whose upload lists several paths."""
    gaps = multi_path_producer_gaps(doc)
    check(
        "MULTI_PATH_PRODUCERS equals the jobs whose upload lists several paths",
        not gaps,
        "; ".join(gaps),
    )
    mutated = copy.deepcopy(doc)
    for step in mutated["jobs"]["napi-addon"]["steps"]:
        if (step.get("with") or {}).get("name") == "napi-addon-linux":
            step["with"]["path"] += "\nbindings/typescript/index.d.ts"
    gaps = multi_path_producer_gaps(mutated)
    check(
        "a second path on napi-addon's upload is reported as missing from the tuple",
        gaps
        == [
            "napi-addon uploads several paths and is missing from MULTI_PATH_PRODUCERS"
        ],
        f"got {gaps}",
    )
    mutated = copy.deepcopy(doc)
    for step in mutated["jobs"]["kotlin-test"]["steps"]:
        if (step.get("with") or {}).get("name") == "uniffi-kotlin-linux":
            step["with"]["path"] = step["with"]["path"].split()[0]
    gaps = multi_path_producer_gaps(mutated)
    check(
        "kotlin-test uploading one path is reported as extra in the tuple",
        gaps
        == [
            (
                "kotlin-test is in MULTI_PATH_PRODUCERS and has no upload listing "
                "several paths"
            )
        ],
        f"got {gaps}",
    )


def check_multi_path_outputs_are_verified(
    doc: dict,
    job_id: str,
    artifact: str,
    marker_name: str,
    tracked: tuple[str, ...],
    rejects_empty: bool,
) -> None:
    """Run a producer's verify step against each uploaded path gone or stale.

    CRITERION: for every path the `artifact` upload lists, the step before that
    upload exits non-zero when the path is absent or holds nothing newer than the
    marker the job touches before its build, and exits 0 when every path is fresh.
    On a cache hit (ARTIFACT_CACHE_HIT=true, no build, no marker) the step exits
    non-zero when an untracked path is absent and exits 0 when every path is
    present. When `rejects_empty` is set, the step also exits non-zero when a path
    is a fresh zero-byte file, after a build and on a cache hit.

    WHY: `if-no-files-found: error` fires only when all listed paths together match
    nothing. The xcframework upload lists the tracked ScpBindings.swift, so the
    checkout always supplies a match, and a build that writes one of kotlin-test's
    two paths satisfies the option, so the option alone cannot fail either producer.
    """
    steps = doc["jobs"][job_id]["steps"]
    upload = next(
        i
        for i, step in enumerate(steps)
        if (step.get("with") or {}).get("name") == artifact
    )
    script = steps[upload - 1].get("run") or ""
    paths = (steps[upload]["with"]["path"]).split()
    check(
        f"{job_id}: the {artifact} upload lists more than one path",
        len(paths) > 1,
        f"it lists {paths}",
    )
    marker_touched = any(
        f'touch "$RUNNER_TEMP/{marker_name}"' in str(step.get("run") or "")
        for step in steps[:upload]
    )
    check(
        f"{job_id}: a step before the upload touches the {marker_name} marker",
        marker_touched,
        "the verify step compares against a marker no step writes",
    )
    now = 1_000_000_000

    def run_with(
        missing: str | None,
        stale: str | None,
        hit: bool = False,
        empty: str | None = None,
    ) -> int:
        with tempfile.TemporaryDirectory() as root:
            runner_temp = Path(root, "runner-temp")
            runner_temp.mkdir()
            if not hit:
                marker = runner_temp / marker_name
                marker.touch()
                os.utime(marker, (now, now))
            for path in paths:
                if path == missing:
                    continue
                target = Path(root, "tree", path)
                file = (
                    target
                    if target.suffix in UPLOADED_FILE_SUFFIXES
                    else target / "content"
                )
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("" if path == empty else "built\n")
                stamp = now - 100 if path == stale or hit else now + 100
                for entry in {file, target}:
                    os.utime(entry, (stamp, stamp))
            env = {**os.environ, "RUNNER_TEMP": str(runner_temp)}
            env.pop("ARTIFACT_CACHE_HIT", None)
            if hit:
                env["ARTIFACT_CACHE_HIT"] = "true"
            return subprocess.run(
                ["bash", "-c", script],
                cwd=Path(root, "tree"),
                env=env,
                capture_output=True,
                check=False,
            ).returncode

    check(
        f"{job_id}: the verify step passes when the build wrote every output",
        run_with(None, None) == 0,
        "the verify step rejects a build that wrote every uploaded path",
    )
    for path in paths:
        check(
            f"{job_id}: a missing {path} fails the producer",
            run_with(path, None) != 0,
            f"the verify step before the upload passes without {path}",
        )
        check(
            f"{job_id}: a {path} older than the build fails the producer",
            run_with(None, path) != 0,
            f"the verify step before the upload passes over a stale {path}",
        )
    check(
        f"{job_id}: on a cache hit the verify step passes when the restore wrote "
        "every output",
        run_with(None, None, hit=True) == 0,
        "the verify step rejects a cache hit that restored every uploaded path",
    )
    # The checkout supplies a tracked path, so CI cannot reach a hit that lacks it.
    for path in (p for p in paths if p not in tracked):
        check(
            f"{job_id}: on a cache hit a missing {path} fails the producer",
            run_with(path, None, hit=True) != 0,
            f"the verify step passes a cache hit without {path}",
        )
    if rejects_empty:
        for path in paths:
            check(
                f"{job_id}: a zero-byte {path} written by the build fails the producer",
                run_with(None, None, empty=path) != 0,
                f"the verify step before the upload passes over an empty {path}",
            )
            check(
                f"{job_id}: on a cache hit a zero-byte {path} fails the producer",
                run_with(None, None, hit=True, empty=path) != 0,
                f"the verify step passes a cache hit that restored an empty {path}",
            )


def a_producer_and_an_unguarded_consumer(
    doc: dict, artifact: str, upload_path: str, test_command: str
) -> dict:
    """Return `doc` with one producer of `artifact` and one consumer that skips it.

    The consumer downloads `artifact` and runs `test_command`, and no step before
    the test carries any assertion fragment.
    """
    mutated = copy.deepcopy(doc)
    mutated["jobs"]["producer-added-by-the-control"] = {
        "runs-on": "windows-latest",
        "steps": [
            {
                "uses": "actions/upload-artifact@v4",
                "with": {"name": artifact, "path": upload_path},
            }
        ],
    }
    mutated["jobs"]["consumer-added-by-the-control"] = {
        "runs-on": "windows-latest",
        "steps": [
            {
                "uses": "actions/download-artifact@v4",
                "with": {"name": artifact, "path": "."},
            },
            {"run": test_command},
        ],
    }
    return mutated


def check_a_new_producer_reaches_the_pyo3_gate(doc: dict) -> None:
    """A PyO3 producer added under a name no line of this file writes is still gated.

    A tuple of artifact names written in this file holds the names somebody
    remembered to list, and says nothing about a producer added later. This control
    adds the producer and the consumer a Windows leg would add, names the artifact
    something this file never mentions, and requires the gate to report the consumer
    that runs pytest with no assertion fragment before it.
    """
    artifact = "pyo3-module-added-by-the-control"
    mutated = a_producer_and_an_unguarded_consumer(
        doc, artifact, "bindings/python/scp_sdk/_scp_core*.pyd", "pytest tests -v"
    )
    gaps = pyo3_consumers_missing_an_assertion_fragment(
        mutated, uploaded_artifact_names(mutated, PYO3_UPLOAD_FILENAME)
    )
    check(
        "a PyO3 consumer of a producer added under an unlisted name is reported",
        any(gap.startswith("consumer-added-by-the-control ") for gap in gaps),
        f"a job downloading {artifact} and running pytest with no assertion "
        f"fragment went unreported: {gaps}",
    )


def check_a_new_producer_reaches_the_napi_gate(doc: dict) -> None:
    """A NAPI producer added under a name no line of this file writes is still gated."""
    artifact = "napi-addon-added-by-the-control"
    mutated = a_producer_and_an_unguarded_consumer(
        doc, artifact, "target/release/scp_ffi_napi.dll", "bun test"
    )
    gaps = napi_consumers_missing_an_assertion_fragment(
        mutated, uploaded_artifact_names(mutated, NAPI_UPLOAD_FILENAME)
    )
    check(
        "a NAPI consumer of a producer added under an unlisted name is reported",
        any(gap.startswith("consumer-added-by-the-control ") for gap in gaps),
        f"a job downloading {artifact} and running its tests with no assertion "
        f"fragment went unreported: {gaps}",
    )


def cache_write(step: dict) -> str | None:
    """Name the cache one step writes, or None when it writes none.

    A step writes a cache when a later run of any ref can restore what it saves:
    a `Swatinem/rust-cache` step whose `save-if` is not the literal false, an
    `actions/cache` or `actions/cache/save` step, a `gradle/actions/setup-gradle`
    step that neither disables its cache nor sets `cache-read-only` to the literal
    true (it writes on the default branch by default), a step exporting a layer
    cache through `cache-to`, an `oven-sh/setup-bun` step that does not set
    `no-cache` to the literal true (it caches the bun executable by default), and
    a setup action given a `cache:` input. An input
    written as an expression counts as writing, so an unreadable input errs toward
    holding the job on push rather than toward skipping a writer.
    """
    uses = str(step.get("uses") or "")
    action = uses.split("@", 1)[0]
    inputs = step.get("with") or {}

    def literal(name: str) -> str:
        return str(inputs.get(name, "")).strip().lower()

    if action == "Swatinem/rust-cache":
        if literal("save-if") == "false":
            return None
        return f"rust-cache `{inputs.get('shared-key')}`"
    if action in ("actions/cache", "actions/cache/save"):
        return f"{action} `{inputs.get('key')}`"
    if action == "gradle/actions/setup-gradle":
        if literal("cache-disabled") == "true" or literal("cache-read-only") == "true":
            return None
        return "the Gradle user-home cache"
    if action == "oven-sh/setup-bun":
        if literal("no-cache") == "true":
            return None
        return "the setup-bun executable cache"
    if "cache-to" in inputs:
        return f"layer cache `{inputs['cache-to']}`"
    if action.startswith("actions/setup-") and inputs.get("cache"):
        return f"{action} cache `{inputs['cache']}`"
    return None


# Caches whose key names no job: setup-bun keys its entry by bun version, OS and
# architecture, so a push that runs any one job writing it refreshes the entry
# every other job restores.
SHARED_KEY_CACHES = frozenset({"the setup-bun executable cache"})


def cache_writers(doc: dict, shared: bool = True) -> dict[str, list[str]]:
    """Map each job holding a cache-writing step to the caches it writes.

    With `shared` false, the caches SHARED_KEY_CACHES names are left out.
    """
    writers: dict[str, list[str]] = {}
    for job_id, job in doc["jobs"].items():
        written = [
            name
            for step in job.get("steps") or []
            if isinstance(step, dict)
            for name in [cache_write(step)]
            if name is not None and (shared or name not in SHARED_KEY_CACHES)
        ]
        if written:
            writers[job_id] = written
    return writers


# A matrix value chosen by event: `${{ fromJSON(github.event_name == 'push' &&
# '<push list>' || '<every other event's list>') }}`. Any other expression in a
# writer's matrix is reported as unreadable.
PUSH_MATRIX = re.compile(
    r"^\$\{\{\s*fromJSON\(\s*github\.event_name\s*==\s*'push'\s*&&\s*'(\[[^']*\])'"
    r"\s*\|\|\s*'(\[[^']*\])'\s*\)\s*\}\}$"
)
SAVE_IF_MATRIX = re.compile(r"matrix\.([\w-]+)\s*==\s*'?([\w.-]+)'?")
# A matrix axis a cache key expands, so that each value of the axis writes its own
# entry: `shared-key: transport-optional-${{ matrix.group }}`.
KEY_MATRIX_AXIS = re.compile(r"\$\{\{\s*matrix\.([\w-]+)\s*\}\}")
# A key that names the runner's platform, so each runner writes its own entry.
# Swatinem/rust-cache puts the platform into every key without the text naming it.
KEY_RUNNER = re.compile(r"\brunner\.(?:os|arch)\b")


def push_runs_step(step: dict) -> bool:
    """Report whether a push to `main` can run one step and meet its `save-if`.

    The step's `if:` and its `save-if`, each with or without the `${{ … }}`
    wrapper, are joined with `&&` and read with parse_condition's grammar.
    `github.event_name` reads `push` and `github.ref` reads `refs/heads/main`.
    Every other comparison that names some other name may come out either way,
    and one pair of operands gets one answer wherever it appears. The step runs
    on push when some choice of those answers makes the whole expression true.
    An expression outside the grammar raises ValueError.
    """
    inputs = step.get("with") or {}
    parts = []
    for text in (step.get("if"), inputs.get("save-if")):
        text = str(text or "").strip()
        wrapped = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.DOTALL)
        text = (wrapped.group(1) if wrapped else text).strip()
        if text:
            parts.append(f"({text})")
    if not parts:
        return True
    tree = parse_condition(" && ".join(parts))
    known = {"github.event_name": "push", "github.ref": "refs/heads/main"}

    def operand(token: str) -> str | None:
        quoted = re.fullmatch(r"'([^']*)'", token)
        if quoted:
            return quoted.group(1)
        if token in ("true", "false") or token.isdigit():
            return token
        return known.get(token)

    free: list[tuple[str, ...]] = []

    def collect(node: tuple) -> None:
        if node[0] in ("or", "and"):
            for part in node[1]:
                collect(part)
        elif None in (operand(node[1]), operand(node[2])):
            pair = tuple(sorted((node[1], node[2])))
            if pair not in free:
                free.append(pair)

    def value(node: tuple, answers: dict) -> bool:
        if node[0] in ("or", "and"):
            results = [value(part, answers) for part in node[1]]
            return any(results) if node[0] == "or" else all(results)
        left, right = operand(node[1]), operand(node[2])
        if None in (left, right):
            equal = answers[tuple(sorted((node[1], node[2])))]
        else:
            equal = left == right
        return equal if node[0] == "==" else not equal

    collect(tree)
    return any(
        value(tree, {pair: bool(mask >> index & 1) for index, pair in enumerate(free)})
        for mask in range(2 ** len(free))
    )


def push_writer_gaps(doc: dict) -> list[str]:
    """Return every way a push to `main` would skip a cache write.

    CRITERION: a job holding a cache-writing step runs on a push to `main` wherever
    a merge_group run with the same filter outputs runs it, and some push runs it at
    all; a matrix leg that a writing step's `save-if` or `if:` names exists on push;
    and every value that every other event runs on an axis a writing step's cache
    key expands (`shared-key` or `key` holding `${{ matrix.<axis> }}`, or, for a
    rust-cache step or a key holding `runner.os` or `runner.arch`, an axis the job's
    `runs-on` names) also runs on push, because each such value names its own entry;
    and push_runs_step finds that a push can meet each writing step's `if:` and
    `save-if` together. A cache SHARED_KEY_CACHES
    names needs only that some push runs some job writing it.

    WHY: rust-cache and `actions/cache/save` write only on `refs/heads/main`, so a
    writer that a push skips leaves its entry to go stale until eviction, and every
    pull request and merge-queue run then compiles from a miss. Nothing goes red:
    the `ci` aggregate evaluates the writer's own `if:`, which says skip. The jobs a
    writer needs are dependency_condition_gaps' business, since GitHub skips a job
    whose dependency skipped and that check enumerates the push event.
    """
    gaps: list[str] = []
    assignments = condition_assignments(doc)
    holders = cache_writers(doc)
    for cache in sorted(SHARED_KEY_CACHES):
        pushed = False
        for job_id in sorted(job for job, written in holders.items() if cache in written):
            condition = doc["jobs"][job_id].get("if") or "true == 'true'"
            try:
                pushed = pushed or any(
                    selects(condition, outputs, event)
                    for outputs, event in assignments
                    if event == "push"
                )
            except ValueError as unreadable:
                gaps.append(
                    f"{job_id} writes {cache} and this check cannot decide whether a "
                    f"push runs it ({unreadable})"
                )
                pushed = True
        if not pushed and any(cache in written for written in holders.values()):
            gaps.append(f"jobs write {cache} and no push to `main` runs any of them")
    for job_id, written in sorted(cache_writers(doc, shared=False).items()):
        job = doc["jobs"][job_id]
        condition = job.get("if") or "true == 'true'"
        caches = ", ".join(written)
        try:
            pushes = [
                outputs
                for outputs, event in assignments
                if event == "push" and selects(condition, outputs, event)
            ]
            dropped = [
                outputs
                for outputs, event in assignments
                if event == "merge_group"
                and selects(condition, outputs, event)
                and not selects(condition, outputs, "push")
            ]
        except ValueError as unreadable:
            gaps.append(
                f"{job_id} writes {caches} and this check cannot decide whether a "
                f"push runs it ({unreadable})"
            )
            continue
        if not pushes:
            gaps.append(f"{job_id} writes {caches} and no push to `main` runs it")
        elif dropped:
            selected = sorted(key for key, on in dropped[0].items() if on == "true")
            gaps.append(
                f"{job_id} writes {caches}, and a push with filters "
                f"{selected or ['none']} true skips it where a merge_group run with "
                f"the same filters runs it"
            )
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        if not isinstance(matrix, dict):
            gaps.append(f"{job_id} writes {caches} through a matrix this check cannot read")
            continue
        on_push: dict[str, list] = {}
        elsewhere: dict[str, list] = {}
        for key, values in matrix.items():
            if isinstance(values, list):
                on_push[key] = values
                elsewhere[key] = values
                continue
            chosen = PUSH_MATRIX.match(str(values))
            if chosen is None:
                gaps.append(
                    f"{job_id} writes {caches} and its matrix `{key}` is an expression "
                    f"this check cannot read: {values!r}"
                )
                continue
            push_values, other_values = (json.loads(group) for group in chosen.groups())
            if not set(map(str, push_values)) <= set(map(str, other_values)):
                gaps.append(
                    f"{job_id}'s matrix `{key}` runs {push_values} on push, outside "
                    f"the {other_values} every other event runs"
                )
            on_push[key] = push_values
            elsewhere[key] = other_values
        for step in job.get("steps") or []:
            if not isinstance(step, dict) or cache_write(step) is None:
                continue
            inputs = step.get("with") or {}
            try:
                if not push_runs_step(step):
                    gaps.append(
                        f"{job_id} saves {cache_write(step)} from a step whose `if:` "
                        f"and `save-if` no push to `main` meets"
                    )
            except ValueError as unreadable:
                gaps.append(
                    f"{job_id} saves {cache_write(step)} from a step whose `if:` or "
                    f"`save-if` this check cannot read ({unreadable})"
                )
            leg_conditions = f"{inputs.get('save-if', '')} {step.get('if') or ''}"
            for key, value in SAVE_IF_MATRIX.findall(leg_conditions):
                if key in on_push and value not in map(str, on_push[key]):
                    gaps.append(
                        f"{job_id} saves {cache_write(step)} only from matrix leg "
                        f"`{key} == {value}`, and a push runs `{key}` over "
                        f"{on_push[key]} alone"
                    )
            key_text = f"{inputs.get('shared-key', '')} {inputs.get('key', '')}"
            key_axes = set(KEY_MATRIX_AXIS.findall(key_text))
            action = str(step.get("uses") or "").split("@", 1)[0]
            if action == "Swatinem/rust-cache" or KEY_RUNNER.search(key_text):
                key_axes |= set(KEY_MATRIX_AXIS.findall(str(job.get("runs-on") or "")))
            for key in sorted(key_axes):
                if key not in on_push:
                    continue
                pushed_values = set(map(str, on_push[key]))
                unwritten = [v for v in elsewhere[key] if str(v) not in pushed_values]
                if unwritten:
                    gaps.append(
                        f"{job_id} writes {cache_write(step)}, one entry per value of "
                        f"matrix `{key}`, and a push never runs {unwritten}, so those "
                        f"entries are never written"
                    )
    return gaps


# A step's `if:` that selects one value of one matrix axis, with or without the
# `${{ … }}` wrapper GitHub accepts around a step condition.
AXIS_CONDITION = re.compile(
    r"^\s*(?:\$\{\{\s*)?matrix\.([A-Za-z0-9_-]+)\s*==\s*'([^']*)'\s*(?:\}\})?\s*$"
)


def matrix_axis_gaps(doc: dict) -> list[str]:
    """Return each disagreement between a job's matrix axes and its steps.

    CRITERION: in every job, an axis of `strategy.matrix` is read when at least
    one step's `if:` reads exactly `matrix.<axis> == '<value>'`. For each axis
    read, every value such a step names is in the axis list, and, unless the
    job's `runs-on` reads that axis, every value the axis lists is named by at
    least one such step. A value no step names runs legs that skip every gated
    step, and a step naming a value the axis lacks never runs on any leg, so
    its commands run nowhere while every leg passes. An axis `runs-on` reads
    picks each leg's runner, so a step gated to one of its values (a macOS-only
    install) leaves the other legs running every ungated step. Another step whose `if:` mentions `matrix.<axis>` for an axis read
    is reported rather than read, because this check could not say which legs
    run it. A matrix carrying `include` or `exclude` is reported rather than
    read, because either one can add or remove an axis value's legs while the
    axis list stays the same. A step whose `if:` reads that form on an axis the
    job's matrix does not define, as a key or inside an `include` entry, is
    reported, because GitHub runs it on no leg.
    """
    gaps = []
    for job_id, job in sorted(doc["jobs"].items()):
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        if not isinstance(matrix, dict):
            continue
        steps = [
            (step.get("name") or f"step {index + 1}", str(step.get("if") or ""))
            for index, step in enumerate(job.get("steps") or [])
            if isinstance(step, dict)
        ]
        defined = {key for key in matrix if key not in ("include", "exclude")}
        for entry in matrix.get("include") or []:
            if isinstance(entry, dict):
                defined.update(entry)
        for label, condition in steps:
            match = AXIS_CONDITION.match(condition)
            if match and match.group(1) not in defined:
                gaps.append(
                    f"{job_id}: {label!r} has `if: {condition}`, but the job's "
                    f"matrix defines no axis {match.group(1)}, so it runs on no leg"
                )
        read_axes = sorted(
            {
                match.group(1)
                for _, condition in steps
                if (match := AXIS_CONDITION.match(condition))
                and match.group(1) in matrix
                and match.group(1) not in ("include", "exclude")
            }
        )
        if not read_axes:
            continue
        expanders = [key for key in ("include", "exclude") if key in matrix]
        if expanders:
            gaps.append(
                f"{job_id}: matrix carries {' and '.join(expanders)}, which this "
                f"check does not expand into legs"
            )
            continue
        for axis_name in read_axes:
            axis = matrix[axis_name]
            if not isinstance(axis, list) or not all(isinstance(v, str) for v in axis):
                gaps.append(
                    f"{job_id}: matrix axis {axis_name} {axis!r} is not a list of names"
                )
                continue
            mention = re.compile(rf"\bmatrix\.{re.escape(axis_name)}(?![A-Za-z0-9_-])")
            named: set[str] = set()
            for label, condition in steps:
                if not mention.search(condition):
                    continue
                match = AXIS_CONDITION.match(condition)
                if match is None or match.group(1) != axis_name:
                    gaps.append(
                        f"{job_id}: {label!r} has `if: {condition}`, which is not "
                        f"`matrix.{axis_name} == '<value>'`"
                    )
                    continue
                value = match.group(2)
                named.add(value)
                if value not in axis:
                    gaps.append(
                        f"{job_id}: {label!r} names {axis_name} {value!r}, which "
                        f"matrix axis {axis_name} {axis} lacks, so its commands "
                        f"run on no leg"
                    )
            if mention.search(str(job.get("runs-on") or "")):
                continue
            for value in axis:
                if value not in named:
                    gaps.append(
                        f"{job_id}: matrix axis {axis_name} value {value!r} has no "
                        f"step whose `if:` names it"
                    )
    return gaps


def scenario_disagreements(doc: dict) -> list[str]:
    """Return each (scenario, job) whose `if:` and SCENARIOS answer differently."""
    found: list[str] = []
    for scenario in SCENARIOS.values():
        for job_id, expected in sorted(scenario.runs.items()):
            condition = doc["jobs"].get(job_id, {}).get("if")
            if condition is None:
                continue
            try:
                actual = selects(condition, scenario.filters, scenario.event)
            except ValueError as unreadable:
                found.append(f"{scenario.name}: {job_id} unreadable ({unreadable})")
                continue
            if actual != expected:
                found.append(
                    f"{scenario.name}: {job_id} {'runs' if actual else 'skips'}, "
                    f"SCENARIOS says it {'runs' if expected else 'skips'}"
                )
    return found


def skipped_writers(doc: dict) -> list[str]:
    """Return each job NOT_ON_PUSH_JOBS or NOT_ON_PUSH_FILTER_JOBS lists that writes a
    cache SHARED_KEY_CACHES does not name."""
    writers = cache_writers(doc, shared=False)
    skipped = set(writers) & (set(NOT_ON_PUSH_JOBS) | set(NOT_ON_PUSH_FILTER_JOBS))
    return [f"{job_id} writes {', '.join(writers[job_id])}" for job_id in sorted(skipped)]


def check_push_runs_every_cache_writer(doc: dict) -> None:
    writers = cache_writers(doc)
    # The detector has to find the writers this workflow holds today, or the gap
    # check below passes over an empty set.
    for job_id in (
        "bridge-parity-kotlin",
        "docker-image-cache",
        "fuzz-build",
        "kotlin-lint",
        "kotlin-test",
        "napi-addon",
        "pyo3-module",
        "pyo3-module-macos",
        "rust-clippy",
        "rust-test",
        "rust-test-optional-features",
        "typescript-wasm-check",
        "xcframework",
    ):
        check(f"{job_id} is read as a cache writer", job_id in writers, f"{writers}")
    gaps = push_writer_gaps(doc)
    check("ci.yml: a push to `main` runs every cache writer", not gaps, "; ".join(gaps))
    for step, expected in (
        ({"uses": "oven-sh/setup-bun@v2"}, True),
        ({"uses": "oven-sh/setup-bun@v2", "with": {"no-cache": "false"}}, True),
        ({"uses": "oven-sh/setup-bun@v2", "with": {"no-cache": True}}, False),
    ):
        check(
            f"cache_write({step}) {'writes' if expected else 'writes nothing'}",
            (cache_write(step) is not None) is expected,
        )
    skipped = skipped_writers(doc)
    check("no job SCENARIOS skips on push writes a cache", not skipped, "; ".join(skipped))
    disagreements = scenario_disagreements(doc)
    check(
        "every scenario's answer matches the job's own `if:`",
        not disagreements,
        "; ".join(disagreements),
    )


def check_push_writer_mutants(doc: dict) -> None:
    """Each way of skipping a writer on push, or leaking a push skip, is reported."""
    guarded = copy.deepcopy(doc)
    clippy = guarded["jobs"]["rust-clippy"]
    clippy["if"] = f"github.event_name != 'push' && ({clippy['if']})"
    gaps = push_writer_gaps(guarded)
    check(
        "a push guard on writer rust-clippy is reported",
        any(gap.startswith("rust-clippy writes") for gap in gaps)
        and not any("cannot decide" in gap for gap in gaps),
        f"{gaps}",
    )
    check(
        "a push guard on writer rust-clippy disagrees with SCENARIOS",
        any(
            "rust-only, push: rust-clippy skips" in found
            for found in scenario_disagreements(guarded)
        ),
        f"{scenario_disagreements(guarded)}",
    )

    shard = copy.deepcopy(doc)
    shard["jobs"]["rust-test"]["strategy"]["matrix"]["shard"] = (
        "${{ fromJSON(github.event_name == 'push' && '[2]' || '[1, 2, 3, 4]') }}"
    )
    gaps = push_writer_gaps(shard)
    check(
        "a push matrix without the writing shard is reported",
        any("rust-test saves" in gap for gap in gaps),
        f"{gaps}",
    )

    # rust-test-optional-features writes one rust-cache entry per `group` value
    # through its key, and rust-clippy one entry per `leg` value through a writing
    # step gated on that leg. A push matrix dropping a value leaves its entry
    # unwritten; a push matrix keeping every value leaves nothing to report.
    # rust-test and rust-test-optional-features also write one rust-cache entry per
    # `os` value, because `runs-on` reads that axis and rust-cache keys by platform.
    for job_id, axis, dropped_value, reported in (
        (
            "rust-test-optional-features",
            "group",
            "node-relay",
            "one entry per value of matrix `group`, and a push never runs ['node-relay']",
        ),
        (
            "rust-test",
            "os",
            "macos-latest",
            "one entry per value of matrix `os`, and a push never runs ['macos-latest']",
        ),
        (
            "rust-test-optional-features",
            "os",
            "macos-latest",
            "one entry per value of matrix `os`, and a push never runs ['macos-latest']",
        ),
        ("rust-clippy", "leg", "examples", "only from matrix leg `leg == examples`"),
    ):
        live_axis = doc["jobs"][job_id]["strategy"]["matrix"][axis]
        check(
            f"{job_id}'s `{axis}` axis lists {dropped_value} for the push-matrix control",
            isinstance(live_axis, list) and dropped_value in live_axis,
            f"{live_axis!r}",
        )
        every = json.dumps(live_axis)
        fewer = json.dumps([value for value in live_axis if value != dropped_value])
        narrowed = copy.deepcopy(doc)
        narrowed["jobs"][job_id]["strategy"]["matrix"][axis] = (
            f"${{{{ fromJSON(github.event_name == 'push' && '{fewer}' || '{every}') }}}}"
        )
        gaps = push_writer_gaps(narrowed)
        check(
            f"a push matrix dropping {job_id}'s `{axis}` value {dropped_value} is reported",
            any(gap.startswith(f"{job_id} ") and reported in gap for gap in gaps),
            f"{gaps}",
        )
        whole = copy.deepcopy(doc)
        whole["jobs"][job_id]["strategy"]["matrix"][axis] = (
            f"${{{{ fromJSON(github.event_name == 'push' && '{every}' || '{every}') }}}}"
        )
        check(
            f"a push matrix keeping every {job_id} `{axis}` value is not reported",
            not any(gap.startswith(f"{job_id} ") for gap in push_writer_gaps(whole)),
            f"{push_writer_gaps(whole)}",
        )

    # An actions/cache key splits by `runs-on` only when it names the platform.
    for key, split in (("deps-${{ runner.os }}-v1", True), ("deps-v1", False)):
        cached = copy.deepcopy(doc)
        job = cached["jobs"]["rust-test"]
        job["strategy"]["matrix"]["os"] = (
            "${{ fromJSON(github.event_name == 'push' && '[\"ubuntu-latest\"]' "
            "|| '[\"ubuntu-latest\", \"macos-latest\"]') }}"
        )
        job["steps"] = [
            {"uses": "actions/cache@v4", "with": {"path": "deps", "key": key}}
            if str(step.get("uses", "")).startswith("Swatinem/rust-cache")
            else step
            for step in job["steps"]
        ]
        gaps = push_writer_gaps(cached)
        check(
            f"an actions/cache key `{key}` on a push matrix dropping macos-latest is "
            f"{'reported' if split else 'not reported'}",
            any("matrix `os`" in gap for gap in gaps) is split,
            f"{gaps}",
        )

    partial = copy.deepcopy(doc)
    pyo3 = partial["jobs"]["pyo3-module"]
    pyo3["if"] = pyo3["if"].replace(
        "needs.changes.outputs.python == 'true' ||",
        "(github.event_name != 'push' && needs.changes.outputs.python == 'true') ||",
    )
    gaps = push_writer_gaps(partial)
    check(
        "a push guard on one clause of writer pyo3-module is reported",
        any(
            gap.startswith("pyo3-module writes") and "skips it where a merge_group run" in gap
            for gap in gaps
        ),
        f"{gaps}",
    )

    # A writing step's own `if:` or `save-if` can exclude push while its job runs.
    def step_where(job: dict, predicate) -> dict:
        return next(
            step for step in job["steps"] if isinstance(step, dict) and predicate(step)
        )

    def clippy_workspace(job: dict) -> dict:
        return step_where(job, lambda step: step.get("if") == "matrix.leg == 'workspace'")

    def test_cache(job: dict) -> dict:
        return step_where(
            job, lambda step: str(step.get("uses", "")).startswith("Swatinem/rust-cache")
        )

    def pyo3_save(job: dict) -> dict:
        return step_where(
            job, lambda step: str(step.get("uses", "")).startswith("actions/cache/save")
        )

    no_push = "github.event_name != 'push'"
    for label, job_id, locate, field, text, reported in (
        (
            "a push exclusion on rust-clippy's workspace rust-cache `if:`",
            "rust-clippy",
            clippy_workspace,
            "if",
            f"matrix.leg == 'workspace' && {no_push}",
            "no push to `main` meets",
        ),
        (
            "a merge_group-only rust-test rust-cache `save-if`",
            "rust-test",
            test_cache,
            "save-if",
            "${{ github.event_name == 'merge_group' && matrix.shard == 1 }}",
            "no push to `main` meets",
        ),
        (
            "a push exclusion on pyo3-module's cache save `if:`",
            "pyo3-module",
            pyo3_save,
            "if",
            f"steps.artifact-cache.outputs.cache-hit != 'true' && {no_push}",
            "no push to `main` meets",
        ),
        (
            "a writing step condition that contradicts itself on one operand pair",
            "rust-clippy",
            clippy_workspace,
            "if",
            "matrix.leg == 'workspace' && matrix.leg != 'workspace'",
            "no push to `main` meets",
        ),
        (
            "a writing step `if:` outside the grammar",
            "rust-clippy",
            clippy_workspace,
            "if",
            "matrix.leg == 'workspace' && !cancelled()",
            "this check cannot read",
        ),
        (
            "a writing step `if:` that admits push alongside other events",
            "rust-clippy",
            clippy_workspace,
            "if",
            f"matrix.leg == 'workspace' && ({no_push} || github.ref == 'refs/heads/main')",
            None,
        ),
        (
            "a rust-cache `save-if` naming a number and the main ref",
            "rust-test",
            test_cache,
            "save-if",
            "${{ github.ref == 'refs/heads/main' && matrix.shard == 1 }}",
            None,
        ),
    ):
        changed = copy.deepcopy(doc)
        step = locate(changed["jobs"][job_id])
        if field == "if":
            step["if"] = text
        else:
            step.setdefault("with", {})[field] = text
        gaps = [gap for gap in push_writer_gaps(changed) if gap.startswith(f"{job_id} ")]
        if reported is None:
            check(f"{label} is not reported", not gaps, f"{gaps}")
        else:
            check(
                f"{label} is reported",
                any(gap.startswith(f"{job_id} saves") and reported in gap for gap in gaps),
                f"{gaps}",
            )

    push_shards = "${{ fromJSON(github.event_name == 'push' && '[1, 5]' || '[1, 2, 3, 4]') }}"
    for label, key, value, reported in (
        (
            "a writer matrix that is one expression",
            None,
            "${{ fromJSON(inputs.matrix) }}",
            "through a matrix this check cannot read",
        ),
        (
            "a writer matrix key no pattern reads",
            "shard",
            "${{ fromJSON(inputs.shards) }}",
            "matrix `shard` is an expression this check cannot read",
        ),
        (
            "a push matrix leg outside every other event's legs",
            "shard",
            push_shards,
            "rust-test's matrix `shard` runs [1, 5] on push",
        ),
    ):
        changed = copy.deepcopy(doc)
        strategy = changed["jobs"]["rust-test"]["strategy"]
        if key is None:
            strategy["matrix"] = value
        else:
            strategy["matrix"][key] = value
        gaps = push_writer_gaps(changed)
        check(f"{label} is reported", any(reported in gap for gap in gaps), f"{gaps}")
    check(
        "the unmutated rust-test matrix is read without a gap",
        not any(gap.startswith("rust-test") for gap in push_writer_gaps(doc)),
        f"{push_writer_gaps(doc)}",
    )

    writing = copy.deepcopy(doc)
    writing["jobs"]["error-codes"].setdefault("steps", []).append(
        {"uses": "actions/cache@v4", "with": {"key": "k", "path": "p"}}
    )
    check(
        "a cache write in a job NOT_ON_PUSH_JOBS lists is reported",
        any(found.startswith("error-codes writes") for found in skipped_writers(writing)),
        f"{skipped_writers(writing)}",
    )

    bun = copy.deepcopy(doc)
    bun["jobs"]["error-codes"].setdefault("steps", []).append(
        {"uses": "oven-sh/setup-bun@v2"}
    )
    check(
        "a setup-bun write in a push-skipped job is not reported while a push writes it",
        not skipped_writers(bun) and not push_writer_gaps(bun),
        f"{skipped_writers(bun)} {push_writer_gaps(bun)}",
    )
    for job in bun["jobs"].values():
        for step in job.get("steps") or []:
            if isinstance(step, dict) and str(step.get("uses", "")).startswith(
                "oven-sh/setup-bun@"
            ):
                guard = job.get("if")
                if guard is not None and "github.event_name != 'push'" not in guard:
                    job["if"] = f"github.event_name != 'push' && ({guard})"
                elif guard is None:
                    job["if"] = "github.event_name != 'push'"
    gaps = push_writer_gaps(bun)
    check(
        "no push running any setup-bun writer is reported",
        any("setup-bun executable cache and no push" in gap for gap in gaps),
        f"{gaps}",
    )

    draft = copy.deepcopy(doc)
    gate = draft["jobs"]["check-draft"]
    gate["if"] = f"github.event_name != 'push' && ({gate['if']})"
    gaps = dependency_condition_gaps(draft)
    check(
        "a push skip on check-draft, which every writer needs, is reported",
        any("changes runs and check-draft skips on event push" in gap for gap in gaps),
        f"{gaps}",
    )

    for job_id, event, scenario in (
        ("rust-fmt", "merge_group", "rust-only, merge_group"),
        ("error-codes", "pull_request", "docs-only, pull_request"),
        ("swift-lint", "merge_group", "swift-and-typescript, merge_group"),
        ("scaffold-typescript-web-check", "pull_request", "typescript-wasm-only, pull_request"),
    ):
        leaked = copy.deepcopy(doc)
        current = leaked["jobs"][job_id]["if"]
        leaked["jobs"][job_id]["if"] = current.replace(
            "github.event_name != 'push'", f"github.event_name != '{event}'"
        )
        check(
            f"{job_id} skipping on {event} disagrees with SCENARIOS",
            any(
                f"{scenario}: {job_id} skips" in found
                for found in scenario_disagreements(leaked)
            ),
            f"{scenario_disagreements(leaked)}",
        )

    for job_id, clause, scenario in (
        ("swift-build-test", "swift", "swift-and-typescript, merge_group"),
        ("bridge-parity-swift", "swift", "swift-and-typescript, pull_request"),
        ("bridge-parity", "typescript", "swift-and-typescript, merge_group"),
        ("typescript-check", "typescript", "swift-and-typescript, pull_request"),
        (
            "scaffold-typescript-web-check",
            "scaffold-typescript-web",
            "swift-and-typescript, merge_group",
        ),
        ("scaffold-typescript-web-check", "typescript-wasm", "typescript-wasm-only, merge_group"),
    ):
        dropped = copy.deepcopy(doc)
        current = dropped["jobs"][job_id]["if"]
        text = f"needs.changes.outputs.{clause} == 'true'"
        narrowed = re.sub(rf"\s*\|\|\s*{re.escape(text)}|{re.escape(text)}\s*\|\|\s*", "", current)
        check(f"the {clause} clause is found in {job_id}'s `if:`", narrowed != current, current)
        dropped["jobs"][job_id]["if"] = narrowed
        check(
            f"{job_id} without its {clause} clause disagrees with SCENARIOS",
            any(
                f"{scenario}: {job_id} skips" in found
                for found in scenario_disagreements(dropped)
            ),
            f"{scenario_disagreements(dropped)}",
        )

    for condition, scenario in (
        ("github.event_name == 'push'", "docs-only, push"),
        ("needs.changes.outputs.rust == 'true'", "rust-only, pull_request"),
    ):
        widened = copy.deepcopy(doc)
        widened["jobs"]["docker-image-cache"]["if"] = condition
        check(
            f"docker-image-cache on `{condition}` alone disagrees with SCENARIOS",
            any(
                f"{scenario}: docker-image-cache runs" in found
                for found in scenario_disagreements(widened)
            ),
            f"{scenario_disagreements(widened)}",
        )


def check_condition_grammar() -> None:
    """parse_condition reads the grammar ci.yml uses and refuses everything else."""
    outputs = {"rust": "true", "python": "false"}
    guarded = (
        "github.event_name != 'push' && "
        "(needs.changes.outputs.rust == 'true' || needs.changes.outputs.python == 'true')"
    )
    for expression, event, expected in (
        (guarded, "push", False),
        (guarded, "pull_request", True),
        (guarded, "merge_group", True),
        # `&&` binds tighter than `||`.
        (
            "needs.changes.outputs.rust == 'true' || "
            "needs.changes.outputs.python == 'true' && github.event_name == 'push'",
            "pull_request",
            True,
        ),
        (
            "(needs.changes.outputs.rust == 'true' || "
            "needs.changes.outputs.python == 'true') && github.event_name == 'push'",
            "pull_request",
            False,
        ),
    ):
        check(
            f"selects({expression!r}, {event}) is {expected}",
            selects(expression, outputs, event) is expected,
        )
    for expression in (
        "always()",
        "!cancelled()",
        "success() && needs.changes.outputs.rust == 'true'",
        "(needs.changes.outputs.rust == 'true'",
        "needs.changes.outputs.rust == 'true')",
        "needs.changes.outputs.rust",
        "needs.changes.outputs.rust == 'true' extra",
        "github.event_name != 'push' && needs.changes.outputs.renamed == 'true'",
        "",
    ):
        try:
            selects(expression, outputs, "push")
            refused = False
        except ValueError:
            refused = True
        check(f"selects refuses {expression!r}", refused)


def check_aggregate_grammar() -> None:
    """scripts/ci-aggregate-result.py reads the same grammar and refuses the rest.

    Each case runs the aggregate over a one-job workflow, so the verdict comes from
    that script's evaluator and the expected answer from this function's table.
    """
    for expression, event, skipped_ok in (
        ("github.event_name != 'push' && needs.changes.outputs.rust == 'true'", "push", True),
        ("github.event_name != 'push' && needs.changes.outputs.rust == 'true'", "merge_group", False),
        # With rust true, python false and the event pull_request, `&&` binding
        # tighter than `||` selects this job; `||` binding tighter, or a
        # left-to-right reading, skips it.
        (
            "needs.changes.outputs.rust == 'true' || "
            "needs.changes.outputs.python == 'true' && github.event_name == 'push'",
            "pull_request",
            False,
        ),
        # The parentheses turn the case above into a skip.
        (
            "(needs.changes.outputs.rust == 'true' || "
            "needs.changes.outputs.python == 'true') && github.event_name == 'push'",
            "pull_request",
            True,
        ),
    ):
        code, out = run_one_job_aggregate(expression, event)
        check(
            f"aggregate over a skipped `{expression}` on {event} -> exit "
            f"{0 if skipped_ok else 1}",
            code == (0 if skipped_ok else 1),
            f"exit {code}: {out}",
        )
    for expression in (
        "!cancelled()",
        "success() && needs.changes.outputs.rust == 'true'",
        "(needs.changes.outputs.rust == 'true'",
        "github.event_name != 'push' && needs.changes.outputs.renamed == 'true'",
    ):
        code, out = run_one_job_aggregate(expression, "push")
        check(f"aggregate refuses `{expression}` -> exit 2", code == 2, f"exit {code}: {out}")


def run_one_job_aggregate(expression: str, event: str) -> tuple[int, str]:
    """Run the aggregate over a workflow holding one job with this `if:`, skipped."""
    workflow = {
        "jobs": {
            "check-draft": {"runs-on": "ubuntu-latest"},
            "changes": {"needs": "check-draft", "outputs": {"rust": "x", "python": "x"}},
            "probe": {"needs": "changes", "if": expression},
            "ci": {"if": "always()", "needs": ["check-draft", "changes", "probe"]},
        }
    }
    needs = {
        "check-draft": {"result": "success"},
        "changes": {"result": "success", "outputs": {"rust": "true", "python": "false"}},
        "probe": {"result": "skipped"},
    }
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
        yaml.safe_dump(workflow, handle)
        path = handle.name
    try:
        proc = subprocess.run(
            [sys.executable, str(AGGREGATE), path],
            env=dict(os.environ, NEEDS_JSON=json.dumps(needs), GITHUB_EVENT_NAME=event),
            capture_output=True,
            text=True,
            cwd=REPO,
            check=False,
        )
    finally:
        os.unlink(path)
    return proc.returncode, proc.stdout + proc.stderr


def check_matrix_axes(path: Path, doc: dict) -> None:
    gaps = matrix_axis_gaps(doc)
    check(
        f"{path.name}: every gated matrix axis agrees with the steps gated on it",
        not gaps,
        "; ".join(gaps),
    )


def check_matrix_axis_controls(doc: dict) -> None:
    """Mutants of the live jobs, each of which the check must report.

    They mutate rust-test-optional-features' `group` axis and rust-clippy's
    `leg` axis in ci.yml, so a control fails if either job loses its axis as
    well as if the reader stops working.
    """
    for job_id, axis_name, kept, dropped_value in (
        ("rust-test-optional-features", "group", "transport", "platform-testing"),
        ("rust-clippy", "leg", "workspace", "packages"),
    ):
        live = doc["jobs"].get(job_id) or {}
        axis = ((live.get("strategy") or {}).get("matrix") or {}).get(axis_name)
        prefix = f"matrix.{axis_name} =="
        has_gated_step = any(
            str(step.get("if") or "").startswith(prefix)
            for step in live.get("steps") or []
            if isinstance(step, dict)
        )
        ready = isinstance(axis, list) and dropped_value in axis and has_gated_step
        check(
            f"{job_id} carries the {axis_name} axis and gated steps the controls "
            f"mutate",
            ready,
            f"{axis_name} axis {axis!r}, gated step present: {has_gated_step}",
        )
        if not ready:
            continue

        def gated(mutant: dict, job_id: str = job_id, prefix: str = prefix) -> list:
            return [
                step
                for step in mutant["jobs"][job_id]["steps"]
                if str(step.get("if") or "").startswith(prefix)
            ]

        extra = copy.deepcopy(doc)
        extra["jobs"][job_id]["strategy"]["matrix"][axis_name].append(
            "added-by-the-control"
        )
        gaps = matrix_axis_gaps(extra)
        check(
            f"a {axis_name} value no step names is reported",
            any(
                f"{job_id}: matrix axis {axis_name} value 'added-by-the-control' "
                f"has no step" in gap
                for gap in gaps
            ),
            f"a {axis_name} value with no step went unreported: {gaps}",
        )

        unknown = copy.deepcopy(doc)
        gated(unknown)[0]["if"] = f"matrix.{axis_name} == 'absent-from-the-matrix'"
        gaps = matrix_axis_gaps(unknown)
        check(
            f"a step gated on a {axis_name} value the matrix lacks is reported",
            any(
                f"names {axis_name} 'absent-from-the-matrix', which matrix axis" in gap
                for gap in gaps
            ),
            f"a step no leg runs went unreported: {gaps}",
        )

        dropped = copy.deepcopy(doc)
        dropped["jobs"][job_id]["strategy"]["matrix"][axis_name].remove(dropped_value)
        gaps = matrix_axis_gaps(dropped)
        check(
            f"deleting {dropped_value} from the {axis_name} list is reported",
            any(f"names {axis_name} {dropped_value!r}" in gap for gap in gaps),
            f"steps left without a leg went unreported: {gaps}",
        )

        for expander, entries in (
            ("include", [{"os": "ubuntu-latest", axis_name: "added-by-the-control"}]),
            ("exclude", [{axis_name: dropped_value}]),
        ):
            expanded = copy.deepcopy(doc)
            expanded["jobs"][job_id]["strategy"]["matrix"][expander] = entries
            gaps = matrix_axis_gaps(expanded)
            check(
                f"a matrix carrying {expander} over {axis_name} is reported",
                any(f"{job_id}: matrix carries {expander}," in gap for gap in gaps),
                f"a matrix whose legs {expander} changes went unreported: {gaps}",
            )

        undefined = copy.deepcopy(doc)
        gated(undefined)[0]["if"] = f"matrix.{axis_name}-misspelt == '{kept}'"
        gaps = matrix_axis_gaps(undefined)
        check(
            f"a step gated on an axis the {job_id} matrix does not define is reported",
            any(
                f"{job_id}: " in gap
                and f"matrix defines no axis {axis_name}-misspelt," in gap
                for gap in gaps
            ),
            f"a step gated on an undefined axis went unreported: {gaps}",
        )

        either = copy.deepcopy(doc)
        gated(either)[0]["if"] = (
            f"matrix.{axis_name} == '{kept}' || matrix.{axis_name} == '{dropped_value}'"
        )
        gaps = matrix_axis_gaps(either)
        check(
            f"a step gated on an `||` of two {axis_name} values is reported",
            any(
                f"which is not `matrix.{axis_name} == '<value>'`" in gap for gap in gaps
            ),
            f"a step whose condition names two values went unreported: {gaps}",
        )

    ungated = {"jobs": {"j": {"strategy": {"matrix": {"os": ["a", "b"]}}, "steps": []}}}
    check(
        "matrix_axis_gaps passes the live ci.yml and skips an axis no step gates on",
        not matrix_axis_gaps(doc) and not matrix_axis_gaps(ungated),
        f"gaps on ci.yml or on an ungated axis: {matrix_axis_gaps(doc)}",
    )

    def one_os_gate(runs_on: str) -> dict:
        return {
            "jobs": {
                "j": {
                    "runs-on": runs_on,
                    "strategy": {"matrix": {"os": ["ubuntu-latest", "macos-latest"]}},
                    "steps": [{"name": "brew", "if": "matrix.os == 'macos-latest'"}],
                }
            }
        }

    gaps = matrix_axis_gaps(one_os_gate("${{ matrix.os }}"))
    check(
        "a step gated to one value of an axis runs-on reads is not reported",
        not gaps,
        f"a one-value gate on the runner axis was reported: {gaps}",
    )
    gaps = matrix_axis_gaps(one_os_gate("ubuntu-latest"))
    check(
        "the same gate on an axis runs-on does not read reports the unnamed value",
        any("matrix axis os value 'ubuntu-latest' has no step" in gap for gap in gaps),
        f"an axis value no step names went unreported: {gaps}",
    )
    runner_typo = one_os_gate("${{ matrix.os }}")
    runner_typo["jobs"]["j"]["steps"][0]["if"] = "matrix.os == 'macos-lates'"
    gaps = matrix_axis_gaps(runner_typo)
    check(
        "a step gated on a value the runs-on axis lacks is still reported",
        any("names os 'macos-lates', which matrix axis" in gap for gap in gaps),
        f"a step no leg runs went unreported on the runner axis: {gaps}",
    )

    no_matrix = {"jobs": {"j": {"steps": [{"name": "s", "if": "matrix.leg == 'a'"}]}}}
    gaps = matrix_axis_gaps(no_matrix)
    check(
        "a step gated on a matrix axis in a job with no matrix is reported",
        any("j: 's' has" in gap and "defines no axis leg," in gap for gap in gaps),
        f"a step gated on an axis of an absent matrix went unreported: {gaps}",
    )
    include_axis = {
        "jobs": {
            "j": {
                "strategy": {"matrix": {"include": [{"leg": "a"}]}},
                "steps": [{"name": "s", "if": "matrix.leg == 'a'"}],
            }
        }
    }
    gaps = matrix_axis_gaps(include_axis)
    check(
        "a step gated on an axis an include entry defines is not reported as "
        "an undefined axis",
        not any("defines no axis" in gap for gap in gaps),
        f"an axis an include entry defines was reported undefined: {gaps}",
    )


def main() -> int:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    jobs = workflow["jobs"]
    # GitHub Actions runs a workflow file whose extension is `.yml` or `.yaml`,
    # and scripts/check-toolchain-wiring.sh enumerates both. This glob read
    # `.yml` alone, so a workflow written with the other spelling would have
    # escaped every assertion below while both gates printed OK. No workflow
    # here carries that spelling today, which is why widening the glob changes
    # no result.
    documents = [
        (path, yaml.safe_load(path.read_text()))
        for path in sorted(
            set((REPO / ".github/workflows").glob("*.yml"))
            | set((REPO / ".github/workflows").glob("*.yaml"))
        )
    ]

    print("timeout — every job in every workflow bounds its own runtime")
    for path, doc in documents:
        ceiling = (
            MAX_TIMEOUT_MINUTES
            if path == WORKFLOW
            else MAX_TIMEOUT_MINUTES_OTHER_WORKFLOWS
        )
        dispatch_inputs = dispatch_input_specs(doc)
        for job_id, job in sorted(doc["jobs"].items()):
            if "uses" in job:
                # A reusable-workflow call takes no timeout-minutes; a called
                # workflow's own jobs carry that budget.
                continue
            budget = job.get("timeout-minutes")
            label = f"{path.name}:{job_id}"
            if isinstance(budget, str) and "${{" in budget:
                check_selected_budget(label, budget, dispatch_inputs, ceiling)
            else:
                check(
                    f"{label} sets timeout-minutes",
                    isinstance(budget, int) and 0 < budget <= ceiling,
                    f"got {budget!r}, want an integer in 1..{ceiling}",
                )
            check_scaling_input_sizes_budget(label, job, budget)

    print("action-ref — every rust-toolchain `uses:` names a ref that resolves")
    for path, doc in documents:
        check_toolchain_refs(path, doc)
    requested = {
        name: pinned
        for name, pinned in (
            (path.name, collect_pinned_nightlies(doc)) for path, doc in documents
        )
        if pinned
    }
    check(
        "every workflow pinning a nightly by date pins one date",
        len({date for pinned in requested.values() for date in pinned}) <= 1,
        f"{requested} — a fuzz build check under one nightly says nothing about a "
        f"fuzz run under another",
    )

    print("doc-flag — the required check's rustdoc reads every other rustdoc's surface")
    check_required_rustdoc_surface(documents)
    check_rustdoc_surface_detects_a_dropped_flag(documents)

    print("doc-command — a documented rustdoc reports what the merge waits on")
    check_documented_rustdoc_reproduces_the_required_job(documents)
    check_documented_rustdoc_detects_a_feature_drift(documents)
    check_rustdoc_enumerations_sit_in_a_shell_block()
    check_enumeration_scan_reads_the_text_it_is_given()

    print("win-shell — every `run:` step a Windows runner can execute names a shell")
    for path, doc in documents:
        check_windows_shell(path, doc)

    print(
        "matrix-axis — each matrix axis a step gates on and its steps' `if:` "
        "values agree"
    )
    for path, doc in documents:
        check_matrix_axes(path, doc)
    check_matrix_axis_controls(workflow)

    print(
        "empty-input — a job publishing a -signed artifact rejects an empty "
        "input set first"
    )
    check_signing_guard(documents)

    print(
        "downloaded-module — a PyO3 consumer's unguarded steps before pytest contain "
        "each PyO3 assertion fragment"
    )
    pyo3_artifacts = uploaded_artifact_names(workflow, PYO3_UPLOAD_FILENAME)
    check_a_bridge_upload_reaches_the_gate(
        workflow, PYO3_UPLOAD_FILENAME, pyo3_artifacts
    )
    check_pyo3_consumer_assertion_fragments(workflow, pyo3_artifacts)
    check_artifact_names_reach_a_consumer(
        workflow, pyo3_artifacts, PYO3_UPLOAD_FILENAME
    )
    check_a_new_producer_reaches_the_pyo3_gate(workflow)
    # Every consumer of every name, read off ci.yml rather than written here: a control
    # that mutates one hardcoded job proves the gate goes red for that job's artifact
    # name alone, which left `pyo3-module-macos` — and so job bridge-parity-swift, its
    # one consumer — tied to nothing this file executes.
    for pyo3_artifact in pyo3_artifacts:
        check_artifact_name_control(workflow, pyo3_artifacts, pyo3_artifact)
        for pyo3_job in artifact_consumers(workflow, pyo3_artifact):
            for pyo3_fragment in PYO3_ASSERTION_FRAGMENTS:
                check_pyo3_assertion_control(
                    workflow, pyo3_artifacts, pyo3_job, pyo3_fragment
                )
            check_assertion_step_guard_controls(
                workflow, pyo3_artifacts, pyo3_job, "PyO3"
            )

    print(
        "downloaded-addon — a NAPI consumer's unguarded steps before its tests "
        "contain each NAPI assertion fragment"
    )
    napi_artifacts = uploaded_artifact_names(workflow, NAPI_UPLOAD_FILENAME)
    check_a_bridge_upload_reaches_the_gate(
        workflow, NAPI_UPLOAD_FILENAME, napi_artifacts
    )
    check_napi_consumer_assertion_fragments(workflow, napi_artifacts)
    check_artifact_names_reach_a_consumer(
        workflow, napi_artifacts, NAPI_UPLOAD_FILENAME
    )
    check_a_new_producer_reaches_the_napi_gate(workflow)
    for napi_artifact in napi_artifacts:
        check_artifact_name_control(workflow, napi_artifacts, napi_artifact)
        for napi_job in artifact_consumers(workflow, napi_artifact):
            for napi_fragment in NAPI_ASSERTION_FRAGMENTS:
                check_napi_assertion_control(
                    workflow, napi_artifacts, napi_job, napi_fragment
                )
            check_assertion_step_guard_controls(
                workflow, napi_artifacts, napi_job, "NAPI"
            )

    print("retention — a downloaded artifact outlives the re-run window")
    check_shared_uploads_outlive_the_rerun_window(workflow)

    print("profile-env — CARGO_PROFILE_* is set for the whole workflow or not at all")
    check_profile_env_is_workflow_level(workflow, "ci.yml")
    check_profile_env_is_workflow_level(
        yaml.safe_load(COMPILE_TIMINGS.read_text()), "compile-timings.yml"
    )

    print(
        "artifact-key — a bridge producer reuses an artifact only for unchanged inputs"
    )
    check_artifact_cache_keys(workflow)

    print(
        "artifact-digest — an artifact-inputs step fails when a hashed input is "
        "missing and hashes the workflow env"
    )
    check_artifact_input_digests_fail_closed(workflow)

    print(
        "producer-outputs — a producer uploading several paths fails on a missing "
        "output"
    )
    check_multi_path_producers_are_listed(workflow)
    for job_id, artifact, marker_name, tracked, rejects_empty in MULTI_PATH_PRODUCERS:
        check_multi_path_outputs_are_verified(
            workflow, job_id, artifact, marker_name, tracked, rejects_empty
        )

    print("package-writers — no `packages: write`; the cache token stays in docker-cache")
    check_package_write_and_cache_token(workflow)

    print("needs-condition — a job's dependencies run wherever the job does")
    check_dependency_conditions(workflow)
    check_dependency_conditions_detect_a_narrowed_producer(workflow)
    check_dependency_conditions_detect_a_conditionless_consumer(workflow)
    check_dependency_conditions_read_a_status_guarded_consumer(workflow)

    print("push-writers — a push to `main` runs every cache writer, and only a push skips")
    check_condition_grammar()
    check_aggregate_grammar()
    check_push_runs_every_cache_writer(workflow)
    check_push_writer_mutants(workflow)

    print("coverage — every job reaches a required status check")
    defined = set(jobs) - {"ci"}
    declared = set(jobs["ci"]["needs"])
    check(
        "`ci` depends on every job a workflow defines",
        defined == declared,
        f"missing {sorted(defined - declared)}, unknown {sorted(declared - defined)}",
    )
    check_scenario_table_covers(jobs)
    check(
        "every scenario supplies whichever filter outputs `changes` publishes",
        all(
            set(scenario.filters) == set(jobs["changes"]["outputs"])
            for scenario in SCENARIOS.values()
        ),
        f"`changes` publishes {sorted(jobs['changes']['outputs'])}, scenarios supply "
        f"{sorted(RUST_ONLY)}",
    )

    print("path-closure — a path filter covers every crate its jobs compile")
    check_closure_reads_workspace_inheritance()
    check_resolution_manifests_reach_the_workspace()
    check_path_dep_closures(jobs)

    print(
        "workspace-scope — a filter gating a `--workspace` compile covers every member"
    )
    # Every workflow, not ci.yml alone: docs.yml's `rust-docs` runs
    # `cargo doc --workspace` under a `docs` filter of its own, and that filter
    # named eleven of the twenty-six members the root manifest lists.
    for path, doc in documents:
        check_workspace_scoped_filters(path, doc)
    check_workspace_scope_detects_a_narrowed_filter(documents)

    print("private-items — every `cargo doc` reads the links private modules write")
    check_rustdoc_lint_reaches_every_member()
    check_rustdoc_lint_readers_detect_a_lowered_level()
    check_rustdoc_documents_private_items(documents)
    check_private_items_detects_a_dropped_flag(documents)
    check_workspace_and_rustdoc_readers(documents)

    print("no-cargo-gradle — kotlin-lint's cargo-free Gradle calls skip the daemon")
    check_no_cargo_gradle_calls_skip_the_daemon(jobs)

    print("merge-queue — a workflow that skips to a success status runs in the queue")
    check_merge_queue_triggers(documents)

    print("step-filter — a filter output gates a job, never a step")
    check_filter_outputs_gate_jobs(jobs)

    print("filter-source — a `changes` output reads a filter key that exists")
    # Every workflow, not ci.yml alone: docs.yml declares a `dorny/paths-filter`
    # step of its own, and its `docs` output reads two keys off that step.
    for path, doc in documents:
        check_filter_keys_agree(path, doc)
    check_filter_key_agreement_detects_a_rename(documents)

    print(
        "shipped-config — a production-config lane runs its bridge's fail-closed "
        "assertions"
    )
    check_shipped_assertion_readers()
    check_testing_unification_readers()
    check_shipped_build_assertions_run(jobs)
    check_shipped_assertion_tripwires(jobs)

    print(
        "zero-test — a filtered test selection that matches nothing must exit non-zero"
    )
    # Every workflow, not ci.yml alone: release.yml ran
    # `cargo test --release -p scp-testing -- conformance`, whose harness filter
    # this check read past a `--` to find, and that job gates a release.
    for path, doc in documents:
        for job_id, job in sorted(doc["jobs"].items()):
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                for line in logical_lines(step.get("run") or ""):
                    if line.startswith("cargo test "):
                        filters = positional_filters(line)
                        check(
                            f"{path.name}:{job_id}: {line[:58]}",
                            not filters,
                            f"test-name filter {filters} — `cargo test` exits 0 when its filter "
                            f"selects nothing; use `cargo nextest run --no-tests=fail -E 'test(name)'`",
                        )
                    if "cargo nextest run" in line and (
                        " -E " in line or positional_filters(line)
                    ):
                        check(
                            f"{path.name}:{job_id}: {line[:58]}",
                            "--no-tests=fail" in line,
                            "a filtered nextest selection must set --no-tests=fail, which exits 4 "
                            "when a selection is empty",
                        )

    rust_pr = SCENARIOS["rust-only, pull_request"]
    docs_pr = SCENARIOS["docs-only, pull_request"]
    docs_push = SCENARIOS["docs-only, push"]
    rust_merge = SCENARIOS["rust-only, merge_group"]

    print("rust-fanout — a Rust-only change runs binding test jobs")
    # SCENARIOS says each job below runs on a Rust-only change, so reporting it
    # `skipped` must reach an aggregate as one named failure. Narrowing that
    # job's `if:` in ci.yml back to its own binding directory makes an aggregate
    # accept that skip, which drops this assertion's exit code to 0.
    for job_id in (
        "python-test",
        "typescript-check",
        "kotlin-test",
        "swift-build-test",
    ):
        needs = build_needs(jobs, rust_pr)
        needs[job_id]["result"] = "skipped"
        code, out = run_aggregate(needs, rust_pr.event)
        check(
            f"{job_id} skipped on a Rust-only change -> exit 1 naming it",
            code == 1 and job_id in out,
            out,
        )

    python_pr = SCENARIOS["python-only, pull_request"]

    print("python-fanout — a change under bindings/python/ runs the wheel-features build")
    # rust-build-pyo3-production builds scp-ffi with bindings/python/pyproject.toml's
    # [tool.maturin] features, so an edit to that file alone must run it.
    # SCENARIOS says it runs on a python-only change, so reporting it `skipped`
    # must reach an aggregate as one named failure. Dropping
    # `|| needs.changes.outputs.python == 'true'` from that job's `if:` makes an
    # aggregate accept that skip, which drops this assertion's exit code to 0.
    needs = build_needs(jobs, python_pr)
    code, out = run_aggregate(needs, python_pr.event)
    check("python-only change, every selected job passed -> exit 0", code == 0, out)
    for job_id in ("rust-build-pyo3-production", "python-test"):
        needs = build_needs(jobs, python_pr)
        needs[job_id]["result"] = "skipped"
        code, out = run_aggregate(needs, python_pr.event)
        check(
            f"{job_id} skipped on a python-only change -> exit 1 naming it",
            code == 1 and job_id in out,
            out,
        )

    print("skip — an aggregate separates a skipped dependency from a passing one")

    needs = build_needs(jobs, rust_pr)
    code, out = run_aggregate(needs, rust_pr.event)
    check("Rust-only change, every selected job passed -> exit 0", code == 0, out)

    needs = build_needs(jobs, docs_pr)
    code, out = run_aggregate(needs, docs_pr.event)
    check("docs-only change, filtered jobs skipped -> exit 0", code == 0, out)

    needs = build_needs(jobs, docs_pr)
    needs["error-codes"]["result"] = "skipped"
    code, out = run_aggregate(needs, docs_pr.event)
    check("a job every pull request selects skipped -> exit 1", code == 1, out)

    needs = build_needs(jobs, docs_pr)
    needs["shipped-feature-graph"]["result"] = "failure"
    code, out = run_aggregate(needs, docs_pr.event)
    check("a job failed -> exit 1", code == 1, out)

    needs = build_needs(jobs, docs_pr)
    needs["rust-test"]["result"] = "cancelled"
    code, out = run_aggregate(needs, docs_pr.event)
    check("a job was cancelled -> exit 1", code == 1, out)

    # A job whose condition did not select it still ran, and still failed. Both
    # assertions below name a job SCENARIOS says a docs-only change skips, so
    # only an aggregate's `failure`/`cancelled` branch can reject them — the
    # branch judging a selected job cannot.
    needs = build_needs(jobs, docs_pr)
    needs["python-test"]["result"] = "failure"
    code, out = run_aggregate(needs, docs_pr.event)
    check("an unselected job failed -> exit 1", code == 1 and "python-test" in out, out)

    needs = build_needs(jobs, docs_pr)
    needs["python-test"]["result"] = "cancelled"
    code, out = run_aggregate(needs, docs_pr.event)
    check(
        "an unselected job was cancelled -> exit 1",
        code == 1 and "python-test" in out,
        out,
    )

    needs = build_needs(jobs, rust_pr)
    needs["changes"] = {"result": "failure", "outputs": {}}
    for job_id in ("rust-clippy", "rust-fmt", "python-test", "typescript-check"):
        needs[job_id]["result"] = "skipped"
    code, out = run_aggregate(needs, rust_pr.event)
    check("a filter job failed and its dependants skipped -> exit 1", code == 1, out)

    needs = build_needs(jobs, docs_push)
    code, out = run_aggregate(needs, docs_push.event)
    check("push event, a pull-request-only job skipped -> exit 0", code == 0, out)

    print("push-skips")
    # SCENARIOS states which jobs a push runs, so an
    # aggregate given that skipped set must pass, every writer reported skipped
    # must fail it, and a push-only skip reported on a pull_request or merge_group
    # run must fail it. Each failing case names the job, so a verdict reached for
    # another reason does not satisfy it.
    rust_push = SCENARIOS["rust-only, push"]
    python_push = SCENARIOS["python-only, push"]
    for scenario in (docs_push, rust_push, python_push):
        code, out = run_aggregate(build_needs(jobs, scenario), scenario.event)
        check(f"{scenario.name}, every non-writer skipped -> exit 0", code == 0, out)
    for scenario in (docs_push, rust_push):
        for job_id in sorted(cache_writers(workflow)):
            if not scenario.runs.get(job_id, True):
                continue
            needs = build_needs(jobs, scenario)
            needs[job_id]["result"] = "skipped"
            code, out = run_aggregate(needs, scenario.event)
            check(
                f"{scenario.name}, writer {job_id} skipped -> exit 1 naming it",
                code == 1 and job_id in out,
                f"exit {code}: {out}",
            )
    for scenario in (s for s in SCENARIOS.values() if s.event != "push"):
        for job_id in NOT_ON_PUSH_JOBS + NOT_ON_PUSH_FILTER_JOBS:
            if not scenario.runs[job_id]:
                continue
            needs = build_needs(jobs, scenario)
            needs[job_id]["result"] = "skipped"
            code, out = run_aggregate(needs, scenario.event)
            check(
                f"{scenario.name}, push-skipped {job_id} skipped -> exit 1 naming it",
                code == 1 and job_id in out,
                f"exit {code}: {out}",
            )

    # merge_group names whichever event a merge queue runs, so it gates every
    # merge. cross-layer skips there because it diffs against a pull request's
    # base branch, and no other job may.
    needs = build_needs(jobs, rust_merge)
    code, out = run_aggregate(needs, rust_merge.event)
    check("merge_group event, a Rust change -> exit 0", code == 0, out)

    needs = build_needs(jobs, rust_merge)
    needs["rust-test"]["result"] = "skipped"
    code, out = run_aggregate(needs, rust_merge.event)
    check("merge_group event, a workspace test job skipped -> exit 1", code == 1, out)

    # A producer that skips takes every consumer in its `needs` list down with it.
    # The comments on the producer jobs in ci.yml and the needs-condition check above
    # rest on this aggregate failing that run, because it evaluates the consumer's
    # own `if:`, not its dependency's.
    needs = build_needs(jobs, rust_pr)
    needs["napi-addon"]["result"] = "skipped"
    needs["bridge-parity"]["result"] = "skipped"
    code, out = run_aggregate(needs, rust_pr.event)
    check(
        "a producer skip that skips a selected consumer -> exit 1",
        code == 1 and "bridge-parity: skipped" in out,
        f"exit {code}: {out}",
    )

    needs = build_needs(jobs, docs_pr)
    needs["cross-layer"]["result"] = "skipped"
    code, out = run_aggregate(needs, docs_pr.event)
    check(
        "pull_request event, a pull-request-only job skipped -> exit 1",
        code == 1,
        out,
    )

    needs = build_needs(jobs, docs_pr)
    for entry in needs.values():
        entry["result"] = "skipped"
    needs["changes"]["outputs"] = dict(docs_pr.filters)
    code, out = run_aggregate(needs, docs_pr.event)
    check("draft pull request, every job skipped -> exit 0", code == 0, out)

    needs = build_needs(jobs, docs_pr)
    needs.pop("wasm-test")
    code, out = run_aggregate(needs, docs_pr.event)
    check("a job missing from a dependency list -> exit 1", code == 1, out)

    # Job cross-layer carries `if: github.event_name == 'pull_request'`, so an
    # aggregate that read an absent GITHUB_EVENT_NAME as "" would judge that
    # condition false and accept a skipped cross-layer on a pull request. This
    # scenario reports exactly that skip, so exit 0 here would be a gate reading
    # a coverage gap as a pass.
    needs = build_needs(jobs, docs_pr)
    needs["cross-layer"]["result"] = "skipped"
    code, out = run_aggregate(needs, None)
    check(
        "GITHUB_EVENT_NAME absent, an event-gated job skipped -> exit 3",
        code == 3 and "GITHUB_EVENT_NAME" in out,
        f"exit {code}: {out}",
    )

    print("filter-key — an `if:` naming an unpublished filter output stops a gate")
    referenced = {
        match.group(1)
        for job in jobs.values()
        for match in FILTER_REFERENCE.finditer(str(job.get("if") or ""))
    }
    check(
        "every `if:` names a filter output `changes` declares",
        referenced <= set(jobs["changes"]["outputs"]),
        f"undeclared {sorted(referenced - set(jobs['changes']['outputs']))}",
    )
    # A renamed or misspelled filter leaves `changes` publishing every key but
    # one. Reading that absent key as "" would compare unequal to 'true', hold
    # every job whose condition names it at `skipped`, and report exit 0.
    for key in sorted(referenced & set(rust_pr.filters)):
        needs = build_needs(jobs, rust_pr)
        needs["changes"]["outputs"] = {
            name: value for name, value in rust_pr.filters.items() if name != key
        }
        code, out = run_aggregate(needs, rust_pr.event)
        check(
            f"`changes` published no {key!r} output -> exit 2",
            code == 2 and key in out,
            f"exit {code}: {out}",
        )

    print(f"\n{checks - len(failures)} of {checks} assertions passed")
    if failures:
        print("failed: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
