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
               on, and crates/scp-ffi/common/Cargo.toml carries the same edge
               in its `[dev-dependencies]`. A workspace build reads both, so
               the pairing this entry records stays rejected.
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
               itself when the extension is absent, and the `scp` fixture skips
               every test that requests it when `SCP(storage=...)` raises
               SCP-VALID-7081 (no extension file is present), so a PyO3 consumer
               whose downloaded module never reached bindings/python/scp_sdk
               leaves pytest exiting 0 over zero executed assertions. The check
               requires each fragment in PYO3_ASSERTION_FRAGMENTS in the `run:`
               text of an unguarded step before `pytest tests`.
  downloaded-addon
               Every real-NAPI test file under bindings/typescript/tests resolves
               to `describe.skip` or `test.skip` when `loadNativeAddon()` throws
               SCP-VALID-7081 (the addon package does not resolve), so a NAPI
               consumer whose downloaded addon was wired anywhere but the package
               directory `require()` resolves leaves `bun test` exiting 0 over
               zero executed NAPI assertions. The check
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
               uniffi-cdylib-linux upload lists the UniFFI cdylib and the
               Kotlin bindings, and a build that wrote one of them satisfies the
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
  cache-key    Every workflow step that restores the cargo cache uses
               ./.github/actions/rust-cache, never Swatinem/rust-cache directly.
               rust-cache keys on member manifests, Cargo.lock,
               `.cargo/config.toml`, `rust-toolchain.toml`, `rustc -vV` and the
               CARGO*/RUST* variables its step sees, but not on the virtual root
               Cargo.toml, which holds every `[profile.*]` table. After
               `[profile.dev.package."*"] opt-level = 1` merged, every job
               restored the old entry with a full key match, recompiled 300 to 660
               dependencies and saved nothing, and merge_group run 41477746543
               took 13.0 minutes against 6.8 before. The check requires the
               wrapper to put manifest-digest.sh's digest into `prefix-key`, runs
               that script on edits to the root Cargo.toml (a profile, a
               dependency's features, a patch rev and a member change the digest;
               a version string, a comment and a lint level do not, so a version
               bump keeps rust-cache's partial restore), requires every
               artifact-changing variable (RUSTFLAGS, RUSTDOCFLAGS,
               CARGO_INCREMENTAL, CARGO_PROFILE_*, CARGO_BUILD_* and the rest of
               ARTIFACT_ENV) in a cache job to sit in the job's or workflow's
               `env:`, never in a step's `env:` or a `$GITHUB_ENV` write, rejects
               a cargo `--config` or `-Z` argument in a cache job, which no key
               hashes, and rejects a `.cargo/config` without `.toml`, which cargo
               reads and rust-cache does not hash. Controls: a direct Swatinem
               step, the wrapper without its prefix-key, digest step or
               workspaces, a digest that skips `[profile.*]`, a root without
               Cargo.toml, a step-level RUSTFLAGS, `$GITHUB_ENV` writes from a run
               and from a local action, two `--config` forms, a `-Z` flag and a
               planted `.cargo/config`; a job-level RUSTFLAGS and a `--config` on
               a line that runs no cargo must pass.
  offline-cargo
               Every job in `.github/workflows/` that runs cargo, maturin or
               wasm-pack runs `./.github/actions/cargo-fetch` exactly once,
               after every toolchain and rust-cache step and before every other
               cargo command, and no step sets CARGO_NET_OFFLINE by hand.
               Cargo otherwise downloads the index and the crate sources inside
               whichever build, test or lint command first needs them and gives
               up after three retries; in run 38171293381 a macOS rust-test leg
               could not resolve `index.crates.io` and failed before compiling
               anything. The fetch step retries for minutes and then writes
               CARGO_NET_OFFLINE=true to `$GITHUB_ENV`, so every later cargo
               command, including those scripts start, reads only the fetched
               copy. A fetch placed before rust-cache would put that variable
               into rust-cache's key; a cargo command before the fetch, or a
               `cargo install` after it, reaches the network; a fetch guarded by
               an `if:` that a later cargo step lacks leaves that step without
               the crates. Job publish-crates in release.yml is the one
               exemption, because `cargo publish` uploads to crates.io. A job
               that builds an image with docker/build-push-action runs cargo
               inside the Dockerfile it names, where no fetch step reaches, so
               that Dockerfile holds itself to the same rule: it copies fetch.sh
               in and runs it once per stage chain, before every cargo command
               except `--version`, `cargo chef prepare` and
               `cargo chef cook --no-build` (which write manifests and compile
               nothing), and every later cargo command runs under
               `ENV CARGO_NET_OFFLINE=true` or with `--offline` or `--frozen`.
               The check also reads fetch.sh for its `$GITHUB_ENV` write, and
               runs controls that each break the rule once (fetch removed from
               rust-clippy, python-wheels, fuzz-nightly and the CodeQL analyze
               job, whose Rust extractor runs cargo, a cargo step moved before it, fetch before rust-cache, two fetches,
               CARGO_NET_OFFLINE at workflow, job and step level, a step turning
               cargo back online, a `cargo install` after the fetch, a guarded
               fetch, a raw cargo job, a stale exemption, and in the Dockerfile
               the fetch removed, its COPY removed, the offline ENV and flags
               removed, the ENV moved before the fetch, and a missing file).
               LIMIT: a job that runs cargo only inside a script, with no
               toolchain step, is not detected; in ci.yml
               `RUSTUP_AUTO_INSTALL: "0"` fails such a job before cargo starts.
  pinned-python
               pyo3's build script runs the interpreter PYO3_PYTHON names, or
               the runner image's default `python3`, and fails when that
               interpreter is newer than the newest version the locked pyo3
               supports. When ubuntu-latest moved its default to 3.14, job
               rust-docs in docs.yml, which ran `cargo doc --workspace` with no
               pinned Python, failed on every pull request. Every step that
               compiles pyo3 must come after an unconditional Python setup
               step (.github/actions/toolcache-setup with `tool: python`, or
               `actions/setup-python`) pinned to 3.12 and run with
               PYO3_PYTHON naming that interpreter: the step's `python-path`
               output, or `python3.12` off Windows. A step compiles pyo3 when
               its `run:` text runs cargo with a compiling subcommand that
               selects a package depending on pyo3 (read from every member's
               Cargo.toml): `-p` naming one or a word only the runner knows,
               `--workspace` excluding none, or no package flag in a directory
               whose nearest manifest builds one, which at the root means a
               default member; or `maturin build|develop` without `-i`; or
               CodeQL on a job analysing rust,
               whose extractor runs build scripts. Controls remove the pin, the
               PYO3_PYTHON write, and the workflow-level key, pin 3.14, guard
               the pin with `if:`, move the write after the build, name
               `python3.12` on a Windows leg, and add unpinned fixture jobs.
               LIMIT: cargo run inside a repository script a step starts is
               not read.
  matrix-axis
               Job rust-test-optional-features runs its commands on three
               legs, one per value of a matrix `group` axis, and jobs
               rust-clippy and rust-test-macos run on the values of a `leg`
               axis that names one list for push and another for every other
               event. GitHub runs a leg whose value no step names and reports
               it green over none of the gated commands, and it skips a step
               whose value the axis lacks on every leg, so deleting
               `platform-testing` from the `group` axis would have dropped
               eight commands from every run while `ci` passed. A step gated
               with `if: matrix.<axis> == '<value>'`, or an `||` of such
               comparisons, must name a value each event's list holds. The
               check reports a step gated that way on an axis the job's matrix
               does not define.
  leg-commands
               Jobs rust-test-macos, rust-clippy and
               rust-test-optional-features split their commands across legs
               (the last on its `group` axis), and rust-doc's two commands split across rust-doc
               and rust-doctest. A step moved to the wrong leg, a leg value
               dropped, or a command deleted while splitting runs that command
               on no leg, and every leg still passes. LEG_COMMANDS pins the
               commands each group ran before the split, and the check fails
               unless each event's legs run every pinned command exactly once.
  linted-features
               Code behind an off-by-default scp-transport or scp-node feature
               that no `cargo clippy` command enables carries lint errors onto
               main unseen. The check reports each `[features]` key of either
               crate's Cargo.toml that no clippy command in ci.yml enables,
               directly or through another feature of that crate. A feature
               that a `[[bin]]` or `[[test]]` names in `required-features`
               counts only when every such target is selected by a clippy
               command that enables all of the target's required features, so
               a `--lib` lane does not lint scp-node's `node-bin`.
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
               matrix that drops on push the leg its `save-if` names, a push
               leg no other event runs unless every step it runs is one an
               other event's leg runs, and any job whose `if:` answers a
               scenario differently from SCENARIOS.
  macos-bridges
               A pull request runs the four macOS bridge jobs (xcframework,
               pyo3-module-macos, swift-build-test and bridge-parity-swift)
               when the `swift` output is true, and all but swift-build-test
               when the `python` output is true, and a merge_group run also
               runs them on `rust`. A
               condition that reads `rust` on pull requests too puts all four
               back on every Rust pull request; one that drops `rust` from the
               merge queue lands a Rust change no macOS bridge job ran; and a
               filter that drops the uniffi or common directory skips them on a
               pull request that changes a bridge they test. The `ci` aggregate
               evaluates each job's own `if:`, so it passes all three. The check
               computes each path group's filter outputs from the `changes` job
               and reports every event whose answer differs from
               MACOS_BRIDGE_PATH_CASES.
  prose-route  A pull request that changes only prose skips every job the
               `code` output guards. That output is a positive list of paths,
               so a file added outside it and outside prose would change with
               those jobs skipped and `ci` green. The check lists every path
               `git ls-files` reports and fails on each one the `code` output
               does not select and that is not under `.docs/` or `.claude/`, a
               root-level `*.md`, or a `*.md` under `docs/guides/`. It also
               fails on each tracked path rust-test reads, found by scanning
               `crates/**/*.rs` for include and workspace_root literals, that
               the `rust` output does not select and no always-on step mirrors.
  verified-download
               sdkmanager unpacks the archive it downloads with no check that
               reaches the job: job 118835960956 died on `Error on ZipFile
               unknown archive` unpacking the NDK, and job 125594057792 printed
               `Error reading Zip content from a SeekableByteChannel` for the
               emulator package that reactivecircus/android-emulator-runner
               installs on every run, then ran no test. Both reruns passed. The
               check reads every workflow, local action and tracked Dockerfile
               against a closed structure. A remote action passes only when
               PERMITTED_ACTIONS lists it with a verdict, named in any case, at
               a 40-hex commit SHA with its tag in a comment, under the
               conditions its verdict names: setup-python, setup-node and
               setup-java only between toolcache-setup's guard.py steps,
               taiki-e with `fallback: none`, setup-buildx with a buildkit
               image named by digest, codeql init with `tools:` from an earlier
               pinned-tool step, setup-gradle with no `gradle-version:`. A local
               action must be composite. A `run:` step, its env values and a
               github-script fail on any word in FETCH_WORDS (curl, wget,
               sdkmanager, gh release download, Invoke-WebRequest, urllib,
               podman, skopeo and the rest), on pip without --require-hashes,
               on bun install without --frozen-lockfile, on cargo install
               without --locked and --path, on a docker subcommand outside
               DOCKER_SUBCOMMANDS, and on a docker run, create or pull whose
               image (the first word after the options) has no digest. Job
               containers, services, `docker://` steps and Dockerfile FROM,
               COPY --from and syntax lines need a digest, an ADD of a URL needs
               --checksum, and a wasm-pack install needs the wasm-bindgen
               Cargo.lock names and a pinned wasm-opt. Every job that runs
               gradlew must validate the wrapper jar first, every wrapper it
               runs must pin distributionSha256Sum, and every build it runs
               must carry gradle/verification-metadata.xml with verify-metadata
               on and no `<trust>` entry. It also feeds the shared
               verified_download module a truncated archive, a body cut short,
               a stalled server, a server that trickles bytes, an oversized body
               and a wrong Content-Length, and fails unless each is retried a
               bounded number of times and then fails naming the artifact. It
               runs android-sdk's install.py main over a planted SDK root, fails a
               job in which a step before android-sdk writes under the SDK root,
               and runs guard.py against a planted tool cache.
  group-partition
               CI runs `--group docs` on every pull request and `--group rest`
               only under the `code` output, so a check missing from GROUPS
               would run in no job and a check in both would run twice. The
               assertion fails unless the two groups name every check in
               CHECKS exactly once.

Assertions over an aggregate's verdict read which jobs a scenario selects out
of SCENARIOS below, never out of the aggregate itself. Six of them once built
that expectation by calling `evaluate` in scripts/ci-aggregate-result.py, the
same function whose verdict they then judged, so each one agreed with that
function however it behaved.

Run: python3 scripts/tests/ci-gate/ci_gate_selftest.py [--group docs|rest|all]
"""

from __future__ import annotations

import argparse
import copy
import functools
import itertools
import json
import os
import posixpath
import re
import shlex
import subprocess
import sys
import tempfile
import time
import tomllib
from collections.abc import Callable
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
    ("ci.yml", "rust-deny"),
    ("ci.yml", "rust-doc"),
    ("ci.yml", "rust-doctest"),
    ("ci.yml", "rust-test"),
    ("docs.yml", "rust-docs"),
}
RUSTDOC_JOBS = {
    ("cache-warm.yml", "workspace-check"),
    ("ci.yml", "rust-doc"),
    ("docs.yml", "rust-docs"),
}

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
# crates/scp-ffi/common/Cargo.toml and crates/scp-transport/Cargo.toml — and
# one cargo invocation resolves one feature set per package, so a build reading
# any one of them compiles out every
# `#[cfg(not(feature = "testing"))]` assertion scp-identity carries. An earlier revision of
# this table paired scp-identity with job rust-test under a comment claiming
# nothing enables `scp-identity/testing`; command_unifies_testing below now
# reads that edge out of the manifests a command's build includes, so pairing
# a package with such a lane fails check_shipped_build_assertions_run instead
# of passing on the command's text.
NON_BRIDGE_SHIPPED_ASSERTION_LANES = {
    "scp-identity": "fail-closed-pre-rotation",
    "scp-node": "fail-closed-pre-rotation",
    "scp-transport": "rust-test-optional-features",
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
# A full commit SHA, the only ref check `verified-download` admits on a remote action.
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")

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
    "code": "true",
    "rust-prose": "false",
}
DOCS_ONLY = dict.fromkeys(RUST_ONLY, "false")

# Jobs the `code` output selects: true for every change outside prose, so every
# scenario below but docs-only runs them. fix-round-check-selftest is in
# PULL_REQUEST_ONLY_FILTER_JOBS; the rest are in NOT_ON_PUSH_FILTER_JOBS.
CODE_JOBS = (
    "ci-workflow-selftest",
    "examples-typecheck",
    "fail-closed-pre-rotation",
    "fix-round-check-selftest",
    "protocol-deps",
    "shipped-feature-graph",
    "toolchain-wiring-cases",
    "vendored-openssl-scope",
    "wasm-protocol",
    "wasm-test",
    "wiping-allocator",
)

# Jobs whose `if:` reads `github.event_name` rather than a `changes` filter
# output, so a filter scenario decides nothing about them and each scenario
# below states them for itself. It carries
# `if: github.event_name == 'pull_request'`, and check-cross-layer.sh is why:
# it reads a declared exemption out of a pull request's body, which a
# merge_group event does not publish.
EVENT_ONLY_JOBS = ("cross-layer",)

# Jobs a `changes` filter output selects whose `if:` also reads
# `github.event_name == 'pull_request' && …`. Job fix-round-check-selftest runs
# check-cross-layer.sh as one of the gates scripts/fix-round-check.sh names, so
# it carries cross-layer's event condition, and the `code` output skips it on a
# prose-only change.
PULL_REQUEST_ONLY_FILTER_JOBS = ("fix-round-check-selftest",)

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
    "ci-workflow-selftest-docs",
    "construction-pattern",
    "deleted-primitives",
    "doc-citations",
    "doc-includes",
    "error-codes",
    "fallback-registry",
    "handle-affinity",
    "handler-no-panic",
    "no-mutable-globals-kotlin",
    "no-mutable-globals-python",
    "no-mutable-globals-rust",
    "no-mutable-globals-ts",
    "no-panic-abort",
    "noop-spelling",
    "pyi-generated",
    "protocol-sync",
    "saga-gating-granularity",
    "sdk-coverage",
    "test-vectors",
    "toolchain-wiring",
)

# Jobs a `changes` filter output selects whose `if:` also reads
# `github.event_name != 'push' && …`. The filter jobs absent from this list (the five
# bridge producers and docker-image-cache) write a cache on a push to `main` and run
# there whenever their filters select them; .github/workflows/cache-warm.yml writes
# every cargo group and the Gradle home.
NOT_ON_PUSH_FILTER_JOBS = (
    "bridge-parity",
    "bridge-parity-kotlin",
    "bridge-parity-swift",
    "ci-workflow-selftest",
    "docker-image",
    "examples-typecheck",
    "fail-closed-pre-rotation",
    "fuzz-build",
    "kotlin-android-instrumented",
    "kotlin-lint",
    "kotlin-test",
    "personal-relay-template",
    "protocol-deps",
    "python-lint",
    "python-test",
    "python-wheel-build",
    "rust-build-pyo3-production",
    "rust-build-uniffi-production",
    "rust-clippy",
    "rust-deny",
    "rust-deny-fuzz",
    "rust-doc",
    "rust-doctest",
    "rust-fmt",
    "rust-test",
    "rust-test-macos",
    "rust-test-napi-production",
    "rust-test-optional-features",
    "rust-test-prose",
    "scaffold-typescript-web-check",
    "shipped-feature-graph",
    "swift-build-test",
    "swift-lint",
    "toolchain-wiring-cases",
    "typescript-check",
    "typescript-wasm-check",
    "vendored-openssl-scope",
    "wasm-protocol",
    "wasm-test",
    "wiping-allocator",
)


def on_event(filter_runs: dict[str, bool], event: str) -> dict[str, bool]:
    """Every conditional job's answer for one event, from the filter jobs' answers."""
    push = event == "push"
    runs = dict(filter_runs)
    runs |= dict.fromkeys(NOT_ON_PUSH_FILTER_JOBS if push else PUSH_ONLY_FILTER_JOBS, False)
    if event != "pull_request":
        runs |= dict.fromkeys(PULL_REQUEST_ONLY_FILTER_JOBS, False)
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
    "kotlin-android-instrumented": False,
    "kotlin-lint": False,
    "kotlin-test": True,
    "napi-addon": True,
    "personal-relay-template": True,
    "pyo3-module": True,
    "pyo3-module-macos": True,
    "python-lint": False,
    "python-test": True,
    "python-wheel-build": True,
    "rust-build-pyo3-production": True,
    "rust-build-uniffi-production": True,
    "rust-clippy": True,
    "rust-deny": True,
    "rust-deny-fuzz": True,
    "rust-doc": True,
    "rust-doctest": True,
    "rust-fmt": True,
    "rust-test": True,
    # rust-test runs its targets on every change `rust` selects; it runs on
    # `rust-prose` alone, which a Rust-only change leaves false.
    "rust-test-prose": False,
    "rust-test-optional-features": True,
    "rust-test-macos": True,
    "rust-test-napi-production": True,
    "scaffold-typescript-web-check": False,
    "swift-build-test": True,
    "swift-lint": False,
    "typescript-check": True,
    "typescript-wasm-check": False,
    "uniffi-cdylib-linux": True,
    "xcframework": True,
} | dict.fromkeys(CODE_JOBS, True)
DOCS_ONLY_RUNS = dict.fromkeys(RUST_ONLY_RUNS, False)
# A Rust-only pull request skips the four macOS bridge jobs, while a Rust-only
# merge_group run runs all four and a Rust-only push runs the two producers among
# them, xcframework and pyo3-module-macos. MACOS_BRIDGE_PATH_CASES below states the
# same rule per changed path.
MACOS_BRIDGE_JOBS = (
    "bridge-parity-swift",
    "pyo3-module-macos",
    "swift-build-test",
    "xcframework",
)
RUST_ONLY_PR_RUNS = RUST_ONLY_RUNS | dict.fromkeys(MACOS_BRIDGE_JOBS, False)
PYTHON_ONLY = DOCS_ONLY | {"python": "true", "code": "true"}
PYTHON_ONLY_RUNS = DOCS_ONLY_RUNS | dict.fromkeys(CODE_JOBS, True) | dict.fromkeys(
    (
        "bridge-parity",
        "bridge-parity-kotlin",
        "bridge-parity-swift",
        # Its `python` clause predates the producer split and is kept so the Kotlin
        # suite runs on every change it ran on before.
        "kotlin-test",
        "napi-addon",
        "pyo3-module",
        "pyo3-module-macos",
        "python-lint",
        "python-test",
        "python-wheel-build",
        "rust-build-pyo3-production",
        # Producer of the UniFFI cdylib and Kotlin bindings kotlin-test and
        # bridge-parity-kotlin download.
        "uniffi-cdylib-linux",
        "xcframework",
    ),
    True,
)
# One filter per job clause: apart from pyo3-module and python-test, no job ORs
# two of swift, typescript and scaffold-typescript-web together, so dropping any
# one of those clauses from such a job's `if:` changes that job's answer in this
# scenario. python-test ORs swift and typescript because a test it runs reads both
# SDKs' sources, and check_binding_test_reads reports a dropped clause there. typescript-wasm sits
# in its own scenario because scaffold-typescript-web-check ORs it with
# scaffold-typescript-web.
SWIFT_TYPESCRIPT = DOCS_ONLY | dict.fromkeys(
    ("swift", "typescript", "scaffold-typescript-web", "code"), "true"
)
SWIFT_TYPESCRIPT_RUNS = DOCS_ONLY_RUNS | dict.fromkeys(CODE_JOBS, True) | dict.fromkeys(
    (
        "bridge-parity",
        "bridge-parity-swift",
        "napi-addon",
        "pyo3-module",
        "pyo3-module-macos",
        "python-test",
        "scaffold-typescript-web-check",
        "swift-build-test",
        "swift-lint",
        "typescript-check",
        "xcframework",
    ),
    True,
)
WASM_ONLY = DOCS_ONLY | {"typescript-wasm": "true", "code": "true"}
WASM_ONLY_RUNS = DOCS_ONLY_RUNS | dict.fromkeys(CODE_JOBS, True) | dict.fromkeys(
    ("pyo3-module", "python-test", "scaffold-typescript-web-check", "typescript-wasm-check"), True
)
# A change confined to `fuzz/**`, such as a fuzz/Cargo.lock bump: of the `changes`
# filters, only `fuzz` and `code` list `fuzz/**`. fuzz-build and rust-deny-fuzz run on
# their `fuzz` clause alone here, so dropping that clause from either `if:` changes
# this scenario's answer.
FUZZ_ONLY = DOCS_ONLY | {"fuzz": "true", "code": "true"}
FUZZ_ONLY_RUNS = DOCS_ONLY_RUNS | dict.fromkeys(CODE_JOBS, True) | dict.fromkeys(
    ("fuzz-build", "rust-deny-fuzz"), True
)
# A change confined to prose that only Rust test code reads, such as an ADR edit:
# no filter but `rust-prose` lists it, and it is prose, so `code` is false too.
RUST_PROSE_ONLY = DOCS_ONLY | {"rust-prose": "true"}
RUST_PROSE_ONLY_RUNS = DOCS_ONLY_RUNS | {"rust-test-prose": True}

SCENARIOS = {
    "rust-only, pull_request": Scenario(
        name="rust-only, pull_request",
        filters=RUST_ONLY,
        event="pull_request",
        runs=on_event(RUST_ONLY_PR_RUNS, "pull_request"),
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
} | {
    f"fuzz-only, {event}": Scenario(
        name=f"fuzz-only, {event}",
        filters=FUZZ_ONLY,
        event=event,
        runs=on_event(FUZZ_ONLY_RUNS, event),
    )
    for event in ("pull_request", "merge_group", "push")
} | {
    f"rust-prose-only, {event}": Scenario(
        name=f"rust-prose-only, {event}",
        filters=RUST_PROSE_ONLY,
        event=event,
        runs=on_event(RUST_PROSE_ONLY_RUNS, event),
    )
    for event in ("pull_request", "merge_group", "push")
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
                ref in TOOLCHAIN_REFS
                or bool(TOOLCHAIN_VERSION_TAG.match(ref))
                or bool(COMMIT_SHA.fullmatch(ref)),
                f"{uses} — that repository publishes {sorted(TOOLCHAIN_REFS)} and a tag "
                f"per released Rust version, and a step may name one of its commits; "
                f"pass a date-pinned nightly through `with: toolchain:` instead",
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


def workspace_member_names(root: Path | None = None) -> set[str]:
    """Return the `[package] name` of every directory workspace_member_directories lists."""
    root = (REPO if root is None else root).resolve()
    return {
        tomllib.loads((root / directory / "Cargo.toml").read_text())["package"]["name"]
        for directory in workspace_member_directories(root)
    }


def selected_packages(job: dict) -> set[str]:
    """Return every package a `-p <package>` in a job's cargo commands selects."""
    names: set[str] = set()
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        for line in logical_lines(step.get("run") or ""):
            tokens = line.split()
            if tokens[:1] != ["cargo"]:
                continue
            names |= {
                tokens[index + 1]
                for index, token in enumerate(tokens[:-1])
                if token in ("-p", "--package")
            }
    return names


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
    """Yield each job compiling every workspace member under a path filter.

    A job compiles every member when one of its commands carries `--workspace`,
    or when its cargo commands' `-p` selections together name every member, as
    rust-test's package shards do. Yields `(job_id, keys, patterns)`, where
    `keys` names the paths-filter keys that decide whether the job runs and
    `patterns` holds their path entries. A job carrying no filter-gated `if:`
    runs on every event, so it needs no filter and this skips it.
    """
    steps = paths_filter_steps(doc)
    if not steps:
        return
    members = workspace_member_names()
    for job_id, job in sorted((doc.get("jobs") or {}).items()):
        workspace_wide = any(
            WORKSPACE_SCOPE_FLAG in line.split()
            for step in (job.get("steps") or [])
            if isinstance(step, dict)
            for line in logical_lines(step.get("run") or "")
        ) or members <= selected_packages(job)
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
    # rust-test selects every member through `-p` across its shards. A shard
    # that drops a member leaves the job compiling part of the workspace, and
    # the discovery stops reading it, which the comparison above turns into a
    # failure.
    ci = next((doc for path, doc in documents if path.name == "ci.yml"), None)
    if ci is not None and "rust-test" in ci["jobs"]:
        dropped = copy.deepcopy(ci)
        for step in dropped["jobs"]["rust-test"]["steps"]:
            if isinstance(step, dict) and " -p scp-relay " in str(step.get("run") or ""):
                step["run"] = str(step["run"]).replace(" -p scp-relay ", " ")
        check(
            "a rust-test shard set missing a member is not read as workspace-wide",
            "rust-test"
            not in {job_id for job_id, _k, _p in workspace_scoped_jobs(dropped)}
            and "rust-test" in {job_id for job_id, _k, _p in workspace_scoped_jobs(ci)},
            "the discovery reads rust-test whatever its shards select",
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


@functools.lru_cache(maxsize=None)
def _glob_regex(pattern: str) -> re.Pattern:
    """Compile one dorny/paths-filter glob as glob_selects reads it."""
    segments = pattern.split("/")
    parts = []
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            parts.append(".*" if last else "(?:[^/]+/)*")
            continue
        piece = "".join(
            "[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c)
            for c in segment
        )
        parts.append(piece if last else f"{piece}/")
    return re.compile("".join(parts))


def glob_selects(pattern: str, path: str) -> bool:
    """Report whether one dorny/paths-filter glob selects one file path.

    dorny/paths-filter matches with picomatch (`dot: true`): a `**` segment
    matches zero or more whole path segments, `*` and `?` match within one
    segment, and every other character matches itself. pattern_covers stays
    the conservative two-shape reader for the checks that rely on it; this
    reader exists for a filter whose entry is a mid-path glob such as
    `'crates/**/Cargo.toml'`, which pattern_covers would read as selecting
    nothing.
    """
    return _glob_regex(pattern).fullmatch(path) is not None


def tracked_crate_manifests() -> list[str]:
    """Every tracked Cargo.toml below crates/, at any depth."""
    proc = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z", "--", "crates/**/Cargo.toml"],
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(path for path in proc.stdout.split("\0") if path)


def manifests_outside(patterns: set[str], manifests: list[str]) -> list[str]:
    return [
        path
        for path in manifests
        if not any(glob_selects(pattern, path) for pattern in patterns)
    ]


def check_fuzz_filter_selects_every_crate_manifest(jobs: dict) -> None:
    """The `fuzz` filter selects every crate manifest, inside its closure or not.

    CRITERION: a change to any tracked `crates/**/Cargo.toml` selects
    fuzz-build. A manifest edit outside the fuzz closure can add the dependency
    edge that pulls a crate into that build, and fuzz-build's
    `cargo check --locked` is the one check that sees fuzz/Cargo.lock fall
    behind it. A crate outside the closure has no `crates/<name>/**` entry, so
    only a manifest-wide entry selects its Cargo.toml; deleting that entry
    fails here. The detector half deletes every entry that is not a
    `crates/<name>/**` closure directory, the shape the closure check above
    requires, and asserts the reader then reports a manifest, so a reader that
    selected everything would fail this self-test.
    """
    patterns = set(path_filters(jobs).get("fuzz", []))
    manifests = tracked_crate_manifests()
    check(
        "the fuzz filter's manifest check reads at least one crate manifest",
        bool(manifests),
        "git ls-files found no crates/**/Cargo.toml, so the check below proves nothing",
    )
    missing = manifests_outside(patterns, manifests)
    check(
        "filter 'fuzz' selects every crate manifest",
        not missing,
        f"unselected {missing}; a manifest edit there can add an edge fuzz/Cargo.lock "
        f"does not record while fuzz-build, the one `cargo check --locked` over it, "
        f"skips",
    )
    closure_only = {
        pattern
        for pattern in patterns
        if re.fullmatch(r"crates/[^/*?]+/\*\*", pattern)
    }
    check(
        "dropping the fuzz filter's manifest-wide entry leaves a crate manifest unselected",
        bool(manifests_outside(closure_only, manifests)),
        "every crate manifest sits inside the fuzz closure, so the check above cannot "
        "tell whether the manifest-wide entry exists",
    )
    for pattern, path, selects in (
        ("crates/**/Cargo.toml", "crates/scp-node/Cargo.toml", True),
        ("crates/**/Cargo.toml", "crates/a/b/Cargo.toml", True),
        ("crates/**/Cargo.toml", "crates/scp-node/src/lib.rs", False),
        ("crates/**/Cargo.toml", "fuzz/Cargo.toml", False),
        ("fuzz/**", "fuzz/Cargo.lock", True),
        ("crates/*/Cargo.toml", "crates/a/b/Cargo.toml", False),
    ):
        check(
            f"glob_selects({pattern!r}, {path!r}) is {selects}",
            glob_selects(pattern, path) is selects,
        )


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


# The dependency sections cargo builds for every package a build reaches, and
# the one it builds only for a package the command selects. Cargo enables a
# dev-dependency only for a selected package: `cargo test -p a` compiles a's
# `[dev-dependencies]`, and not those of a crate a reaches as a dependency, so
# a feature such an unbuilt dev entry names never joins the build's feature
# set. testing_edge reads DEV_SECTION only when its caller says the manifest's
# package is selected.
ALWAYS_BUILT_SECTIONS = ("dependencies", "build-dependencies")
DEV_SECTION = "dev-dependencies"


def testing_edge(manifest: Path, package: str, *, selected: bool) -> str | None:
    """Return how `manifest` turns `package`'s `testing` feature on, or None.

    `selected` says whether the command builds `manifest`'s package's own test
    targets. Cargo enables a dev-dependency only for a selected package, so
    the `[dev-dependencies]` tables (top-level and `[target.*]`) count only
    when `selected` is true; `[dependencies]` and `[build-dependencies]` count
    for every package the build reaches.

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
    sections = ALWAYS_BUILT_SECTIONS + ((DEV_SECTION,) if selected else ())
    tables = [document.get(section) or {} for section in sections]
    for target in (document.get("target") or {}).values():
        tables += [target.get(section) or {} for section in sections]
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
    roots = {manifest.resolve() for manifest in selected}
    for manifest in sorted(manifests):
        edge = testing_edge(manifest, package, selected=manifest in roots)
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
    """Write a seven-crate workspace holding each spelling of a manifest edge
    that turns a sibling's `testing` feature on.

    leaf     declares the feature and no dependencies.
    enabler  depends on leaf with `features = ["testing"]` — the
             dependency-entry spelling that crates/scp-ffi/common/Cargo.toml
             writes against scp-identity in its `[dev-dependencies]`;
             testing_edge reads `[dependencies]`
             and `[build-dependencies]` identically.
    implier  declares a feature naming `"leaf/testing"`, the spelling
             crates/scp-identity/Cargo.toml's `testing` feature carries against
             scp-dht.
    middle   depends on enabler and never names leaf.
    selfdev  dev-depends on itself with `features = ["testing"]`, the spelling
             crates/scp-dht/Cargo.toml uses to turn its own feature on in its
             tests.
    devonly  dev-depends on leaf with `features = ["testing"]`, the edge
             crates/scp-node/Cargo.toml carries against scp-transport.
    user     depends on devonly, as scp-transport's tests reach scp-node
             through scp-testing; cargo builds no dev-dependency of devonly
             when only user is selected.
    """
    (root / "Cargo.toml").write_text(
        "[workspace]\n"
        'members = ["leaf", "enabler", "implier", "middle", "selfdev", '
        '"devonly", "user"]\n'
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
        "devonly": (
            "[dev-dependencies]\n"
            'leaf = { path = "../leaf", features = ["testing"] }\n'
        ),
        "user": '[dependencies]\ndevonly = { path = "../devonly" }\n',
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
    crates/scp-ffi/common/Cargo.toml and crates/scp-transport/Cargo.toml — and
    compiles out every shipped-build assertion scp-identity carries.
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
                    "--exclude implier --exclude middle --exclude devonly"
                ),
                "leaf",
                root,
            )
            is None,
            "leaf, selfdev and user remain; none reaches enabler's manifest "
            "or implier's feature table, and user's build compiles devonly "
            "without devonly's dev-dependencies",
        )
        check(
            "a dev-dependency edge counts when its package is selected",
            command_unifies_testing(
                split_command("cargo test -p devonly"), "leaf", root
            )
            is not None,
            "`cargo test -p devonly` compiles devonly's dev-dependency on "
            "leaf with `testing`, so narrowing dev sections to selected "
            "packages must still report it",
        )
        check(
            "a dev-dependency edge of a non-selected package is not reported",
            command_unifies_testing(
                split_command("cargo test -p user"), "leaf", root
            )
            is None,
            "user reaches devonly as a plain dependency, and cargo enables "
            "devonly's dev-dependencies only when devonly is selected",
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
    # order — crates/scp-ffi/common/Cargo.toml sorts ahead of
    # crates/scp-testing/Cargo.toml — so the second conjunct names
    # the manifest this entry records by asking testing_edge, the one-manifest
    # reader command_unifies_testing is built on, about that manifest alone.
    # Whether scp-testing's own `testing` feature compiles src/helpers.rs is a
    # fact of the build cargo resolves, not of manifest text, and job
    # rust-test-optional-features checks it with
    # `cargo check -p scp-testing --lib --features testing`.
    scp_testing_edge = testing_edge(
        scp_testing_manifest, "scp-identity", selected=True
    )
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
        "a -p scp-node build turns scp-transport/testing on",
        command_unifies_testing(
            split_command("cargo test -p scp-node"), "scp-transport"
        )
        is not None,
        "crates/scp-node/Cargo.toml dev-depends on scp-transport with "
        "`testing`, and cargo builds that edge when scp-node is selected",
    )
    check(
        "a -p scp-transport build skips scp-node's dev-dependencies",
        command_unifies_testing(
            split_command(
                "cargo nextest run --no-tests=fail -p scp-transport "
                "--features push-store --lib --tests"
            ),
            "scp-transport",
        )
        is None,
        "scp-transport's tests reach scp-node through scp-testing as a plain "
        "dependency, so scp-node's dev edge on scp-transport/testing is never "
        "built; job rust-test-optional-features rests on that",
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
            # and `changes` run. On a draft pull request both skip, every job that
            # needs either skips with it, and scripts/ci-aggregate-result.py returns 0 on exactly
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
    `needs` list must select that job too, and so must the `if:` of every job that
    uploads an artifact the job downloads.

    An artifact's producer counts as a dependency whether or not `needs` lists it. A
    consumer that waits for the artifact in a step instead (see awaited_download_gaps)
    runs when the producer skips, and its wait fails it, so a narrower producer
    condition fails that consumer on exactly the runs it would have skipped it on.

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
        needs = job_needs(job)
        awaited = sorted(
            {
                producer
                for artifact in downloaded_artifacts(job)
                for producer in artifact_producers(doc, artifact)
                if producer not in needs and producer != job_id
            }
        )
        if not needs and not awaited:
            continue
        condition = job.get("if")
        if condition is None:
            # A job that carries no `if:` runs on every run of this workflow, so the
            # criterion binds hardest on it: every job in its `needs` list has to run
            # on every such run too. Stepping over it would exempt exactly the case
            # the criterion states, so substitute the constant-true expression,
            # written in the grammar `selects` reads, and compare normally.
            condition = "true == 'true'"
        # A consumer that runs over a skipped `needs` entry is exempt from that entry,
        # but never from a producer it awaits: the wait fails it whatever its `if:`.
        runs_over_a_skip = bool(RUNS_OVER_A_SKIPPED_DEPENDENCY.search(str(condition)))
        for dependency in ([] if runs_over_a_skip else needs) + awaited:
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
                relation = "needs" if dependency in needs else "awaits an artifact of"
                gaps.append(
                    f"{job_id} {relation} {dependency} and this check cannot decide whether "
                    f"{dependency} runs wherever {job_id} does ({unreadable})"
                )
                continue
            if pairs:
                outputs, event = pairs[0]
                selected = sorted(key for key, on in outputs.items() if on == "true")
                effect = (
                    f"which skips {job_id}"
                    if dependency in needs
                    else f"so {job_id} waits for an artifact nothing uploads and fails"
                )
                gaps.append(
                    f"{job_id} runs and {dependency} skips on event {event} with "
                    f"filters {selected or ['none']} true, {effect} "
                    f"and fails the `ci` aggregate on every such pull request"
                )
    return gaps


def job_needs(job: dict) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def downloaded_artifacts(job: dict) -> list[str]:
    """Every artifact name a job downloads from its own workflow run.

    A download that names `run-id` reads another run's artifacts, which no job of
    this run produces.
    """
    return [
        str((step.get("with") or {}).get("name"))
        for step in job.get("steps") or []
        if str(step.get("uses") or "").startswith("actions/download-artifact")
        and "run-id" not in (step.get("with") or {})
    ]


def artifact_producers(doc: dict, artifact: str) -> list[str]:
    """Every job id with an `actions/upload-artifact` step uploading `artifact`."""
    return sorted(
        job_id
        for job_id, job in doc["jobs"].items()
        if any(
            str(step.get("uses") or "").startswith("actions/upload-artifact")
            and (step.get("with") or {}).get("name") == artifact
            for step in job.get("steps") or []
        )
    )


def check_dependency_conditions(doc: dict) -> None:
    gaps = dependency_condition_gaps(doc)
    check(
        "ci.yml: every job's `needs`, and every producer it awaits, are selected "
        "wherever the job is",
        not gaps,
        "; ".join(gaps),
    )


def draft_condition_gaps(doc: dict) -> list[str]:
    """Return each way job `changes` fails to carry job check-draft's `if:`.

    CRITERION: job `changes` carries an `if:` whose whitespace-normalised text equals
    check-draft's, and that text reads `github.event.pull_request.draft`.

    WHY: `changes` does not need check-draft, so that it starts when the run is
    created. Every path-filtered job reaches the draft gate only through `changes`,
    so `changes` without the draft `if:` runs on a draft pull request and every job
    that needs it runs with it. scripts/ci-aggregate-result.py returns 0 for a
    draft once it sees check-draft skipped, and fails a run in which check-draft
    skipped and `changes` did not, so a divergence would also turn every draft run
    red; this check reports it on the pull request that introduces it.
    """
    jobs = doc["jobs"]
    gate = jobs.get("check-draft", {}).get("if")
    if gate is None or "github.event.pull_request.draft" not in str(gate):
        return [f"check-draft carries no draft `if:` (it carries {gate!r})"]
    condition = jobs.get("changes", {}).get("if")
    if condition is None:
        return ["changes carries no `if:`, so it runs on a draft pull request"]
    if " ".join(str(condition).split()) != " ".join(str(gate).split()):
        return [f"changes carries `if: {condition}`, not check-draft's `if: {gate}`"]
    return []


def check_draft_condition(doc: dict) -> None:
    gaps = draft_condition_gaps(doc)
    check("ci.yml: job changes carries check-draft's `if:`", not gaps, "; ".join(gaps))
    # Controls: `changes` without the `if:`, `changes` with a narrower one, and a
    # check-draft whose `if:` changed while `changes` kept the old text each report.
    absent = copy.deepcopy(doc)
    del absent["jobs"]["changes"]["if"]
    gaps = draft_condition_gaps(absent)
    check(
        "a changes job without the draft `if:` is reported",
        any("changes carries no `if:`" in gap for gap in gaps),
        f"{gaps}",
    )
    narrowed = copy.deepcopy(doc)
    narrowed["jobs"]["changes"]["if"] = "github.event_name == 'push'"
    gaps = draft_condition_gaps(narrowed)
    check(
        "a changes job whose `if:` differs from check-draft's is reported",
        any("not check-draft's" in gap for gap in gaps),
        f"{gaps}",
    )
    moved = copy.deepcopy(doc)
    gate = moved["jobs"]["check-draft"]
    gate["if"] = f"github.event_name != 'push' && ({gate['if']})"
    gaps = draft_condition_gaps(moved)
    check(
        "a check-draft `if:` that changes alone no longer carries is reported",
        any("not check-draft's" in gap for gap in gaps),
        f"{gaps}",
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
    for bridge-parity-kotlin alone: uniffi-cdylib-linux's other consumer, kotlin-test,
    needs only `kotlin || rust` for its own tests, so the `python` clause is the one an
    edit scoped to the Kotlin lane would drop.
    """
    for producer_id, clause in (
        ("pyo3-module", "outputs.kotlin"),
        ("uniffi-cdylib-linux", "outputs.python"),
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


def check_dependency_conditions_detect_a_narrowed_awaited_producer(doc: dict) -> None:
    """A producer a consumer awaits, without a `needs` edge, is compared like one.

    kotlin-android-instrumented downloads uniffi-kotlin-linux and does not list
    uniffi-cdylib-linux in `needs`. Dropping the producer's `kotlin` clause leaves a
    Kotlin-only pull request running the consumer while the producer skips.
    """
    consumer, producer_id = "kotlin-android-instrumented", "uniffi-cdylib-linux"
    narrowed = copy.deepcopy(doc)
    producer = narrowed["jobs"][producer_id]
    producer["if"] = narrow_condition(producer["if"], "outputs.kotlin")
    gaps = dependency_condition_gaps(narrowed)
    check(
        f"dropping the kotlin clause from {producer_id} is reported against {consumer}, "
        f"which awaits it without a `needs` edge",
        producer_id not in job_needs(narrowed["jobs"][consumer])
        and any(
            f"{consumer} runs and {producer_id} skips" in gap
            and "waits for an artifact nothing uploads" in gap
            for gap in gaps
        ),
        f"an awaited producer that no longer covers {consumer} went unreported: {gaps}",
    )
    check(
        f"the narrowed awaited {producer_id} is reported by the comparison, not by a "
        f"parse refusal",
        not any("cannot decide" in gap for gap in gaps),
        f"the mutant expression went unread: {gaps}",
    )
    # A consumer whose `if:` runs over a skipped dependency is not exempted from a
    # producer it awaits, because the wait fails it. This grammar cannot read
    # `always()`, so the gap it reports is a parse refusal, which also fails the check.
    guarded = copy.deepcopy(narrowed)
    guarded["jobs"][consumer]["if"] = "always() && " + str(
        guarded["jobs"][consumer]["if"]
    )
    check(
        f"an `always()` {consumer} is not exempted from the producer it awaits",
        any(
            gap.startswith(consumer) and producer_id in gap
            for gap in dependency_condition_gaps(guarded)
        ),
        f"{dependency_condition_gaps(guarded)}",
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


AWAIT_SCRIPT = "scripts/ci-await-artifact.py"


def awaits(script: str, artifact: str, producer_name: str) -> bool:
    """Whether one `run:` text invokes AWAIT_SCRIPT for `artifact` from `producer_name`."""
    try:
        words = shlex.split(script)
    except ValueError:
        return False
    if AWAIT_SCRIPT not in words:
        return False
    pairs = set(itertools.pairwise(words))
    return ("--artifact", artifact) in pairs and ("--producer", producer_name) in pairs


def awaited_download_gaps(doc: dict) -> list[str]:
    """Return every download whose producer the job neither needs nor awaits.

    CRITERION: for each `actions/download-artifact` step in ci.yml that reads its own
    run, and each job that uploads that artifact, either the downloading job lists the
    producer in `needs`, or an earlier step of the downloading job that runs on every
    run of the job and can fail it invokes AWAIT_SCRIPT with `--artifact` set to the
    artifact name and `--producer` set to the producer's `name:`.

    WHY: a `needs` entry makes the consumer start after the producer ends, and a
    skipped or failed producer keeps the consumer from running at all, which the `ci`
    aggregate reports. Without that entry the consumer starts with the run, so its
    download would race the upload, and a producer that never uploads would leave the
    download to fail with a message that names no producer. AWAIT_SCRIPT returns only
    once the artifact exists, and fails the job, naming the producer, once the producer
    has completed without it. The jobs API reports a job by its display name, which is
    why the argument has to equal the producer's `name:`.
    """
    jobs = doc["jobs"]
    gaps: list[str] = []
    for job_id, job in sorted(jobs.items()):
        needs = job_needs(job)
        steps = job.get("steps") or []
        for index, step in enumerate(steps):
            if not str(step.get("uses") or "").startswith("actions/download-artifact"):
                continue
            inputs = step.get("with") or {}
            if "run-id" in inputs:
                continue
            artifact = str(inputs.get("name"))
            for producer in artifact_producers(doc, artifact):
                if producer in needs or producer == job_id:
                    continue
                name = str(jobs[producer].get("name") or producer)
                if "${{" in name:
                    gaps.append(
                        f"{job_id} downloads {artifact} from {producer}, whose `name:` "
                        f"is an expression the wait step cannot name"
                    )
                    continue
                if not any(
                    a_step_that_runs_and_can_fail_its_job(earlier)
                    and awaits(str(earlier.get("run") or ""), artifact, name)
                    for earlier in steps[:index]
                ):
                    gaps.append(
                        f"{job_id} downloads {artifact} without {producer} in `needs` "
                        f"and with no earlier unguarded step running {AWAIT_SCRIPT} "
                        f"--artifact {artifact} --producer {name!r}"
                    )
    return gaps


def check_awaited_downloads(doc: dict) -> None:
    gaps = awaited_download_gaps(doc)
    check(
        "ci.yml: every download either needs its producer or awaits it first",
        not gaps,
        "; ".join(gaps),
    )
    consumer = "kotlin-android-instrumented"
    if consumer not in doc["jobs"] or "uniffi-cdylib-linux" in job_needs(
        doc["jobs"][consumer]
    ):
        check(
            f"{consumer} awaits uniffi-kotlin-linux, so the controls below have a "
            f"wait step to mutate",
            False,
            f"{consumer} is absent or lists uniffi-cdylib-linux in `needs`",
        )
        return

    def wait_index(steps: list) -> int:
        return next(
            i for i, s in enumerate(steps) if AWAIT_SCRIPT in str(s.get("run") or "")
        )

    def mutate(edit: Callable[[list], None]) -> list[str]:
        mutated = copy.deepcopy(doc)
        edit(mutated["jobs"][consumer]["steps"])
        return [
            gap for gap in awaited_download_gaps(mutated) if gap.startswith(consumer)
        ]

    def drop(steps: list) -> None:
        del steps[wait_index(steps)]

    def move_after_download(steps: list) -> None:
        step = steps.pop(wait_index(steps))
        download = next(
            i
            for i, s in enumerate(steps)
            if str(s.get("uses") or "").startswith("actions/download-artifact")
        )
        steps.insert(download + 1, step)

    def guard(steps: list) -> None:
        steps[wait_index(steps)]["if"] = "github.event_name == 'pull_request'"

    def fail_open(steps: list) -> None:
        steps[wait_index(steps)]["continue-on-error"] = True

    def rename(old: str, new: str) -> Callable[[list], None]:
        def edit(steps: list) -> None:
            step = steps[wait_index(steps)]
            step["run"] = str(step["run"]).replace(old, new)

        return edit

    for label, edit in (
        ("with no wait step", drop),
        ("whose wait step runs after the download", move_after_download),
        ("whose wait step carries an `if:`", guard),
        ("whose wait step continues on error", fail_open),
        (
            "whose wait step names another producer",
            rename("UniFFI cdylib + Kotlin bindings", "UniFFI cdylib"),
        ),
        (
            "whose wait step names another artifact",
            rename("--artifact uniffi-kotlin-linux", "--artifact uniffi-kotlin"),
        ),
    ):
        check(
            f"a {consumer} {label} is reported",
            bool(mutate(edit)),
            "the mutant went unreported",
        )


AWAIT_PRODUCER = "Bridge artifact / planted producer"
AWAIT_ARTIFACT = "planted-artifact"


def run_await_script(
    respond: Callable[[str, int], tuple[int, dict]],
    timeout: str = "5",
    env_overrides: dict[str, str] | None = None,
) -> tuple[int, str]:
    """Run AWAIT_SCRIPT against a planted API; `respond(kind, n)` answers the nth call.

    `kind` is "artifacts" or "jobs"; the answer is (HTTP status, JSON body). The jobs
    answer also receives the requested page through the path the script builds.
    """
    import http.server
    import threading

    calls: dict[str, int] = {"artifacts": 0, "jobs": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep the planted server out of the log
            pass

        def do_GET(self):  # the name http.server dispatches on
            path, _, query = self.path.partition("?")
            prefix = "/repos/planted/repo/actions/runs/7/"
            kind = path[len(prefix) :] if path.startswith(prefix) else ""
            if kind not in calls:
                self.send_error(404)
                return
            calls[kind] += 1
            page = dict(p.split("=", 1) for p in query.split("&") if "=" in p).get(
                "page", "1"
            )
            status, body = respond(
                kind, calls[kind] if kind == "artifacts" else int(page)
            )
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = {
        **os.environ,
        "GITHUB_API_URL": f"http://127.0.0.1:{server.server_address[1]}",
        "GITHUB_REPOSITORY": "planted/repo",
        "GITHUB_RUN_ID": "7",
        "GH_TOKEN": "planted-token",
        **(env_overrides or {}),
    }
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(REPO / AWAIT_SCRIPT),
                "--artifact",
                AWAIT_ARTIFACT,
                "--producer",
                AWAIT_PRODUCER,
                "--timeout",
                timeout,
                "--interval",
                "0.02",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
    return result.returncode, result.stdout + result.stderr


def await_artifacts(present: bool, expired: bool = False) -> tuple[int, dict]:
    listed = [{"name": AWAIT_ARTIFACT, "expired": expired}] if present else []
    return 200, {"total_count": len(listed), "artifacts": listed}


def await_jobs(status: str, conclusion: str | None, page: int = 1) -> tuple[int, dict]:
    if page > 1:
        return 200, {"jobs": []}
    job = {"name": AWAIT_PRODUCER, "status": status, "conclusion": conclusion}
    return 200, {"jobs": [{"name": "other", "status": "completed"}, job]}


def check_await_script() -> None:
    """AWAIT_SCRIPT exits 0 only once the artifact exists, and fails every other way."""
    cases: list[tuple[str, Callable[[str, int], tuple[int, dict]], str, int, str]] = [
        (
            "an artifact already uploaded",
            lambda kind, n: (
                await_artifacts(True)
                if kind == "artifacts"
                else await_jobs("in_progress", None)
            ),
            "5",
            0,
            "is in this run",
        ),
        (
            "an artifact uploaded on the third poll while the producer runs",
            lambda kind, n: (
                await_artifacts(n >= 3)
                if kind == "artifacts"
                else await_jobs("in_progress", None)
            ),
            "5",
            0,
            "is in this run",
        ),
        (
            "a producer that completed between the two artifact reads of one poll",
            lambda kind, n: (
                await_artifacts(n >= 2)
                if kind == "artifacts"
                else await_jobs("completed", "success")
            ),
            "5",
            0,
            "is in this run",
        ),
        (
            "a producer that succeeded without uploading",
            lambda kind, n: (
                await_artifacts(False)
                if kind == "artifacts"
                else await_jobs("completed", "success")
            ),
            "5",
            1,
            "uploaded no artifact",
        ),
        (
            "a producer that failed",
            lambda kind, n: (
                await_artifacts(False)
                if kind == "artifacts"
                else await_jobs("completed", "failure")
            ),
            "5",
            1,
            "conclusion failure",
        ),
        (
            "a producer that skipped",
            lambda kind, n: (
                await_artifacts(False)
                if kind == "artifacts"
                else await_jobs("completed", "skipped")
            ),
            "5",
            1,
            "conclusion skipped",
        ),
        (
            "an expired artifact from a producer that completed",
            lambda kind, n: (
                await_artifacts(True, expired=True)
                if kind == "artifacts"
                else await_jobs("completed", "success")
            ),
            "5",
            1,
            "uploaded no artifact",
        ),
        (
            "a producer that never completes",
            lambda kind, n: (
                await_artifacts(False)
                if kind == "artifacts"
                else await_jobs("in_progress", None)
            ),
            "0.3",
            1,
            "did not appear within",
        ),
        (
            "a producer not created before the deadline",
            lambda kind, n: (
                await_artifacts(False) if kind == "artifacts" else (200, {"jobs": []})
            ),
            "0.3",
            1,
            "did not appear within",
        ),
        (
            "a producer listed on the second page of jobs",
            lambda kind, n: (
                await_artifacts(False)
                if kind == "artifacts"
                else (
                    (
                        200,
                        {
                            "jobs": [
                                {"name": f"filler {i}", "status": "completed"}
                                for i in range(100)
                            ]
                        },
                    )
                    if n == 1
                    else await_jobs("completed", "failure")
                )
            ),
            "5",
            1,
            "conclusion failure",
        ),
        (
            "two jobs with the producer's name",
            lambda kind, n: (
                await_artifacts(False)
                if kind == "artifacts"
                else (
                    200,
                    {"jobs": [await_jobs("in_progress", None)[1]["jobs"][1]] * 2},
                )
            ),
            "5",
            2,
            "2 jobs named",
        ),
        (
            "two transient 502 answers before the artifact appears",
            lambda kind, n: (
                (502, {}) if kind == "artifacts" and n <= 2 else await_artifacts(True)
            ),
            "5",
            0,
            "2 in a row",
        ),
        (
            "an API that refuses the token",
            lambda kind, n: (
                403,
                {"message": "Resource not accessible by integration"},
            ),
            "5",
            2,
            "HTTP 403",
        ),
        (
            "an API that keeps failing",
            lambda kind, n: (502, {}),
            "5",
            2,
            "failed 5 times in a row",
        ),
        (
            "an answer with no artifacts list",
            lambda kind, n: (200, {"total_count": 0}),
            "5",
            2,
            "no `artifacts` list",
        ),
    ]
    for label, respond, timeout, want, text in cases:
        code, out = run_await_script(respond, timeout)
        check(
            f"{AWAIT_SCRIPT} over {label} exits {want}",
            code == want and text in out,
            f"exit {code}, want {want} with {text!r}: {out}",
        )
    code, out = run_await_script(
        lambda kind, n: await_artifacts(True), env_overrides={"GH_TOKEN": ""}
    )
    check(
        f"{AWAIT_SCRIPT} without GH_TOKEN exits 3",
        code == 3 and "GH_TOKEN" in out,
        f"exit {code}: {out}",
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

    WHY: every real-FFI test module under bindings/python/tests skips itself when the
    extension is absent, and the `scp` fixture in bindings/python/tests/conftest.py
    skips every test that requests it when `SCP(storage=...)` raises SCP-VALID-7081,
    the code scp_sdk/_extension.py raises when no extension file is present; a module
    guard that still catches ImportError also skips on that. A consumer whose
    downloaded module never reached the import path therefore leaves pytest exiting 0
    over zero executed assertions in every one of these jobs at once, which is the
    `zero-test` shape this file names. The fragments also read the methods the
    `server` and `testing` features compile onto the native class, so a build
    missing one fails before pytest with the method's name: `crates/scp-ffi/`
    compiles `fullstack_create_node` only under `testing` and
    `relay_start_in_memory` only under `server`.
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


# The assignment that makes a shipped-addon test file fail, rather than skip,
# when the addon does not load (bindings/typescript/tests/shipped-addon.test.ts).
NAPI_SHIPPED_EXPECTATION = "SCP_EXPECT_SHIPPED_ADDON=1"

# A command line that builds the NAPI addon in the job itself.
NAPI_BUILD_LINE = re.compile(r"\bcargo build\b[^\n]*-p scp-ffi-napi\b")


def napi_builders_missing_the_shipped_expectation(job_id: str, steps: list) -> list[str]:
    r"""Return a gap for each `bun test` line a NAPI-building job runs unprotected.

    CRITERION: in a job whose step runs a line matching NAPI_BUILD_LINE, every
    line matching `\bbun test\b` at or after that line carries
    NAPI_SHIPPED_EXPECTATION, and its step carries no `if:` and no
    `continue-on-error` other than false.

    WHY: such a job tests the addon it builds, and downloads none, so the
    download rule above never reads it. Its test file resolves its suite to
    `describe.skip` when the addon does not load, and `bun test` exits 0 over
    zero assertions, unless NAPI_SHIPPED_EXPECTATION makes the file throw.
    """
    gaps: list[str] = []
    built = False
    for step in steps:
        for line in str(step.get("run") or "").splitlines():
            if NAPI_BUILD_LINE.search(line):
                built = True
            if not built or not re.search(r"\bbun test\b", line):
                continue
            if NAPI_SHIPPED_EXPECTATION not in line:
                gaps.append(
                    f"{job_id} builds a NAPI addon and runs `{line.strip()}` "
                    f"without {NAPI_SHIPPED_EXPECTATION}"
                )
            elif not a_step_that_runs_and_can_fail_its_job(step):
                gaps.append(
                    f"{job_id} builds a NAPI addon and runs `{line.strip()}` in a "
                    f"step that may be skipped or may fail open"
                )
    return gaps


def napi_consumers_missing_an_assertion_fragment(
    doc: dict, artifacts: tuple[str, ...]
) -> list[str]:
    r"""Return every NAPI-testing job that can pass over a skipped suite.

    CRITERION: in every job that downloads an artifact named in `artifacts`, each
    fragment in NAPI_ASSERTION_FRAGMENTS occurs in the `run:` text of a step that
    comes before the first step whose `run:` text matches `\bbun test\b` or
    `\bpytest tests` and that carries no `if:` and no `continue-on-error` other
    than false. Every other job meets the criterion of
    napi_builders_missing_the_shipped_expectation.

    WHY: every real-NAPI test file under bindings/typescript/tests wraps its addon load
    and its first construction in one `try`, passes the caught error to
    `skipReasonIfAddonAbsent` in tests/napi-guard.ts, and resolves its whole `describe`
    block to `describe.skip` or to a lone `test.skip` when `loadNativeAddon()` throws
    SCP-VALID-7081 — tests/real-napi.test.ts, tests/e2e-fullstack.test.ts and
    tests/persistence.test.ts among them. A downloaded addon wired anywhere but the
    package directory `require()` resolves therefore leaves `bun test` exiting 0 over
    zero executed NAPI assertions, which is the same `zero-test` shape the PyO3
    criterion above names.
    """
    gaps: list[str] = []
    for job_id, job in sorted(doc["jobs"].items()):
        steps = job.get("steps") or []
        if not any(
            str(step.get("uses") or "").startswith("actions/download-artifact")
            and (step.get("with") or {}).get("name") in artifacts
            for step in steps
        ):
            gaps.extend(napi_builders_missing_the_shipped_expectation(job_id, steps))
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


def check_napi_shipped_expectation_controls(
    doc: dict, artifacts: tuple[str, ...], job_id: str
) -> None:
    """A NAPI-building job that drops the shipped expectation is reported.

    The first mutant deletes NAPI_SHIPPED_EXPECTATION from `job_id`'s `bun test`
    line; the second sets `if:` on that step. The job as written must not be
    reported.
    """
    prefix = f"{job_id} builds a NAPI addon"
    check(
        f"{job_id}, which builds a NAPI addon and runs bun test, is not reported",
        not any(
            gap.startswith(prefix)
            for gap in napi_consumers_missing_an_assertion_fragment(doc, artifacts)
        ),
        "the workflow as written must meet the criterion",
    )
    hits = [
        step
        for step in doc["jobs"][job_id]["steps"]
        if NAPI_SHIPPED_EXPECTATION in str(step.get("run") or "")
    ]
    check(
        f"{job_id} sets {NAPI_SHIPPED_EXPECTATION} in exactly one step",
        len(hits) == 1,
        f"{len(hits)} steps carry it, so the mutants are not the ones intended",
    )
    if len(hits) != 1:
        return
    index = doc["jobs"][job_id]["steps"].index(hits[0])
    for name, mutate in (
        (
            f"drops {NAPI_SHIPPED_EXPECTATION}",
            lambda step: step.update(
                run=str(step["run"]).replace(NAPI_SHIPPED_EXPECTATION + " ", "")
            ),
        ),
        ("sets `if:` on its bun test step", lambda step: step.update({"if": "false"})),
        (
            "sets `continue-on-error: true` on its bun test step",
            lambda step: step.update({"continue-on-error": True}),
        ),
    ):
        mutated = copy.deepcopy(doc)
        mutate(mutated["jobs"][job_id]["steps"][index])
        gaps = napi_consumers_missing_an_assertion_fragment(mutated, artifacts)
        check(
            f"a {job_id} that {name} is reported",
            any(gap.startswith(prefix) for gap in gaps),
            f"the mutant went unreported: {gaps}",
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


# The local action every cargo-cache step uses, the upstream action only it may call, and
# the script whose digest of each workspace's root Cargo.toml it puts into the cache key.
# See the `cache-key` entry in this file's docstring.
RUST_CACHE_ACTION = "./.github/actions/rust-cache"
# The upstream action, as action_name reads any spelling of it.
RUST_CACHE_UPSTREAM = "swatinem/rust-cache"
RUST_CACHE_ACTION_FILE = REPO / ".github/actions/rust-cache/action.yml"
MANIFEST_DIGEST_SCRIPT = REPO / ".github/actions/rust-cache/manifest-digest.sh"
# A variable that changes what cargo compiles. rust-cache hashes the CARGO*/RUST*
# variables its own step sees, so one of these set only in a later step's `env:`, or
# written to `$GITHUB_ENV` by any step, changes the artifacts without changing the key.
# CARGO_TARGET_DIR is absent: it moves artifacts, it does not change them.
ARTIFACT_ENV = re.compile(
    r"^(RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_ENCODED_RUSTDOCFLAGS"
    r"|CARGO_INCREMENTAL|CARGO_PROFILE_\w+|CARGO_BUILD_\w+|CARGO_TARGET_\w+_RUSTFLAGS"
    r"|CARGO_TARGET_\w+_LINKER|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER)$"
)
ARTIFACT_ENV_WRITE = re.compile(
    r"(?<![\w$])(RUSTFLAGS|RUSTDOCFLAGS|CARGO_\w+|RUSTC\w*)=[^\n]*>>\s*\"?\$\{?GITHUB_ENV"
)
# A cargo command-line argument that changes what cargo compiles: `--config` overrides
# any config key (a `[profile.dev.package."*"]` value no variable can reach), and `-Z`
# turns on an unstable behavior. rust-cache hashes neither.
ARTIFACT_ARG = re.compile(r"(?<![\w-])(--config(?=[\s=])|-Z\s*[\w-]+)")


def direct_rust_cache_gaps(
    documents: list[tuple[Path, dict]], actions: dict[str, dict] | None = None
) -> list[str]:
    """Return each step that calls Swatinem/rust-cache without the wrapper.

    CRITERION: no step in any workflow or local composite action other than
    RUST_CACHE_ACTION `uses:` an action whose action_name (any spelling) is
    RUST_CACHE_UPSTREAM; RUST_CACHE_ACTION is the only caller.
    """
    actions = local_actions() if actions is None else actions
    gaps = []
    for path, doc in documents:
        for job_id, job in sorted((doc.get("jobs") or {}).items()):
            for index, step in enumerate(job.get("steps") or []):
                if remote_name(step) == RUST_CACHE_UPSTREAM:
                    label = step.get("name") or f"step {index}"
                    gaps.append(f"{path.name} job {job_id}, {label}: uses {step['uses']}")
    for uses, action in sorted(actions.items()):
        if uses == RUST_CACHE_ACTION:
            continue
        for index, step in enumerate((action.get("runs") or {}).get("steps") or []):
            if remote_name(step) == RUST_CACHE_UPSTREAM:
                gaps.append(f"{uses} step {index}: uses {step['uses']}")
    return gaps


def remote_name(step: object) -> str | None:
    """A step's remote action, as action_name reads it; None for a local or no `uses:`."""
    uses = step_uses(step) if isinstance(step, dict) else ""
    return action_name(uses) if uses and not uses.startswith(("./", "docker://")) else None


def wrapper_key_gaps(action: dict) -> list[str]:
    """Return each way the wrapper action fails to key on the manifest digest.

    CRITERION: a step with id `manifest` runs manifest-digest.sh, and a later step
    uses RUST_CACHE_UPSTREAM with a `prefix-key` that reads
    `steps.manifest.outputs.digest` and passes the wrapper's `workspaces` input on, so
    the digest covers the roots the cache restores.
    """
    steps = (action.get("runs") or {}).get("steps") or []
    digest_at = next(
        (
            index
            for index, step in enumerate(steps)
            if step.get("id") == "manifest"
            and "manifest-digest.sh" in str(step.get("run") or "")
            and "inputs.workspaces" in str((step.get("env") or {}).values())
        ),
        None,
    )
    gaps = []
    if digest_at is None:
        gaps.append("no step with id `manifest` runs manifest-digest.sh on the workspaces input")
    caches = [
        (index, step)
        for index, step in enumerate(steps)
        if remote_name(step) == RUST_CACHE_UPSTREAM
    ]
    if len(caches) != 1:
        gaps.append(f"{len(caches)} {RUST_CACHE_UPSTREAM} steps, expected 1")
    for index, step in caches:
        inputs = step.get("with") or {}
        if "steps.manifest.outputs.digest" not in str(inputs.get("prefix-key", "")):
            gaps.append("the rust-cache `prefix-key` does not read steps.manifest.outputs.digest")
        if "inputs.workspaces" not in str(inputs.get("workspaces", "")):
            gaps.append("the rust-cache step does not pass the workspaces input on")
        if digest_at is not None and index < digest_at:
            gaps.append("the rust-cache step runs before the digest step")
    return gaps


CACHE_WARM_WORKFLOW = REPO / ".github/workflows/cache-warm.yml"


def wrapper_warm_key_gaps(script: str, groups: set[str], warm_text: str) -> list[str]:
    """Return each group whose key reads cache-warm.yml when it should not, or the reverse.

    CRITERION: the prefix the wrapper's `manifest` step prints for a group changes with
    an edit to .github/workflows/cache-warm.yml exactly when that file writes the group,
    so an edit to a warm job's commands writes a new entry for the groups it fills and
    leaves every other group's entry an exact match. `script` is the step's `run:` text,
    `groups` every `shared-key` a workflow names, and `warm_text` the file's content.
    """
    written = {
        str((step.get("with") or {}).get("shared-key"))
        for job in (yaml.safe_load(warm_text).get("jobs") or {}).values()
        for step in job.get("steps") or []
        if str(step.get("uses") or "") == RUST_CACHE_ACTION
    }
    gaps = []
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "Cargo.toml").write_text((REPO / "Cargo.toml").read_text())
        workflows = root / ".github/workflows"
        workflows.mkdir(parents=True)

        def key(group: str, text: str) -> str:
            (workflows / "cache-warm.yml").write_text(text)
            output = root / "output"
            output.write_text("")
            env = dict(
                os.environ,
                GITHUB_WORKSPACE=str(root),
                GITHUB_OUTPUT=str(output),
                GITHUB_ACTION_PATH=str(MANIFEST_DIGEST_SCRIPT.parent),
                CACHE_WORKSPACES=". -> target",
                CACHE_GROUP=group,
            )
            result = subprocess.run(
                ["bash", "-c", script], env=env, cwd=root, capture_output=True, text=True
            )
            if result.returncode != 0:
                return f"exit {result.returncode}: {result.stdout.strip()} {result.stderr.strip()}"
            return output.read_text().strip()

        edited = warm_text + "\n# planted edit\n"
        for group in sorted(groups):
            before, after = key(group, warm_text), key(group, edited)
            if before.startswith("exit ") or after.startswith("exit "):
                gaps.append(f"group {group}: the digest step failed ({before} / {after})")
            elif (before != after) != (group in written):
                gaps.append(
                    f"group {group}: an edit to cache-warm.yml "
                    f"{'changes' if before != after else 'keeps'} its key, and cache-warm.yml "
                    f"{'writes' if group in written else 'does not write'} it"
                )
    return gaps


def manifest_digest(script: Path, root: Path) -> str:
    result = subprocess.run(
        ["bash", str(script), str(root)], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


# Edits to the root Cargo.toml, each a regex substitution applied once. KEYED edits change
# a compiled artifact, so the digest must change; UNKEYED edits change none or are keyed
# by Cargo.lock, so the digest must not change and rust-cache keeps its partial restore.
DIGEST_KEYED_EDITS = {
    "a [profile.dev] opt-level": (r"(?m)^\[profile\.dev\]\n", "[profile.dev]\nopt-level = 2\n"),
    'a [profile.dev.package."*"] value': (
        r'(?m)^\[profile\.dev\.package\."\*"\]\n',
        '[profile.dev.package."*"]\ncodegen-units = 7\n',
    ),
    "a [profile.release] value": (r"(?m)^\[profile\.release\]\n", "[profile.release]\nlto = false\n"),
    "a workspace dependency's features": (
        r'(?m)^(tokio = \{ version = "[^"]*", features = \[)"full"\]',
        r'\1"full", "test-util"]',
    ),
    "a [patch.crates-io] rev": (r'(rev = ")[0-9a-f]{40}(")', r"\g<1>" + "0" * 40 + r"\2"),
    "a workspace member": (r"(?m)^members = \[\n", 'members = [\n    "crates/planted",\n'),
}
DIGEST_UNKEYED_EDITS = {
    "a workspace dependency's version string": (r'(?m)^(async-trait = )"[^"]*"', r'\1"0.1.99"'),
    "a workspace dependency's inline version": (
        r'(?m)^(tokio = \{ version = )"[^"]*"',
        r'\1"1.99"',
    ),
    "a comment line": (r"(?m)^\[profile\.dev\]\n", "[profile.dev]\n# planted comment\n"),
    "a [workspace.lints.clippy] level": (
        r"(?m)^\[workspace\.lints\.clippy\]\n",
        '[workspace.lints.clippy]\nplanted_lint = "allow"\n',
    ),
}


def manifest_digest_gaps(script: Path, manifest_text: str) -> list[str]:
    """Return each edit to `manifest_text` whose effect on the digest is wrong.

    CRITERION: every DIGEST_KEYED_EDITS edit changes the digest `script` prints and
    every DIGEST_UNKEYED_EDITS edit leaves it unchanged. An edit whose pattern matches
    nothing is a gap too, because it would prove nothing.
    """
    gaps = []
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)

        def digest_of(text: str) -> str:
            (root / "Cargo.toml").write_text(text)
            return manifest_digest(script, root)

        base = digest_of(manifest_text)
        for keyed, edits in ((True, DIGEST_KEYED_EDITS), (False, DIGEST_UNKEYED_EDITS)):
            for label, (pattern, replacement) in edits.items():
                edited, count = re.subn(pattern, replacement, manifest_text, count=1)
                if count != 1:
                    gaps.append(f"{label}: the edit matches nothing in Cargo.toml")
                    continue
                changed = digest_of(edited) != base
                if changed != keyed:
                    gaps.append(
                        f"{label} {'leaves' if keyed else 'changes'} the digest"
                    )
    return gaps


def artifact_env_gaps(doc: dict, name: str, action_texts: dict[str, str]) -> list[str]:
    """Return each artifact-changing variable a cargo-cache job sets outside the key.

    CRITERION: in a job with a RUST_CACHE_ACTION step, no step's `env:` sets a key
    ARTIFACT_ENV matches, and no step's `run:`, nor any local action in
    `action_texts` that a step uses, writes such a variable to `$GITHUB_ENV` or passes
    an ARTIFACT_ARG on a line that runs cargo (a config override belongs in a
    `CARGO_*` variable at the job or workflow level, which the key hashes). The
    workflow-level and job-level `env:` reach the cache step, so those stay allowed
    (check profile-env further confines CARGO_PROFILE_* to the workflow level).
    """
    gaps = []
    for job_id, job in sorted((doc.get("jobs") or {}).items()):
        steps = job.get("steps") or []
        if not any(str(step.get("uses") or "") == RUST_CACHE_ACTION for step in steps):
            continue
        for index, step in enumerate(steps):
            label = step.get("name") or step.get("uses") or f"step {index}"
            for key in sorted(step.get("env") or {}):
                if ARTIFACT_ENV.match(str(key)):
                    gaps.append(f"{name} job {job_id}, {label}: step env sets {key}")
            texts = [str(step.get("run") or "")]
            uses = str(step.get("uses") or "")
            if uses in action_texts:
                texts.append(action_texts[uses])
            for text in texts:
                for match in ARTIFACT_ENV_WRITE.finditer(text):
                    if ARTIFACT_ENV.match(match.group(1)):
                        gaps.append(
                            f"{name} job {job_id}, {label}: writes {match.group(1)} "
                            "to $GITHUB_ENV"
                        )
                for line in text.splitlines():
                    if CARGO_COMMAND.search(line):
                        for match in ARTIFACT_ARG.finditer(line):
                            gaps.append(
                                f"{name} job {job_id}, {label}: passes cargo "
                                f"{match.group(1)}"
                            )
    return gaps


def local_action_texts() -> dict[str, str]:
    """Map each `./.github/actions/<name>` ref to the text of every file in it."""
    texts = {}
    for directory in sorted((REPO / ".github/actions").iterdir()):
        if directory.is_dir():
            texts[f"./.github/actions/{directory.name}"] = "\n".join(
                path.read_text() for path in sorted(directory.iterdir()) if path.is_file()
            )
    return texts


# Cargo reads `.cargo/config` as well as `.cargo/config.toml`; rust-cache hashes only
# the second, so the first in any workspace root's ancestry would change artifacts
# outside the key.
def unkeyed_cargo_config_gaps(roots: list[Path]) -> list[str]:
    """CRITERION: no directory from REPO down to each root holds `.cargo/config`."""
    gaps = []
    for root in roots:
        for directory in (root, *root.parents):
            legacy = directory / ".cargo/config"
            if legacy.is_file():
                gaps.append(f"{legacy} exists, and rust-cache hashes only .cargo/config.toml")
            if directory == REPO or directory == directory.parent:
                break
    return sorted(set(gaps))


def check_cache_key(documents: list[tuple[Path, dict]]) -> None:
    gaps = direct_rust_cache_gaps(documents)
    check(
        f"no workflow step uses {RUST_CACHE_UPSTREAM} except through {RUST_CACHE_ACTION}",
        not gaps,
        f"{gaps}: that step's key omits the root Cargo.toml's [profile.*] tables",
    )
    planted = copy.deepcopy(documents)
    path, doc = next(
        (path, doc)
        for path, doc in planted
        if any(
            str(step.get("uses") or "") == RUST_CACHE_ACTION
            for job in (doc.get("jobs") or {}).values()
            for step in job.get("steps") or []
        )
    )
    step = next(
        step
        for job in doc["jobs"].values()
        for step in job.get("steps") or []
        if str(step.get("uses") or "") == RUST_CACHE_ACTION
    )
    for spelling in ("Swatinem/rust-cache@v2", "swatinem/rust-cache@v2"):
        step["uses"] = spelling
        check(
            f"a direct {spelling} step in {path.name} is reported",
            any(gap.startswith(f"{path.name} job ") for gap in direct_rust_cache_gaps(planted)),
            f"{direct_rust_cache_gaps(planted)}",
        )
    actions = copy.deepcopy(local_actions())
    actions[CARGO_FETCH_ACTION]["runs"]["steps"].append({"uses": "SWATINEM/Rust-Cache@v2"})
    check(
        f"a direct rust-cache step inside {CARGO_FETCH_ACTION} is reported",
        any(gap.startswith(f"{CARGO_FETCH_ACTION} step ") for gap in direct_rust_cache_gaps(documents, actions)),
        f"{direct_rust_cache_gaps(documents, actions)}",
    )

    action = yaml.safe_load(RUST_CACHE_ACTION_FILE.read_text())
    gaps = wrapper_key_gaps(action)
    check(
        f"{RUST_CACHE_ACTION} puts the manifest digest into rust-cache's prefix-key",
        not gaps,
        "; ".join(gaps),
    )
    for label, mutate in (
        ("without the prefix-key", lambda steps: steps[1]["with"].pop("prefix-key")),
        ("with the digest step removed", lambda steps: steps.pop(0)),
        ("passing no workspaces on", lambda steps: steps[1]["with"].pop("workspaces")),
    ):
        mutated = copy.deepcopy(action)
        mutate(mutated["runs"]["steps"])
        check(
            f"the wrapper {label} is reported",
            bool(wrapper_key_gaps(mutated)),
            f"{label}: wrapper_key_gaps returned nothing",
        )

    manifest_text = (REPO / "Cargo.toml").read_text()
    gaps = manifest_digest_gaps(MANIFEST_DIGEST_SCRIPT, manifest_text)
    check(
        "manifest-digest.sh changes on each artifact-changing edit to Cargo.toml and on "
        "no other",
        not gaps,
        "; ".join(gaps),
    )
    # Control: a digest script that skips [profile.*] tables, the hole this check closes.
    with tempfile.TemporaryDirectory() as scratch:
        planted_script = Path(scratch) / "manifest-digest.sh"
        text = MANIFEST_DIGEST_SCRIPT.read_text()
        skip = "skip = header ~ /^(workspace\\.)?lints(\\.|$)/"
        planted_script.write_text(
            text.replace(skip, "skip = header ~ /^profile(\\.|$)/ || header ~ /^(workspace\\.)?lints(\\.|$)/")
        )
        check(
            "the planting replaced the digest script's skip rule",
            planted_script.read_text() != text,
            "the skip rule text moved; update this control",
        )
        planted_gaps = manifest_digest_gaps(planted_script, manifest_text)
        check(
            "a digest that ignores [profile.*] tables is reported",
            any("profile" in gap and "leaves the digest" in gap for gap in planted_gaps),
            f"{planted_gaps}",
        )
    check(
        "manifest-digest.sh exits non-zero for a root without Cargo.toml",
        subprocess.run(
            ["bash", str(MANIFEST_DIGEST_SCRIPT), str(REPO / ".github")],
            capture_output=True,
            check=False,
        ).returncode
        != 0,
        "a missing manifest printed a digest that keys on nothing",
    )

    manifest_step = next(
        step for step in action["runs"]["steps"] if step.get("id") == "manifest"
    )
    groups = {
        str((step.get("with") or {}).get("shared-key"))
        for _path, doc in documents
        for job in (doc.get("jobs") or {}).values()
        for step in job.get("steps") or []
        if str(step.get("uses") or "") == RUST_CACHE_ACTION
    }
    warm_text = CACHE_WARM_WORKFLOW.read_text()
    gaps = wrapper_warm_key_gaps(manifest_step["run"], groups, warm_text)
    check(
        "an edit to cache-warm.yml changes the key of each group it writes and of no other",
        not gaps,
        "; ".join(gaps),
    )
    # Controls: a step that always hashes the file rekeys every group on each warm
    # edit, and one that never hashes it leaves a warm group's stale entry an exact
    # match that skips the save. Every group the workflows hold today is one
    # cache-warm.yml writes, so the first control reads a planted group name that no
    # workflow writes; without it, hashing the file into every group matches the
    # live set exactly and nothing is reported.
    planted_groups = groups | {"planted-group-cache-warm-does-not-write"}
    test = 'if grep -Eq "^[[:space:]]+shared-key:'
    for label, replacement, reported in (
        (
            "hashing cache-warm.yml into every group",
            'if true || grep -Eq "^[[:space:]]+shared-key:',
            "changes its key, and cache-warm.yml does not write it",
        ),
        (
            "hashing cache-warm.yml into no group",
            'if false && grep -Eq "^[[:space:]]+shared-key:',
            "keeps its key, and cache-warm.yml writes it",
        ),
    ):
        planted = manifest_step["run"].replace(test, replacement)
        check(f"the planting for a wrapper {label} replaced its test", planted != manifest_step["run"])
        planted_gaps = wrapper_warm_key_gaps(planted, planted_groups, warm_text)
        check(
            f"a wrapper {label} is reported",
            any(reported in gap for gap in planted_gaps),
            f"{planted_gaps}",
        )
    check(
        "the digest step exits non-zero when cache-warm.yml is not checked out",
        subprocess.run(
            ["bash", "-c", manifest_step["run"]],
            env=dict(
                os.environ,
                GITHUB_WORKSPACE=str(REPO / ".github"),
                GITHUB_OUTPUT=os.devnull,
                GITHUB_ACTION_PATH=str(MANIFEST_DIGEST_SCRIPT.parent),
                CACHE_WORKSPACES=f"{REPO} -> target",
                CACHE_GROUP="workspace-debug",
            ),
            capture_output=True,
            check=False,
        ).returncode
        != 0,
        "a missing cache-warm.yml printed a key that ignores it",
    )

    texts = local_action_texts()
    for path, doc in documents:
        gaps = artifact_env_gaps(doc, path.name, texts)
        check(
            f"{path.name}: every cargo-cache job sets artifact-changing variables only "
            "where the cache step sees them",
            not gaps,
            f"{gaps}: move each to the job's or the workflow's `env:`",
        )
    workflow = next(doc for path, doc in documents if path.name == "ci.yml")
    job_id = next(
        job_id
        for job_id, job in workflow["jobs"].items()
        if any(str(step.get("uses") or "") == RUST_CACHE_ACTION for step in job.get("steps") or [])
    )
    mutated = copy.deepcopy(workflow)
    mutated["jobs"][job_id]["steps"][-1].setdefault("env", {})["RUSTFLAGS"] = "-D warnings"
    check(
        f"a step-level RUSTFLAGS on {job_id} is reported",
        any("step env sets RUSTFLAGS" in gap for gap in artifact_env_gaps(mutated, "ci.yml", texts)),
        f"{artifact_env_gaps(mutated, 'ci.yml', texts)}",
    )
    mutated = copy.deepcopy(workflow)
    mutated["jobs"][job_id]["steps"].append(
        {"name": "planted", "run": "echo 'CARGO_PROFILE_DEV_OPT_LEVEL=0' >> \"$GITHUB_ENV\""}
    )
    check(
        f"a $GITHUB_ENV write of CARGO_PROFILE_DEV_OPT_LEVEL on {job_id} is reported",
        any(
            "writes CARGO_PROFILE_DEV_OPT_LEVEL" in gap
            for gap in artifact_env_gaps(mutated, "ci.yml", texts)
        ),
        f"{artifact_env_gaps(mutated, 'ci.yml', texts)}",
    )
    mutated = copy.deepcopy(workflow)
    mutated["jobs"][job_id]["steps"].append({"uses": "./.github/actions/planted"})
    planted_texts = {**texts, "./.github/actions/planted": 'echo "RUSTFLAGS=-Cplanted" >> "$GITHUB_ENV"'}
    check(
        f"a local action writing RUSTFLAGS to $GITHUB_ENV on {job_id} is reported",
        any("writes RUSTFLAGS" in gap for gap in artifact_env_gaps(mutated, "ci.yml", planted_texts)),
        f"{artifact_env_gaps(mutated, 'ci.yml', planted_texts)}",
    )
    for planted_run, expected in (
        ("cargo test --config 'profile.dev.package.\"*\".opt-level=0'", "passes cargo --config"),
        ("cargo build --config=build.rustflags=['-Cplanted']", "passes cargo --config"),
        ("cargo +nightly build -Zbuild-std", "passes cargo -Zbuild-std"),
    ):
        mutated = copy.deepcopy(workflow)
        mutated["jobs"][job_id]["steps"].append({"name": "planted", "run": planted_run})
        check(
            f"`{planted_run}` on {job_id} is reported",
            any(expected in gap for gap in artifact_env_gaps(mutated, "ci.yml", texts)),
            f"{artifact_env_gaps(mutated, 'ci.yml', texts)}",
        )
    mutated = copy.deepcopy(workflow)
    mutated["jobs"][job_id]["steps"].append(
        {"name": "planted", "run": "bun run lint --config x\nls -Z"}
    )
    check(
        f"--config and -Z on lines that run no cargo on {job_id} are not reported",
        not artifact_env_gaps(mutated, "ci.yml", texts),
        f"{artifact_env_gaps(mutated, 'ci.yml', texts)}",
    )
    mutated = copy.deepcopy(workflow)
    mutated["jobs"][job_id].setdefault("env", {})["RUSTFLAGS"] = "-D warnings"
    check(
        f"a job-level RUSTFLAGS on {job_id}, which the cache step sees, is not reported",
        not artifact_env_gaps(mutated, "ci.yml", texts),
        f"{artifact_env_gaps(mutated, 'ci.yml', texts)}",
    )

    roots = [REPO, REPO / "fuzz"]
    gaps = unkeyed_cargo_config_gaps(roots)
    check("no workspace root's ancestry holds a .cargo/config without .toml", not gaps, f"{gaps}")
    with tempfile.TemporaryDirectory() as scratch:
        planted_root = Path(scratch)
        (planted_root / ".cargo").mkdir()
        (planted_root / ".cargo/config").write_text("[build]\nrustflags = ['-Cplanted']\n")
        check(
            "a planted .cargo/config is reported",
            bool(unkeyed_cargo_config_gaps([planted_root])),
            "unkeyed_cargo_config_gaps missed .cargo/config",
        )


# The step that fetches every crate a job compiles and takes cargo offline, and the
# rule check_offline_cargo holds every workflow job to. See the `offline-cargo` entry
# in this file's docstring.
CARGO_FETCH_ACTION = "./.github/actions/cargo-fetch"
CARGO_FETCH_SCRIPT = REPO / ".github/actions/cargo-fetch/fetch.sh"
CARGO_FETCH_ENV_WRITE = re.compile(
    r"""^printf 'CARGO_NET_OFFLINE=true\\n' >> "\$GITHUB_ENV"$""", re.MULTILINE
)
# INDICATORS of a step that installs a compiler or restores cargo's cache: the fetch
# runs after each of them. rust-cache hashes every `CARGO*` variable its step sees into
# its key, so a fetch before it would put CARGO_NET_OFFLINE into that key.
TOOLCHAIN_OR_CACHE_ACTIONS = (
    "./.github/actions/rust-toolchain",
    "dtolnay/rust-toolchain@",
    RUST_CACHE_ACTION,
)
# An action that runs cargo inside its own step. CodeQL's Rust extractor runs
# `cargo metadata` and the build scripts while it loads the workspace.
CARGO_RUNNING_ACTIONS = (
    "github/codeql-action/init@",
    "github/codeql-action/analyze@",
)
# The command words that resolve this workspace's dependencies through cargo.
CARGO_FAMILY = {"cargo", "maturin", "wasm-pack"}
# A command word in a line shlex cannot split, read anywhere on it, which errs toward
# reporting a step rather than toward passing one.
CARGO_COMMAND = re.compile(r"(?<![\w./$-])(cargo|maturin|wasm-pack)(?![\w-])")
# Tokens after which the shell reads a command word, and words that run the command
# after them (`time cargo build`, `do cargo build`, `env A=1 cargo build`).
SHELL_SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "{", "}", "!", "$", "`", ";;"}
SHELL_PREFIXES = {
    "do", "then", "else", "elif", "if", "while", "until", "exec", "nohup", "sudo",
    "xargs", "env", "nice",
}
TIME_COMMANDS = {"time", "/usr/bin/time"}
TIME_VALUE_FLAGS = {"-f", "-o", "--format", "--output"}
# INDICATORS, not the criterion: the subcommands that may run before the fetch,
# because they read no lockfile (`--version`, `-V`) or need crates.io for a tool this
# workspace's Cargo.lock does not name (`cargo install`).
CARGO_BEFORE_FETCH = {"install", "--version", "-V"}
VERSION_FLAGS = {"--version", "-V"}
# INDICATORS, not the criterion: the cargo subcommands that need the network after
# the fetch took cargo offline, so none may run after it.
CARGO_NEEDS_NETWORK = {"install", "publish", "update", "search", "login", "owner", "yank"}
# The jobs that run cargo with no fetch step, each with the reason. `cargo publish`
# uploads each crate and resolves the next one against the versions it just uploaded,
# which no fetch before the first upload can have downloaded.
OFFLINE_CARGO_EXEMPT = {
    ("release.yml", "publish-crates"): "cargo publish uploads to crates.io",
}


def command_substitutions(line: str) -> list[str]:
    """Return the text inside each `$( … )` on a line, outermost first."""
    found, start = [], line.find("$(")
    while start != -1:
        depth, end = 0, start + 1
        while end < len(line):
            depth += {"(": 1, ")": -1}.get(line[end], 0)
            if depth == 0:
                break
            end += 1
        found.append(line[start + 2 : end])
        start = line.find("$(", start + 2)
    return found


def command_words(line: str) -> list[tuple[str, list[str]]] | None:
    """Return (command word, the tokens after it) for each simple command on a line.

    Reads a command word where the shell does: at the start of the line, after a
    separator, after a keyword or prefix command in SHELL_PREFIXES, after `time` and
    its flags, and after `VAR=value` assignments, and again inside each `$( … )`,
    where `TREE="$(cargo tree …)"` runs cargo. `command -v cargo` looks cargo up and
    runs nothing. Returns None for a line, or a substitution in it, that shlex cannot
    split.
    """
    nested = []
    for inner in command_substitutions(line):
        words = command_words(inner)
        if words is None:
            return None
        nested += words
    line = line.replace("$(", "$ (")
    lexer = shlex.shlex(
        EXPRESSION.sub("EXPRESSION", line), posix=True, punctuation_chars=True
    )
    lexer.whitespace_split = True
    try:
        lexed = list(lexer)
    except ValueError:
        return None
    # shlex joins adjacent punctuation, so `$(seq 60); do docker …` yields `);`, which
    # is no separator, and the docker after `do` went unread. Split each such run of
    # separator characters into separators, longest first.
    tokens = []
    for token in lexed:
        if token in SHELL_SEPARATORS or not re.fullmatch(r"[();&|]+", token):
            tokens.append(token)
            continue
        while token:
            piece = next(
                (s for s in ("&&", "||", ";;") if token.startswith(s)), token[0]
            )
            tokens.append(piece)
            token = token[len(piece) :]
    found = []
    at_start, index = True, 0
    while index < len(tokens):
        token = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else ""
        if not at_start:
            at_start = token in SHELL_SEPARATORS
        elif (
            token in SHELL_SEPARATORS
            or token in SHELL_PREFIXES
            or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token)
        ):
            pass
        elif token in TIME_COMMANDS:
            while index + 1 < len(tokens) and tokens[index + 1].startswith("-"):
                index += 2 if tokens[index + 1] in TIME_VALUE_FLAGS else 1
        elif token == "command" and following.startswith("-"):
            at_start = False
        elif token == "command":
            pass
        else:
            found.append((token, tokens[index + 1 :]))
            at_start = False
        index += 1
    return found + nested


def cargo_invocations(script: str) -> list[tuple[str, str, str]]:
    """Return (line, command word, its subcommand) for each cargo-family command.

    A `+toolchain` after `cargo` is skipped, so `cargo +nightly install` reads as
    `install`. A line shlex cannot split is read with CARGO_COMMAND anywhere on it.
    """
    found = []
    for line in logical_lines(script):
        commands = command_words(line)
        if commands is None:
            commands = [
                (match.group(1), line[match.end() :].split())
                for match in CARGO_COMMAND.finditer(line)
            ]
        for word, rest in commands:
            word = posixpath.basename(word)
            if word not in CARGO_FAMILY:
                continue
            if rest and rest[0].startswith("+"):
                rest = rest[1:]
            found.append((line, word, rest[0] if rest else ""))
    return found


def step_uses(step: dict) -> str:
    return str(step.get("uses") or "")


def is_fetch_step(step: dict) -> bool:
    return step_uses(step) == CARGO_FETCH_ACTION


def is_toolchain_or_cache_step(step: dict) -> bool:
    return step_uses(step).startswith(TOOLCHAIN_OR_CACHE_ACTIONS)


def step_runs_cargo(step: dict) -> bool:
    if step_uses(step).startswith(CARGO_RUNNING_ACTIONS):
        return True
    return bool(cargo_invocations(str(step.get("run") or "")))


def job_runs_cargo(job: dict) -> bool:
    return any(
        is_fetch_step(step) or is_toolchain_or_cache_step(step) or step_runs_cargo(step)
        for step in job.get("steps") or []
    )


def normalised_condition(step: dict) -> str:
    return " ".join(str(step.get("if") or "").split())


def offline_env_gaps(where: str, env: object) -> list[str]:
    if isinstance(env, dict) and "CARGO_NET_OFFLINE" in env:
        return [f"{where}: env sets CARGO_NET_OFFLINE"]
    return []


# A step that builds a container image, so its cargo commands run inside the Dockerfile
# it names, where no fetch step of the job reaches.
DOCKER_BUILD_ACTIONS = ("docker/build-push-action@",)
CARGO_FETCH_SOURCE = ".github/actions/cargo-fetch/fetch.sh"
OFFLINE_FLAGS = {"--offline", "--frozen"}
DOCKER_OFFLINE_ENV = re.compile(r"""(?:^|\s)CARGO_NET_OFFLINE(?:=|\s+)(["']?)true\1(?:\s|$)""")


def dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    """Return (KEYWORD, arguments) for each instruction, continuations joined.

    Docker drops a comment line even inside a continuation, so this reader does too.
    """
    found, pending = [], ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        keyword, _, rest = (pending + stripped).partition(" ")
        found.append((keyword.upper(), rest.strip()))
        pending = ""
    if pending:
        keyword, _, rest = pending.partition(" ")
        found.append((keyword.upper(), rest.strip()))
    return found


def dockerfile_offline_gaps(label: str, text: str) -> list[str]:
    """Return each way one Dockerfile breaks the fetch-then-offline rule.

    CRITERION: in every stage, no cargo-family command runs before the stage, or a
    stage it is built `FROM`, has run the copied-in CARGO_FETCH_SOURCE, except
    `--version`, `cargo chef prepare` and `cargo chef cook --no-build`; the fetch runs
    once per stage chain; and every cargo-family command after it runs under
    `ENV CARGO_NET_OFFLINE=true` or with a flag in OFFLINE_FLAGS. No ENV sets
    CARGO_NET_OFFLINE before the fetch or to anything but `true`. A RUN line shlex
    cannot split is read with CARGO_COMMAND anywhere on it, as cargo_invocations reads
    a workflow line.
    """
    gaps: list[str] = []
    stages: dict[str, tuple[bool, bool]] = {}
    scripts: set[str] = set()
    fetched = offline = False
    current = None
    for keyword, rest in dockerfile_instructions(text):
        flagless = [word for word in rest.split() if not word.startswith("--")]
        if keyword == "FROM":
            base = flagless[0].lower() if flagless else ""
            fetched, offline = stages.get(base, (False, False))
            has_name = len(flagless) >= 3 and flagless[1].lower() == "as"
            current = flagless[2].lower() if has_name else None
        elif keyword == "COPY" and CARGO_FETCH_SOURCE in flagless[:-1]:
            scripts.add(flagless[-1])
        elif keyword == "ENV" and "CARGO_NET_OFFLINE" in rest:
            if not DOCKER_OFFLINE_ENV.search(rest):
                gaps.append(f"{label}: `ENV {rest}` sets CARGO_NET_OFFLINE to other than true")
            elif not fetched:
                gaps.append(f"{label}: `ENV {rest}` comes before the fetch")
            offline = True
        elif keyword == "RUN":
            while rest.startswith("--"):
                rest = rest.partition(" ")[2].lstrip()
            if rest.startswith("["):
                try:
                    rest = shlex.join(json.loads(rest))
                except (ValueError, TypeError):
                    gaps.append(f"{label}: cannot read `RUN {rest}`")
                    continue
            commands = command_words(rest)
            if commands is None:
                # As cargo_invocations does: a cargo word anywhere on a line shlex
                # cannot split is read as a command.
                commands = [
                    (match.group(1), rest[match.end() :].split())
                    for match in CARGO_COMMAND.finditer(rest)
                ]
            for word, tokens in commands:
                runs_script = word in scripts or (
                    posixpath.basename(word) in {"bash", "sh"} and tokens[:1]
                    and tokens[0] in scripts
                )
                if runs_script:
                    if fetched:
                        gaps.append(f"{label}: `RUN {rest}` fetches a second time")
                    fetched = True
                    continue
                word = posixpath.basename(word)
                if word not in CARGO_FAMILY:
                    continue
                if tokens and tokens[0].startswith("+"):
                    tokens = tokens[1:]
                if tokens[:1] and tokens[0] in VERSION_FLAGS:
                    continue
                if not fetched:
                    writes_manifests = word == "cargo" and (
                        tokens[:2] == ["chef", "prepare"]
                        or (tokens[:2] == ["chef", "cook"] and "--no-build" in tokens)
                    )
                    if not writes_manifests:
                        gaps.append(f"{label}: `RUN {rest}` runs before the fetch")
                elif not offline and not OFFLINE_FLAGS & set(tokens):
                    gaps.append(f"{label}: `RUN {rest}` runs online after the fetch")
                if word == "cargo" and tokens[:1] and tokens[0] in CARGO_NEEDS_NETWORK:
                    gaps.append(f"{label}: `RUN {rest}` needs the network")
        if current:
            stages[current] = (fetched, offline)
    return gaps


def docker_build_gaps(label: str, step: dict, dockerfiles: dict[str, str]) -> list[str]:
    """Return the gaps of the Dockerfile one docker/build-push-action step builds."""
    inputs = step.get("with") or {}
    context = str(inputs.get("context") or ".")
    if "://" in context or "${{" in context:
        return [f"{label}: builds context `{context}`, which this check cannot read"]
    path = posixpath.normpath(str(inputs.get("file") or posixpath.join(context, "Dockerfile")))
    if path not in dockerfiles:
        source = REPO / path
        if not source.is_file():
            return [f"{label}: builds `{path}`, which does not exist"]
        dockerfiles[path] = source.read_text()
    return dockerfile_offline_gaps(f"{label}, {path}", dockerfiles[path])


def offline_cargo_gaps(
    name: str, doc: dict, dockerfiles: dict[str, str] | None = None
) -> list[str]:
    """Return each way one workflow's jobs break the fetch-then-offline rule.

    CRITERION: every job that runs cargo, and is not in OFFLINE_CARGO_EXEMPT, has
    exactly one CARGO_FETCH_ACTION step; that step comes after every toolchain and
    rust-cache step; no step before it runs a cargo-family command other than one in
    CARGO_BEFORE_FETCH; no step after it runs one in CARGO_NEEDS_NETWORK; and when the
    fetch carries an `if:`, every later step that runs cargo carries that condition
    too, so no cargo step runs where the fetch skipped. In every job, no `env:` sets
    CARGO_NET_OFFLINE and no `run:` text names it or `net.offline`, so the fetch step's
    `$GITHUB_ENV` write is the one place cargo goes offline. A job runs cargo when it
    has a toolchain, rust-cache or fetch step, or a step that runs a cargo-family
    command or a cargo-running action. Each step that uses a DOCKER_BUILD_ACTIONS
    action adds the gaps dockerfile_offline_gaps finds in the Dockerfile it builds;
    `dockerfiles` maps a repository path to the text to read in place of that file.
    """
    dockerfiles = {} if dockerfiles is None else dockerfiles
    gaps = offline_env_gaps(f"{name}: workflow", doc.get("env"))
    for job_id, job in sorted((doc.get("jobs") or {}).items()):
        label = f"{name}:{job_id}"
        gaps += offline_env_gaps(label, job.get("env"))
        steps = job.get("steps") or []
        for index, step in enumerate(steps):
            step_label = f"{label}, {step.get('name') or f'step {index}'}"
            gaps += offline_env_gaps(step_label, step.get("env"))
            script = str(step.get("run") or "")
            if "CARGO_NET_OFFLINE" in script or "net.offline" in script:
                gaps.append(f"{step_label}: run text sets cargo's offline mode by hand")
            if step_uses(step).startswith(DOCKER_BUILD_ACTIONS):
                gaps += docker_build_gaps(step_label, step, dockerfiles)
        exempt = (name, job_id) in OFFLINE_CARGO_EXEMPT
        if exempt or "uses" in job or not job_runs_cargo(job):
            continue
        fetches = [index for index, step in enumerate(steps) if is_fetch_step(step)]
        if len(fetches) != 1:
            gaps.append(f"{label}: runs cargo with {len(fetches)} cargo-fetch steps, not 1")
            if not fetches:
                continue
        fetch = fetches[0]
        for index, step in enumerate(steps):
            step_label = f"{label}, {step.get('name') or f'step {index}'}"
            if is_toolchain_or_cache_step(step) and index > fetch:
                gaps.append(
                    f"{step_label}: {step_uses(step)} runs after the cargo-fetch step"
                )
            if index < fetch and step_uses(step).startswith(CARGO_RUNNING_ACTIONS):
                gaps.append(f"{step_label}: {step_uses(step)} runs before the fetch")
            for line, word, subcommand in cargo_invocations(str(step.get("run") or "")):
                if index < fetch and not (
                    (word == "cargo" and subcommand in CARGO_BEFORE_FETCH)
                    or subcommand in VERSION_FLAGS
                ):
                    gaps.append(f"{step_label}: `{line}` runs before the fetch")
                if index > fetch and word == "cargo" and subcommand in CARGO_NEEDS_NETWORK:
                    gaps.append(
                        f"{step_label}: `{line}` needs the network after the fetch "
                        f"took cargo offline"
                    )
        condition = normalised_condition(steps[fetch])
        if condition:
            for index, step in enumerate(steps[fetch + 1 :], start=fetch + 1):
                if step_runs_cargo(step) and condition not in normalised_condition(step):
                    gaps.append(
                        f"{label}, {step.get('name') or f'step {index}'}: runs cargo "
                        f"without the fetch's condition `{condition}`"
                    )
    for (workflow, job_id), reason in OFFLINE_CARGO_EXEMPT.items():
        if workflow != name:
            continue
        job = (doc.get("jobs") or {}).get(job_id)
        if job is None or not any(
            word == "cargo" and subcommand == "publish"
            for step in job.get("steps") or []
            for _, word, subcommand in cargo_invocations(str(step.get("run") or ""))
        ):
            gaps.append(
                f"{name}:{job_id}: exempt because {reason}, but runs no `cargo publish`"
            )
    return gaps


def offline_cargo_job(doc: dict, job_id: str) -> tuple[list[dict], int]:
    steps = doc["jobs"][job_id]["steps"]
    return steps, next(index for index, step in enumerate(steps) if is_fetch_step(step))


def check_offline_cargo(documents: list[tuple[Path, dict]]) -> None:
    by_name = {path.name: doc for path, doc in documents}
    for name, doc in sorted(by_name.items()):
        gaps = offline_cargo_gaps(name, doc)
        check(
            f"{name}: every job that runs cargo fetches once, first, then runs offline",
            not gaps,
            f"{gaps}: a cargo command that reaches the registry fails its job when "
            f"index.crates.io does not resolve",
        )
    script = CARGO_FETCH_SCRIPT.read_text()
    check(
        "fetch.sh writes CARGO_NET_OFFLINE=true to $GITHUB_ENV",
        bool(CARGO_FETCH_ENV_WRITE.search(script)),
        f"{CARGO_FETCH_SCRIPT.relative_to(REPO)} no longer takes cargo offline for "
        f"the steps after it, so every job's later cargo commands reach the network",
    )
    check(
        "the fetch-script reader rejects a fetch.sh without the $GITHUB_ENV write",
        not CARGO_FETCH_ENV_WRITE.search(CARGO_FETCH_ENV_WRITE.sub("", script)),
        "the reader matched a fetch.sh with the write removed",
    )

    # Reader controls: the command lines the reader must and must not read as cargo.
    for line, expected in (
        ("cargo clippy --workspace", [("cargo", "clippy")]),
        ('TREE="$(cargo tree -p scp-ffi -i libsqlite3-sys)"', [("cargo", "tree")]),
        ("for pkg in a b; do cargo build -p \"$pkg\"; done", [("cargo", "build")]),
        ('/usr/bin/time -f "${label} wall %e s" cargo build --timings', [("cargo", "build")]),
        ("CARGO_TARGET_DIR=t env A=1 cargo +1.98.0 test", [("cargo", "test")]),
        ("cd bindings/python && maturin develop", [("maturin", "develop")]),
        ("rustc --version; cargo --version", [("cargo", "--version")]),
        ("if PATH=/usr/bin command -v cargo >/dev/null; then", []),
        ('echo "::error::cargo is on PATH"', []),
        ("pip install maturin", []),
    ):
        got = [(word, sub) for _, word, sub in cargo_invocations(line)]
        check(
            f"the offline-cargo reader reads `{line}` as {expected or 'no cargo command'}",
            got == expected,
            f"read {got}",
        )

    # Controls: each fixture below breaks the rule one way and must be reported.
    ci = by_name["ci.yml"]

    def reported(label: str, doc: dict, name: str, needle: str) -> None:
        gaps = offline_cargo_gaps(name, doc)
        check(
            f"offline-cargo control: {label} is reported",
            any(needle in gap for gap in gaps),
            f"no gap containing {needle!r} among {gaps}",
        )

    mutated = copy.deepcopy(ci)
    steps, fetch = offline_cargo_job(mutated, "rust-clippy")
    del steps[fetch]
    reported("rust-clippy with its fetch step removed", mutated, "ci.yml",
             "ci.yml:rust-clippy: runs cargo with 0 cargo-fetch steps")

    mutated = copy.deepcopy(ci)
    steps, fetch = offline_cargo_job(mutated, "rust-clippy")
    later = next(
        index for index in range(fetch + 1, len(steps)) if step_runs_cargo(steps[index])
    )
    steps.insert(fetch, steps.pop(later))
    reported("a rust-clippy cargo step moved before the fetch", mutated, "ci.yml",
             "runs before the fetch")

    mutated = copy.deepcopy(ci)
    steps, fetch = offline_cargo_job(mutated, "rust-clippy")
    cache = max(
        index for index, step in enumerate(steps) if is_toolchain_or_cache_step(step)
    )
    steps.insert(cache, steps.pop(fetch))
    reported("rust-clippy fetching before its rust-cache step", mutated, "ci.yml",
             "runs after the cargo-fetch step")

    mutated = copy.deepcopy(ci)
    steps, fetch = offline_cargo_job(mutated, "rust-clippy")
    steps.insert(fetch, copy.deepcopy(steps[fetch]))
    reported("rust-clippy fetching twice", mutated, "ci.yml",
             "ci.yml:rust-clippy: runs cargo with 2 cargo-fetch steps")

    for where, apply in (
        ("workflow", lambda doc: doc.setdefault("env", {})),
        ("job", lambda doc: doc["jobs"]["rust-clippy"].setdefault("env", {})),
        ("step", lambda doc: offline_cargo_job(doc, "rust-clippy")[0][-1].setdefault("env", {})),
    ):
        mutated = copy.deepcopy(ci)
        apply(mutated)["CARGO_NET_OFFLINE"] = "true"
        reported(f"a {where}-level CARGO_NET_OFFLINE", mutated, "ci.yml",
                 "env sets CARGO_NET_OFFLINE")

    mutated = copy.deepcopy(ci)
    steps, fetch = offline_cargo_job(mutated, "rust-clippy")
    steps.insert(fetch + 1, {"run": 'echo "CARGO_NET_OFFLINE=false" >> "$GITHUB_ENV"'})
    reported("a step turning cargo back online", mutated, "ci.yml",
             "run text sets cargo's offline mode by hand")

    mutated = copy.deepcopy(ci)
    steps, fetch = offline_cargo_job(mutated, "rust-clippy")
    steps.insert(fetch + 1, {"run": "cargo +1.98.0 install cargo-nextest --locked"})
    reported("a cargo install after the fetch", mutated, "ci.yml",
             "needs the network after the fetch")

    mutated = copy.deepcopy(ci)
    steps, fetch = offline_cargo_job(mutated, "rust-clippy")
    steps[fetch]["if"] = "steps.artifact-cache.outputs.cache-hit != 'true'"
    reported("a guarded fetch with an unguarded later cargo step", mutated, "ci.yml",
             "without the fetch's condition")

    mutated = copy.deepcopy(ci)
    mutated["jobs"]["fixture-raw-cargo"] = {
        "runs-on": "ubuntu-latest",
        "steps": [{"uses": "actions/checkout@v5"}, {"run": "cargo build --workspace"}],
    }
    reported("a job running cargo with no toolchain step and no fetch", mutated, "ci.yml",
             "ci.yml:fixture-raw-cargo: runs cargo with 0 cargo-fetch steps")

    for name, job_id in (
        ("build-matrix.yml", "python-wheels"),
        ("fuzz.yml", "fuzz-nightly"),
        ("codeql.yml", "analyze"),
    ):
        mutated = copy.deepcopy(by_name[name])
        steps, fetch = offline_cargo_job(mutated, job_id)
        del steps[fetch]
        reported(f"{name}:{job_id} with its fetch step removed", mutated, name,
                 f"{name}:{job_id}: runs cargo with 0 cargo-fetch steps")

    mutated = copy.deepcopy(by_name["release.yml"])
    mutated["jobs"]["publish-crates"]["steps"] = [
        step for step in mutated["jobs"]["publish-crates"]["steps"]
        if "cargo publish" not in str(step.get("run") or "")
    ]
    reported("an exemption naming a job that no longer publishes", mutated, "release.yml",
             "runs no `cargo publish`")

    # Dockerfile controls: the reader, then the image the docker-image job builds,
    # broken one way at a time.
    read = dockerfile_instructions("RUN a \\\n# note\n    && b\nENV X=1\n")
    check(
        "the Dockerfile reader joins a continuation and drops a comment line inside it",
        read == [("RUN", "a  && b"), ("ENV", "X=1")],
        f"read {read}",
    )
    dockerfile = (REPO / "Dockerfile").read_text()
    fetch_run = next(
        line for line in dockerfile.splitlines()
        if line.startswith("RUN ") and "cargo-fetch.sh" in line
    )
    offline_env = "ENV CARGO_NET_OFFLINE=true\n"
    for label, text, needle in (
        ("a Dockerfile with its fetch removed",
         dockerfile.replace(fetch_run + "\n", ""), "runs before the fetch"),
        ("a Dockerfile that runs the fetch script without copying it in",
         "\n".join(line for line in dockerfile.splitlines()
                   if not (line.startswith("COPY ") and CARGO_FETCH_SOURCE in line)),
         "runs before the fetch"),
        ("a Dockerfile building online after the fetch",
         dockerfile.replace(offline_env, "").replace(" --offline", ""),
         "runs online after the fetch"),
        ("a Dockerfile setting CARGO_NET_OFFLINE before the fetch",
         dockerfile.replace(offline_env, "").replace(fetch_run, offline_env + fetch_run),
         "comes before the fetch"),
        ("a Dockerfile running cargo before the fetch on a line shlex cannot split",
         dockerfile.replace(fetch_run, "RUN a=\"$(printf '\"')\"; cargo build --release\n"
                            + fetch_run),
         "runs before the fetch"),
        ("a Dockerfile fetching twice",
         dockerfile.replace(fetch_run, fetch_run + "\n" + fetch_run),
         "fetches a second time"),
    ):
        check(f"offline-cargo control: {label} differs from the Dockerfile",
              text != dockerfile, "the mutation changed nothing")
        gaps = offline_cargo_gaps("ci.yml", ci, {"Dockerfile": text})
        check(
            f"offline-cargo control: {label} is reported",
            any(needle in gap and "docker-image" in gap for gap in gaps),
            f"no docker-image gap containing {needle!r} among {gaps}",
        )
    mutated = copy.deepcopy(ci)
    build = next(
        step for step in mutated["jobs"]["docker-image"]["steps"]
        if step_uses(step).startswith(DOCKER_BUILD_ACTIONS)
    )
    build.setdefault("with", {})["file"] = "fixture/Missing.Dockerfile"
    reported("a docker-image job building a Dockerfile that does not exist", mutated,
             "ci.yml", "fixture/Missing.Dockerfile`, which does not exist")


# PyO3's build script runs the interpreter PYO3_PYTHON names, or the first `python3` on
# PATH when PYO3_PYTHON is unset, and fails the build when that interpreter is newer than
# the newest version the locked pyo3 supports. A runner image moves its default Python
# on its own schedule, so a job that compiles pyo3 pins the interpreter itself. See the
# `pinned-python` entry in this file's docstring.
PINNED_PYTHON_VERSION = "3.12"
SETUP_PYTHON_ACTION = "actions/setup-python@"
PYO3_CRATES = {"pyo3", "pyo3-ffi", "pyo3-build-config"}
PYTHON_PATH_OUTPUT = re.compile(r"^\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.python-path\s*\}\}$")
PYO3_ENV_WRITE = re.compile(
    r"""PYO3_PYTHON=(?P<value>\$\{\{[^}]*\}\}|[^\s"'>]+)["']?\s*>>\s*["']?\$\{?GITHUB_ENV\}?"""
)
# INDICATORS, not the criterion: the cargo subcommands that compile the packages they
# select and so run their build scripts. `cargo tree`, `metadata`, `fetch`, `deny` and
# `fmt` read manifests or sources and run no build script.
CARGO_COMPILING = {
    "build", "b", "check", "c", "clippy", "doc", "d", "test", "t", "bench", "run", "r",
    "rustc", "rustdoc", "fix", "nextest", "llvm-cov", "llvm-lines", "miri", "mutants",
    "hack", "publish",
}
MATURIN_COMPILING = {"build", "develop", "publish"}
CODEQL_ACTIONS = ("github/codeql-action/init@", "github/codeql-action/analyze@",
                  "github/codeql-action/autobuild@")


def is_dynamic(text: str) -> bool:
    """True for a word whose value only the runner knows: a variable or an expression."""
    return "$" in text or "EXPRESSION" in text or any(c in text for c in "*?[")


@functools.cache
def cargo_workspace() -> tuple[dict[str, str], frozenset[str], frozenset[str]]:
    """Return (member directory -> package name, default-member names, pyo3 packages).

    A package is a pyo3 package when any dependency table of its manifest, target
    tables included, names a crate in PYO3_CRATES or another pyo3 package.
    """
    root = tomllib.loads((REPO / "Cargo.toml").read_text())["workspace"]
    members: dict[str, str] = {}
    depends: dict[str, set[str]] = {}
    for member in root["members"]:
        manifest = tomllib.loads((REPO / member / "Cargo.toml").read_text())
        name = manifest["package"]["name"]
        members[posixpath.normpath(member)] = name
        depends[name] = manifest_dependencies(manifest)
    pyo3: set[str] = set()
    while True:
        grown = {name for name, deps in depends.items() if deps & (PYO3_CRATES | pyo3)}
        if grown <= pyo3:
            break
        pyo3 |= grown
    defaults = root.get("default-members", root["members"])
    return (
        members,
        frozenset(members[posixpath.normpath(path)] for path in defaults),
        frozenset(pyo3),
    )


def manifest_dependencies(manifest: dict) -> set[str]:
    """Return every package name a manifest's dependency tables name, renames resolved."""
    tables = [manifest]
    tables += [t for t in (manifest.get("target") or {}).values() if isinstance(t, dict)]
    found: set[str] = set()
    for table in tables:
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in (table.get(key) or {}).items():
                found.add(spec.get("package", name) if isinstance(spec, dict) else name)
    return found


def directory_compiles_pyo3(directory: str | None) -> bool:
    """True when cargo run with no package flag in `directory` compiles pyo3.

    `directory` is relative to the repository root, or None when unknown. Cargo reads
    the nearest Cargo.toml at or above it: the root manifest builds the default members,
    a member manifest builds that member, and any other manifest builds what it names.
    """
    if directory is None:
        return True
    members, defaults, pyo3 = cargo_workspace()
    directory = posixpath.normpath(directory)
    if directory.startswith(("/", "..")):
        return False
    while True:
        if directory in (".", ""):
            return bool(defaults & pyo3)
        if directory in members:
            return members[directory] in pyo3
        manifest = REPO / directory / "Cargo.toml"
        if manifest.is_file():
            deps = manifest_dependencies(tomllib.loads(manifest.read_text()))
            return bool(deps & (PYO3_CRATES | pyo3))
        directory = posixpath.dirname(directory)


def manifest_directory(cwd: str | None, manifest: str) -> str | None:
    if cwd is None or is_dynamic(manifest):
        return None
    return posixpath.dirname(posixpath.normpath(posixpath.join(cwd, manifest)))


def cargo_compiles_pyo3(tokens: list[str], cwd: str | None) -> bool:
    """True when one cargo command line, the tokens after `cargo`, compiles pyo3.

    A subcommand outside CARGO_COMPILING compiles nothing. Otherwise the command
    compiles pyo3 when it selects a pyo3 package with `-p`/`--package`, or a package
    word it cannot read; when it passes `--workspace` or `--all` and excludes none of
    the pyo3 packages; or, with neither, when the manifest it reads (`--manifest-path`,
    else the nearest one at or above the working directory) builds one.
    """
    if tokens and tokens[0].startswith("+"):
        tokens = tokens[1:]
    if not tokens:
        return False
    subcommand = tokens[0]
    if not is_dynamic(subcommand) and subcommand not in CARGO_COMPILING:
        return False
    workspace, packages, excluded, manifest = False, [], set(), None
    index = 1
    while index < len(tokens) and tokens[index] != "--":
        token = tokens[index]
        value = tokens[index + 1] if index + 1 < len(tokens) else ""
        if token in ("--workspace", "--all"):
            workspace = True
        elif token in ("-p", "--package"):
            packages.append(value)
            index += 1
        elif token.startswith("--package="):
            packages.append(token.partition("=")[2])
        elif token.startswith("-p") and len(token) > 2 and not token.startswith("--"):
            packages.append(token[2:])
        elif token == "--exclude":
            excluded.add(value)
            index += 1
        elif token.startswith("--exclude="):
            excluded.add(token.partition("=")[2])
        elif token == "--manifest-path":
            manifest = value
            index += 1
        elif token.startswith("--manifest-path="):
            manifest = token.partition("=")[2]
        index += 1
    _, _, pyo3 = cargo_workspace()
    if packages:
        return any(is_dynamic(p) or p.partition("@")[0] in pyo3 for p in packages)
    if workspace:
        return bool(pyo3 - {e for e in excluded if not is_dynamic(e)})
    directory = cwd if manifest is None else manifest_directory(cwd, manifest)
    return directory_compiles_pyo3(directory)


def names_interpreters(tokens: list[str]) -> bool:
    """True when maturin arguments name the interpreters to build for with `-i`."""
    return any(
        token in ("-i", "--interpreter") or token.startswith("--interpreter=")
        for token in tokens
    )


def maturin_compiles_pyo3(tokens: list[str], cwd: str | None) -> bool:
    """True when `maturin <tokens>` compiles pyo3 for an interpreter it does not name.

    maturin builds the crate its manifest names. With `-i`/`--interpreter` it builds
    for each interpreter named and hands pyo3 that one, so no ambient Python is read.

    The manifest is `-m`/`--manifest-path`, else `[tool.maturin] manifest-path` of the
    working directory's pyproject.toml, else the working directory's Cargo.toml.
    """
    if not tokens or (not is_dynamic(tokens[0]) and tokens[0] not in MATURIN_COMPILING):
        return False
    if names_interpreters(tokens):
        return False
    for index, token in enumerate(tokens):
        if token in ("-m", "--manifest-path") and index + 1 < len(tokens):
            return directory_compiles_pyo3(manifest_directory(cwd, tokens[index + 1]))
        if token.startswith("--manifest-path="):
            return directory_compiles_pyo3(
                manifest_directory(cwd, token.partition("=")[2])
            )
    if cwd is None:
        return True
    pyproject = REPO / cwd / "pyproject.toml"
    if pyproject.is_file():
        tool = tomllib.loads(pyproject.read_text()).get("tool", {}).get("maturin", {})
        if "manifest-path" in tool:
            return directory_compiles_pyo3(manifest_directory(cwd, tool["manifest-path"]))
    return directory_compiles_pyo3(cwd)


def start_directory(job: dict, step: dict) -> str | None:
    """The directory, relative to the repository root, a step's `run:` starts in."""
    directory = step.get("working-directory") or (
        ((job.get("defaults") or {}).get("run") or {}).get("working-directory")
    )
    if directory is None:
        return "."
    directory = str(directory)
    if directory.startswith("${{") and "github.workspace" in directory:
        directory = "." + directory.split("}}", 1)[1]
    if "${{" in directory or "$" in directory:
        return None
    return posixpath.normpath(directory)


def script_compiles_pyo3(script: str, cwd: str | None) -> bool:
    """True when a `run:` script compiles pyo3 through cargo or maturin.

    Reads each simple command in order and follows `cd` and `pushd`.
    """
    for line in logical_lines(script):
        commands = command_words(line)
        if commands is None:
            commands = [
                (match.group(1), line[match.end() :].split())
                for match in CARGO_COMMAND.finditer(line)
            ]
        for word, tokens in commands:
            base = posixpath.basename(word)
            if base in ("cd", "pushd"):
                target = tokens[0] if tokens else "."
                if target.startswith(("$GITHUB_WORKSPACE", "${GITHUB_WORKSPACE}")):
                    cwd = "."
                elif is_dynamic(target) or cwd is None:
                    cwd = None
                else:
                    cwd = posixpath.normpath(posixpath.join(cwd, target))
            elif (base == "cargo" and cargo_compiles_pyo3(tokens, cwd)) or (
                base == "maturin" and maturin_compiles_pyo3(tokens, cwd)
            ):
                return True
    return False


def job_matrix_values(job: dict) -> set[str]:
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    values: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif node is not None:
            values.add(str(node))

    walk(matrix)
    return values


def step_compiles_pyo3(job: dict, step: dict) -> bool:
    """True when one step runs pyo3's build script.

    CRITERION: the step's `run:` text runs a cargo or maturin command that compiles a
    package depending on pyo3 (cargo_compiles_pyo3, maturin_compiles_pyo3); or it is a CodeQL step for a job whose analysed
    languages include rust, whose extractor runs the workspace's build scripts.
    """
    uses = step_uses(step)
    inputs = step.get("with") or {}
    if uses.startswith(CODEQL_ACTIONS):
        languages = str(inputs.get("languages") or "")
        if "${{" in languages:
            return "rust" in job_matrix_values(job)
        return "rust" in re.split(r"[\s,]+", languages)
    script = str(step.get("run") or "")
    return bool(script) and script_compiles_pyo3(script, start_directory(job, step))


def python_setup_version_key(step: dict) -> str | None:
    """The input naming the Python version a setup step installs, or None for any other step.

    The workflows set Python up through TOOLCACHE_ACTION with `tool: python`, which runs
    setup-python and passes `version` through as its `python-version`.
    """
    uses = step_uses(step)
    if uses.startswith(SETUP_PYTHON_ACTION):
        return "python-version"
    if uses == TOOLCACHE_ACTION and str((step.get("with") or {}).get("tool")) == "python":
        return "version"
    return None


def pinned_setup_steps(steps: list[dict], before: int) -> dict[str, int]:
    """Return {id or '': index} of each unconditional setup-python 3.12 step before `before`."""
    found: dict[str, int] = {}
    for index, step in enumerate(steps[:before]):
        key = python_setup_version_key(step)
        if key is None or step.get("if"):
            continue
        version = str((step.get("with") or {}).get(key) or "").strip()
        if version == PINNED_PYTHON_VERSION:
            found[str(step.get("id") or "")] = index
    return found


def job_runs_on_windows(job: dict) -> bool:
    return "windows" in str(job.get("runs-on") or "") or any(
        "windows" in value for value in job_matrix_values(job)
    )


def pyo3_python_gaps(label: str, doc: dict, job: dict, steps: list[dict], index: int) -> list[str]:
    """Return why PYO3_PYTHON, as step `index` sees it, does not name the pinned interpreter.

    PYO3_PYTHON reaches a step from its own `env:`, its job's, the workflow's, or the
    latest earlier unconditional step that writes it to `$GITHUB_ENV`. Each of those
    that sets it must name the interpreter, so the verdict does not depend on which one
    GitHub gives precedence, and at least one must set it. A value names the interpreter
    when it is the `python-path` output of an unconditional setup-python
    PINNED_PYTHON_VERSION step before the step that reads or writes it, or, except on a
    Windows runner, where setup-python installs no `python3.12` command, the literal
    `python3.12`.
    """
    pinned = pinned_setup_steps(steps, index)
    windows = job_runs_on_windows(job)
    sources: list[tuple[str, str, int]] = []
    for where, env in (("step", steps[index].get("env")), ("job", job.get("env")),
                       ("workflow", doc.get("env"))):
        if isinstance(env, dict) and "PYO3_PYTHON" in env:
            sources.append((f"{where} env", str(env["PYO3_PYTHON"]), index))
    for earlier in range(index - 1, -1, -1):
        if steps[earlier].get("if"):
            continue
        match = PYO3_ENV_WRITE.search(str(steps[earlier].get("run") or ""))
        if match:
            sources.append((f"$GITHUB_ENV write of step {earlier}", match.group("value"), earlier))
            break
    if not sources:
        return [f"{label}: compiles pyo3 with PYO3_PYTHON unset"]
    gaps = []
    for where, value, limit in sources:
        output = PYTHON_PATH_OUTPUT.match(value.strip())
        if output and output.group(1) in pinned and pinned[output.group(1)] < limit:
            continue
        if not output and value.strip() == f"python{PINNED_PYTHON_VERSION}" and not windows:
            continue
        gaps.append(
            f"{label}: PYO3_PYTHON from the {where} is `{value}`, which names no "
            f"unconditional setup-python {PINNED_PYTHON_VERSION} interpreter before it"
            + (" (a Windows runner has no python3.12 command)" if windows else "")
        )
    return gaps


def pinned_python_gaps(name: str, doc: dict) -> list[str]:
    """Return each step that compiles pyo3 without the pinned interpreter.

    CRITERION: in every job, every step that compiles pyo3
    (step_compiles_pyo3) comes after an unconditional `actions/setup-python` step whose
    `python-version` is exactly PINNED_PYTHON_VERSION, and runs with PYO3_PYTHON naming
    that interpreter (pyo3_python_gaps).
    """
    gaps: list[str] = []
    for job_id, job in sorted((doc.get("jobs") or {}).items()):
        if "uses" in job:
            continue
        steps = job.get("steps") or []
        for index, step in enumerate(steps):
            if not step_compiles_pyo3(job, step):
                continue
            label = f"{name}:{job_id}, {step.get('name') or f'step {index}'}"
            if not pinned_setup_steps(steps, index):
                gaps.append(
                    f"{label}: compiles pyo3 with no unconditional setup-python "
                    f"{PINNED_PYTHON_VERSION} step before it"
                )
            gaps += pyo3_python_gaps(label, doc, job, steps, index)
    return gaps


def check_pinned_python(documents: list[tuple[Path, dict]]) -> None:
    by_name = {path.name: doc for path, doc in documents}
    for name, doc in sorted(by_name.items()):
        gaps = pinned_python_gaps(name, doc)
        check(
            f"{name}: every step compiling pyo3 runs on a pinned Python "
            f"{PINNED_PYTHON_VERSION} that PYO3_PYTHON names",
            not gaps,
            f"{gaps}: pyo3's build script reads the runner image's default Python, "
            f"and fails once the image moves it past the newest version pyo3 supports",
        )
    _, _, pyo3 = cargo_workspace()
    check(
        "the pinned-python reader finds scp-ffi among the packages depending on pyo3",
        "scp-ffi" in pyo3,
        f"read {sorted(pyo3)}",
    )

    # Reader controls: commands that do and do not compile pyo3.
    for line, cwd, expected in (
        ("cargo build --workspace", ".", True),
        ("cargo +1.98.0 clippy --all-targets", ".", True),
        ("cargo test -p scp-ffi --features testing", ".", True),
        ("cargo nextest run --package=scp-ffi", ".", True),
        ('cargo build -p "$pkg"', ".", True),
        ("cargo build --manifest-path crates/scp-ffi/Cargo.toml", ".", True),
        ("cargo doc", "crates/scp-ffi/src", True),
        ("cd bindings/python && maturin develop --features testing", ".", True),
        ("cargo build -p scp-ffi-napi --release", ".", False),
        ("cargo build --workspace --exclude scp-ffi", ".", False),
        ("cargo tree --workspace -e features", ".", False),
        ("cargo check --locked", "fuzz", False),
        ("cargo build --release", "crates/scp-crypto", False),
        ("maturin build --out dist -i python3.10 python3.12", "bindings/python", False),
        ("maturin sdist", "bindings/python", False),
    ):
        got = script_compiles_pyo3(line, cwd)
        check(
            f"the pinned-python reader reads `{line}` in {cwd} as "
            f"{'compiling' if expected else 'not compiling'} pyo3",
            got == expected,
            f"read {got}",
        )

    # Controls: each fixture below breaks the rule one way and must be reported.
    def reported(label: str, name: str, doc: dict, needle: str) -> None:
        gaps = pinned_python_gaps(name, doc)
        check(
            f"pinned-python control: {label} is reported",
            any(needle in gap for gap in gaps),
            f"no gap containing {needle!r} among {gaps}",
        )

    def not_reported(label: str, name: str, doc: dict) -> None:
        gaps = pinned_python_gaps(name, doc)
        check(f"pinned-python control: {label} is not reported", not gaps, f"{gaps}")

    def rust_docs(doc: dict) -> tuple[list[dict], int, int]:
        steps = doc["jobs"]["rust-docs"]["steps"]
        setup = next(i for i, s in enumerate(steps) if python_setup_version_key(s))
        writer = next(i for i, s in enumerate(steps) if PYO3_ENV_WRITE.search(str(s.get("run") or "")))
        return steps, setup, writer

    docs = by_name["docs.yml"]
    mutated = copy.deepcopy(docs)
    steps, setup, _ = rust_docs(mutated)
    del steps[setup]
    reported("docs.yml rust-docs with its setup-python step removed", "docs.yml", mutated,
             "no unconditional setup-python 3.12 step before it")

    mutated = copy.deepcopy(docs)
    steps, _, writer = rust_docs(mutated)
    del steps[writer]
    reported("docs.yml rust-docs with its PYO3_PYTHON write removed", "docs.yml", mutated,
             "compiles pyo3 with PYO3_PYTHON unset")

    mutated = copy.deepcopy(docs)
    steps, setup, _ = rust_docs(mutated)
    steps[setup]["with"][python_setup_version_key(steps[setup])] = "3.14"
    reported("docs.yml rust-docs pinned to 3.14", "docs.yml", mutated,
             "no unconditional setup-python 3.12 step before it")

    mutated = copy.deepcopy(docs)
    steps, setup, _ = rust_docs(mutated)
    steps[setup]["if"] = "github.event_name == 'push'"
    reported("docs.yml rust-docs with a conditional setup-python step", "docs.yml", mutated,
             "no unconditional setup-python 3.12 step before it")

    mutated = copy.deepcopy(docs)
    steps, _, writer = rust_docs(mutated)
    steps.append(steps.pop(writer))
    reported("docs.yml rust-docs writing PYO3_PYTHON after cargo doc", "docs.yml", mutated,
             "compiles pyo3 with PYO3_PYTHON unset")

    ci = by_name["ci.yml"]
    mutated = copy.deepcopy(ci)
    mutated["env"].pop("PYO3_PYTHON", None)
    reported("ci.yml without its workflow-level PYO3_PYTHON", "ci.yml", mutated,
             "ci.yml:rust-clippy, Run clippy over the workspace: compiles pyo3 with "
             "PYO3_PYTHON unset")

    mutated = copy.deepcopy(ci)
    mutated["env"]["PYO3_PYTHON"] = "python3"
    reported("ci.yml with PYO3_PYTHON naming the image's python3", "ci.yml", mutated,
             "PYO3_PYTHON from the workflow env is `python3`")

    mutated = copy.deepcopy(by_name["build-matrix.yml"])
    mutated["jobs"]["rust"]["env"] = {"PYO3_PYTHON": "python3.12"}
    reported("build-matrix.yml rust, which has a Windows leg, naming python3.12",
             "build-matrix.yml", mutated, "a Windows runner has no python3.12 command")

    mutated = copy.deepcopy(by_name["codeql.yml"])
    mutated["jobs"]["analyze"]["steps"] = [
        step for step in mutated["jobs"]["analyze"]["steps"]
        if not python_setup_version_key(step)
        and not PYO3_ENV_WRITE.search(str(step.get("run") or ""))
    ]
    reported("codeql.yml analyze, whose Rust leg runs build scripts, with no pin",
             "codeql.yml", mutated, "codeql.yml:analyze")

    fixture = {"runs-on": "ubuntu-latest", "steps": [{"uses": "actions/checkout@v5"}]}
    for label, step, expected in (
        ("a workspace build", {"run": "cargo build --workspace"}, True),
        ("a default-member clippy run", {"run": "cargo clippy --all-targets"}, True),
        ("a test of scp-ffi", {"run": "cargo test -p scp-ffi"}, True),
        ("a maturin develop", {"working-directory": "bindings/python",
                               "run": "maturin develop"}, True),
        ("a build of scp-ffi-napi alone", {"run": "cargo build -p scp-ffi-napi"}, False),
        ("a fuzz-workspace check", {"working-directory": "fuzz", "run": "cargo check"}, False),
    ):
        mutated = {"jobs": {"fixture": copy.deepcopy(fixture)}}
        mutated["jobs"]["fixture"]["steps"].append(step)
        if expected:
            reported(f"an unpinned job running {label}", "fixture.yml", mutated,
                     "fixture.yml:fixture")
        else:
            not_reported(f"an unpinned job running {label}", "fixture.yml", mutated)
    mutated = {"env": {"PYO3_PYTHON": "python3.12"}, "jobs": {"fixture": copy.deepcopy(fixture)}}
    mutated["jobs"]["fixture"]["steps"] += [
        {"uses": TOOLCACHE_ACTION, "with": {"tool": "python", "version": "3.12"}},
        {"run": "cargo build --workspace"},
    ]
    not_reported("a pinned job running a workspace build", "fixture.yml", mutated)


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
    "uniffi-cdylib-linux": (
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
        {
            "napi-addon",
            "pyo3-module",
            "pyo3-module-macos",
            "uniffi-cdylib-linux",
            "xcframework",
        }
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
    below a comment indented as a job key, and writes the same digest when only a
    whole-line comment or a blank line changes in either.

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
        # Whole-line comments and blank lines change no build, so adding them to
        # the env: range, to the job and to the comment block that heads the next
        # job leaves the digest alone.
        jobs_at = workflow.index("\njobs:\n")
        next_job = workflow.index("\n  ", workflow.index(header) + len(header))
        while not re.match(r"\n  [^ #]", workflow[next_job:]):
            next_job = workflow.index("\n  ", next_job + 1)
        commented = (
            workflow[:jobs_at]
            + "\n# probe comment\n\n"
            + workflow[jobs_at:next_job]
            + "\n    # probe comment\n\n  # probe comment heading the next job"
            + workflow[next_job:]
        ).replace(header, f"{header}    # probe comment\n", 1)
        _, commented_output = run_artifact_inputs_step(
            step, job_id, None, workflow=commented
        )
        check(
            f"{job_id}: a comment or blank line in the env: block or the job leaves "
            f"the digest unchanged",
            commented != workflow and commented_output == output,
            f"adding comments and blank lines moved the digest from {output!r} to "
            f"{commented_output!r}",
        )
        # Control: the step without its comment-and-blank-line skip is reported.
        hashes_comments = script.replace(
            " found && /^[[:space:]]*(#|$)/ {next}", ""
        )
        _, plain_comments = run_artifact_inputs_step(
            step, job_id, None, script=hashes_comments
        )
        _, commented_comments = run_artifact_inputs_step(
            step, job_id, None, script=hashes_comments, workflow=commented
        )
        check(
            f"{job_id}: a step that hashes comments is reported",
            hashes_comments != script and plain_comments != commented_comments,
            "a step that hashes comments still kept the digest across a comment edit",
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
# zero-byte output (uniffi-cdylib-linux's two paths are files; the xcframework's
# include directories).
MULTI_PATH_PRODUCERS = (
    (
        "xcframework",
        "swift-xcframework-dev",
        "xcframework-build-start",
        ("bindings/swift/Sources/SCP/Internal/ScpBindings.swift",),
        False,
    ),
    ("uniffi-cdylib-linux", "uniffi-kotlin-linux", "uniffi-kotlin-build-start", (), True),
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
    for step in mutated["jobs"]["uniffi-cdylib-linux"]["steps"]:
        if (step.get("with") or {}).get("name") == "uniffi-kotlin-linux":
            step["with"]["path"] = step["with"]["path"].split()[0]
    gaps = multi_path_producer_gaps(mutated)
    check(
        "uniffi-cdylib-linux uploading one path is reported as extra in the tuple",
        gaps
        == [
            (
                "uniffi-cdylib-linux is in MULTI_PATH_PRODUCERS and has no upload "
                "listing several paths"
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
    checkout always supplies a match, and a build that writes one of
    uniffi-cdylib-linux's two paths satisfies the option, so the option alone cannot
    fail either producer.
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
    a `Swatinem/rust-cache` step (direct or through the wrapper, its name read in any
    case as action_name reads it) whose `save-if` is not the literal false, an
    `actions/cache` or `actions/cache/save` step, a `gradle/actions/setup-gradle`
    step that neither disables its cache nor sets `cache-read-only` to the literal
    true without a `cache-write-only` that overrides it (it writes on the default
    branch by default), a step exporting a layer
    cache through `cache-to`, an `oven-sh/setup-bun` step that does not set
    `no-cache` to the literal true (it caches the bun executable by default), and
    a setup action given a `cache:` input. An input
    written as an expression counts as writing, so an unreadable input errs toward
    holding the job on push rather than toward skipping a writer.
    """
    uses = str(step.get("uses") or "")
    action = uses.rstrip("/") if uses.startswith("./") else action_name(uses)
    inputs = step_inputs(step)

    def literal(name: str) -> str:
        return str(inputs.get(name, "")).strip().lower()

    if action in (RUST_CACHE_ACTION, RUST_CACHE_UPSTREAM):
        if literal("save-if") == "false":
            return None
        return f"rust-cache `{inputs.get('shared-key')}`"
    if action in ("actions/cache", "actions/cache/save"):
        return f"{action} `{inputs.get('key')}`"
    if action == "gradle/actions/setup-gradle":
        # `cache-write-only` overrides `cache-read-only` (setup-gradle action.yml).
        write_only = literal("cache-write-only") not in ("", "false")
        if literal("cache-disabled") == "true" or (
            literal("cache-read-only") == "true" and not write_only
        ):
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
# GitHub Actions reads context and property names, and compares strings with
# `==`, without regard to case, so every pattern that reads a `matrix`,
# `strategy` or `runner` reference matches in any case, and a name it captures
# is looked up in any case (matrix_key).
SAVE_IF_MATRIX = re.compile(r"matrix\.([\w-]+)\s*==\s*'?([\w.-]+)'?", re.IGNORECASE)
# A matrix axis a cache key expands, so that each value of the axis writes its own
# entry: `shared-key: transport-optional-${{ matrix.group }}`.
KEY_MATRIX_AXIS = re.compile(r"\$\{\{\s*matrix\.([\w-]+)\s*\}\}", re.IGNORECASE)
# A key that names the runner's platform, so each runner writes its own entry.
# Swatinem/rust-cache puts the platform into every key without the text naming it.
KEY_RUNNER = re.compile(r"\brunner\.(?:os|arch)\b", re.IGNORECASE)


class AmbiguousMatrixKey(ValueError):
    """Two matrix keys differ only in case, so a reference names neither for certain."""


def matrix_key(name: str, keys) -> str | None:
    """Return the key of `keys` that `name` names in any case.

    Returns None when no key matches, a state the caller may skip. Raises
    AmbiguousMatrixKey when two or more keys match, which the caller reports.
    """
    found = [key for key in keys if str(key).lower() == name.lower()]
    if len(found) > 1:
        raise AmbiguousMatrixKey(
            f"`matrix.{name}` names each of {sorted(map(str, found))}, matrix keys "
            f"that differ only in case"
        )
    return found[0] if found else None


def axis_event_values(values: object) -> dict[str, list] | None:
    """Return the values one matrix axis runs, as {"push": [...], "other": [...]}.

    A literal list runs on every event. A PUSH_MATRIX expression runs its first
    list on push and its second on pull_request and merge_group. Any other value
    returns None.
    """
    if isinstance(values, list):
        return {"push": values, "other": values}
    chosen = PUSH_MATRIX.match(str(values))
    if chosen is None:
        return None
    push_values, other_values = (json.loads(group) for group in chosen.groups())
    return {"push": push_values, "other": other_values}


def axis_terms(condition: object) -> tuple[str, list[str]] | None:
    """Read a step `if:` that picks legs of one matrix axis by value.

    Returns (axis, values) when the condition, with or without the `${{ … }}`
    wrapper, is `matrix.<axis> == '<value>'` or an `||` of such comparisons that
    all name one axis. Returns None for every other condition, including an empty
    one, so a caller can report what it cannot read.
    """
    text = str(condition or "").strip()
    wrapped = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.DOTALL)
    text = (wrapped.group(1) if wrapped else text).strip()
    if not text:
        return None
    try:
        tree = parse_condition(text)
    except ValueError:
        return None

    def disjuncts(node: tuple) -> list[tuple]:
        if node[0] == "or":
            return [leaf for part in node[1] for leaf in disjuncts(part)]
        return [node]

    axes: set[str] = set()
    values: list[str] = []
    for leaf in disjuncts(tree):
        if leaf[0] != "==":
            return None
        axis = re.fullmatch(r"matrix\.([A-Za-z0-9_-]+)", leaf[1], re.IGNORECASE)
        value = re.fullmatch(r"'([^']*)'", leaf[2])
        if axis is None or value is None:
            return None
        axes.add(axis.group(1))
        values.append(value.group(1))
    if len(axes) != 1:
        return None
    return axes.pop(), values


# The lines of a `run:` script that leg_commands counts as a command: a cargo
# invocation, or a bash script a job starts.
LEG_COMMAND_PREFIXES = ("cargo ", "bash ")


def leg_steps(job: dict, axis: str | None, value: object) -> list[dict] | None:
    """Return the steps one leg of a job runs, in step order.

    A step runs on the leg when it carries no `if:`, or when axis_terms reads its
    `if:` as picking values of `axis` that include the leg's `value`. With `axis`
    None the job has one leg. Returns None when a step's `if:` leaves open whether
    this leg runs it.
    """
    steps: list[dict] = []
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        condition = step.get("if")
        if condition:
            terms = axis_terms(condition)
            if axis is None or terms is None or terms[0] != axis:
                return None
            if str(value).lower() not in {term.lower() for term in terms[1]}:
                continue
        steps.append(step)
    return steps


def leg_placeholder(axis: str | None) -> re.Pattern | None:
    """Return the pattern of `${{ matrix.<axis> }}` in any case, or None with no axis."""
    return (
        re.compile(rf"\$\{{\{{\s*matrix\.{re.escape(axis)}\s*\}}\}}", re.IGNORECASE)
        if axis
        else None
    )


def leg_commands(job: dict, axis: str | None, value: object) -> list[str] | None:
    """Return the commands one leg of a job runs, in step order.

    Each command is a logical line of the `run:` script of a step leg_steps finds
    the leg running that starts with one of LEG_COMMAND_PREFIXES, with every
    `${{ matrix.<axis> }}` replaced by the leg's value, so two legs whose step text
    is the same but whose matrix value differs run two different commands. Returns
    None when leg_steps does.
    """
    steps = leg_steps(job, axis, value)
    if steps is None:
        return None
    placeholder = leg_placeholder(axis)
    commands: list[str] = []
    for step in steps:
        for line in logical_lines(step.get("run") or ""):
            if line.startswith(LEG_COMMAND_PREFIXES):
                commands.append(placeholder.sub(str(value), line) if placeholder else line)
    return commands


def leg_step_identities(job: dict, axis: str, value: object) -> set[str] | None:
    """Return one string per step a leg runs, holding the step and its job.

    Each string serializes, with sorted keys, the step without its `if:` beside
    every job key but `strategy:`, `steps:` and `name:`, and replaces every
    `${{ matrix.<axis> }}` in it with the leg's value. A step's `run:`, `uses:`,
    `with:` and `env:`, and a job `env:`, `defaults:`, `runs-on:` or any other
    job key that can change what the step does, therefore differ between two
    legs whenever the leg value they hold does. `name:` is left out because it
    is a display label no step can read.

    Returns None when leg_steps does, and when any `${{ }}` expression in the
    job outside `strategy:`, a step's `if:` and a rust-cache step's `save-if`
    names `matrix` other than as that exact placeholder, or names `strategy`:
    such an expression evaluates per leg while its text stays the same.
    """
    steps = leg_steps(job, axis, value)
    if steps is None:
        return None
    placeholder = leg_placeholder(axis)
    scanned = {key: item for key, item in job.items() if key != "strategy"}
    scanned["steps"] = [
        {
            key: (
                {name: text for name, text in item.items() if name != "save-if"}
                if key == "with"
                and isinstance(item, dict)
                and str(step.get("uses", "")) == RUST_CACHE_ACTION
                else item
            )
            for key, item in step.items()
            if key != "if"
        }
        if isinstance(step, dict)
        else step
        for step in job.get("steps") or []
    ]
    for expression in re.findall(r"\$\{\{.*?\}\}", json.dumps(scanned), re.DOTALL):
        if re.search(r"\bstrategy\b", expression, re.IGNORECASE) or (
            re.search(r"\bmatrix\b", expression, re.IGNORECASE)
            and not placeholder.fullmatch(expression)
        ):
            return None
    context = {key: item for key, item in job.items() if key not in ("strategy", "steps", "name")}
    return {
        placeholder.sub(
            str(value),
            json.dumps(
                {"job": context, "step": {key: item for key, item in step.items() if key != "if"}},
                sort_keys=True,
            ),
        )
        for step in steps
    }


def push_runs_step(step: dict, legs: dict[str, str] | None = None) -> bool:
    """Report whether a push to `main` can run one step and meet its `save-if`.

    The step's `if:` and its `save-if`, each with or without the `${{ … }}`
    wrapper, are joined with `&&` and read with parse_condition's grammar.
    `github.event_name` reads `push` and `github.ref` reads `refs/heads/main`.
    Every other comparison that names some other name may come out either way,
    and one pair of operands gets one answer wherever it appears. The step runs
    on push when some choice of those answers makes the whole expression true.
    `legs` maps `matrix.<axis>` operands to one leg's values, which the
    expression then reads as known rather than free.
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
    known = {
        name.lower(): text
        for name, text in {
            "github.event_name": "push",
            "github.ref": "refs/heads/main",
            **(legs or {}),
        }.items()
    }

    # GitHub reads names and compares strings without regard to case.
    def operand(token: str) -> str | None:
        quoted = re.fullmatch(r"'([^']*)'", token)
        if quoted:
            return quoted.group(1).lower()
        if token in ("true", "false") or token.isdigit():
            return token
        found = known.get(token.lower())
        return None if found is None else found.lower()

    free: list[tuple[str, ...]] = []

    def collect(node: tuple) -> None:
        if node[0] in ("or", "and"):
            for part in node[1]:
                collect(part)
        elif None in (operand(node[1]), operand(node[2])):
            pair = tuple(sorted((node[1].lower(), node[2].lower())))
            if pair not in free:
                free.append(pair)

    def value(node: tuple, answers: dict) -> bool:
        if node[0] in ("or", "and"):
            results = [value(part, answers) for part in node[1]]
            return any(results) if node[0] == "or" else all(results)
        left, right = operand(node[1]), operand(node[2])
        if None in (left, right):
            equal = answers[tuple(sorted((node[1].lower(), node[2].lower())))]
        else:
            equal = left == right
        return equal if node[0] == "==" else not equal

    collect(tree)
    return any(
        value(tree, {pair: bool(mask >> index & 1) for index, pair in enumerate(free)})
        for mask in range(2 ** len(free))
    )


def push_only_legs_repeat_other_legs(
    job: dict, axis: str, push_only: list, other_values: list
) -> bool:
    """Report whether every push-only leg repeats steps other events' legs run.

    A push to `main` may run a leg no other event runs only to write a cache those
    legs restore: job rust-test-macos's `all` leg runs the steps its three
    pull-request legs split between them, so one leg writes one entry holding all
    three feature sets. Such a leg must run at least one command (leg_commands),
    and every step it runs must be, by leg_step_identities, a step some leg of
    pull_request and merge_group runs: the same `run:` script, `uses:`, `with:`
    and `env:`, under the same job keys. A leg whose steps leg_steps cannot read
    fails.
    """
    elsewhere: set[str] = set()
    for value in other_values:
        identities = leg_step_identities(job, axis, value)
        if identities is None:
            return False
        elsewhere |= identities
    for value in push_only:
        identities = leg_step_identities(job, axis, value)
        if not leg_commands(job, axis, value) or identities is None:
            return False
        if not identities <= elsewhere:
            return False
    return True


def warm_pushed_caches(warm: dict) -> set[str]:
    """Name each SHARED_KEY_CACHES cache a job of the cache-warm workflow `warm` writes
    on every push to `main`: the workflow triggers on a push to `main` and the job
    carries no `if:`."""
    events = warm.get("on", warm.get(True)) or {}
    push = events.get("push", None) if isinstance(events, dict) else None
    branches = (push or {}).get("branches") if isinstance(push, dict) else None
    if not branches or "main" not in branches:
        return set()
    return {
        name
        for job_id, written in cache_writers(warm).items()
        if warm["jobs"][job_id].get("if") is None
        for name in written
        if name in SHARED_KEY_CACHES
    }


def push_writer_gaps(doc: dict, warm: dict | None = None) -> list[str]:
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
    names needs only that some push runs some job writing it, in ci.yml or in the
    cache-warm workflow `warm` (the repository's when None).

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
    if warm is None:
        warm = yaml.safe_load(CACHE_WARM_WORKFLOW.read_text())
    warmed = warm_pushed_caches(warm)
    for cache in sorted(SHARED_KEY_CACHES):
        pushed = cache in warmed
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
            push_only = [v for v in push_values if str(v) not in set(map(str, other_values))]
            if push_only and not push_only_legs_repeat_other_legs(
                job, key, push_only, other_values
            ):
                gaps.append(
                    f"{job_id}'s matrix `{key}` runs {push_values} on push, outside "
                    f"the {other_values} every other event runs, and a push-only leg "
                    f"runs no command, or a step no leg of another event runs"
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
            named = []
            for name, value in SAVE_IF_MATRIX.findall(leg_conditions):
                try:
                    key = matrix_key(name, on_push)
                except AmbiguousMatrixKey as ambiguous:
                    gaps.append(f"{job_id} saves {cache_write(step)} where {ambiguous}")
                    continue
                if key is not None:
                    named.append((key, value))
            axes = sorted({key for key, _ in named})
            if axes:
                # Fix each named axis at each combination of the values a push runs,
                # and ask whether one of those legs runs this step and saves.
                try:
                    saved = any(
                        push_runs_step(
                            step,
                            {f"matrix.{key}": leg for key, leg in zip(axes, combination)},
                        )
                        for combination in itertools.product(
                            *(list(map(str, on_push[key])) for key in axes)
                        )
                    )
                except ValueError:
                    saved = True  # The unreadable expression is reported above.
                if not saved:
                    legs = " or ".join(f"`{key} == {value}`" for key, value in named)
                    pushed = ", ".join(f"`{key}` over {on_push[key]}" for key in axes)
                    gaps.append(
                        f"{job_id} saves {cache_write(step)} only from matrix leg "
                        f"{legs}, and a push runs {pushed} alone"
                    )
            key_text = f"{inputs.get('shared-key', '')} {inputs.get('key', '')}"
            named_axes = KEY_MATRIX_AXIS.findall(key_text)
            action = str(step.get("uses") or "").split("@", 1)[0]
            if action == RUST_CACHE_ACTION or KEY_RUNNER.search(key_text):
                named_axes += KEY_MATRIX_AXIS.findall(str(job.get("runs-on") or ""))
            key_axes = set()
            for name in named_axes:
                try:
                    key_axes.add(matrix_key(name, on_push))
                except AmbiguousMatrixKey as ambiguous:
                    gaps.append(f"{job_id} writes {cache_write(step)} where {ambiguous}")
            key_axes.discard(None)
            def leg_runs_step(key: str, value: object) -> bool:
                """Whether a leg holding `value` on axis `key` runs this step at all.

                A leg whose value the step's `if:` excludes writes no entry under
                that value, so it is not a value the key expands for this step.
                """
                try:
                    return push_runs_step(
                        {"if": step.get("if")}, {f"matrix.{key}": str(value)}
                    )
                except ValueError:
                    return True

            for key in sorted(key_axes):
                pushed_values = set(map(str, on_push[key]))
                unwritten = [
                    v
                    for v in elsewhere[key]
                    if str(v) not in pushed_values and leg_runs_step(key, v)
                ]
                if unwritten:
                    gaps.append(
                        f"{job_id} writes {cache_write(step)}, one entry per value of "
                        f"matrix `{key}`, and a push never runs {unwritten}, so those "
                        f"entries are never written"
                    )
    return gaps


# The commands each split job ran before its split into legs, one tuple per
# group of jobs that together hold them. A push and a pull request each run the
# group's legs (leg_commands) for that event, and leg_command_gaps requires that
# those legs run every pinned command exactly once, so a split,
# a merge, or a renamed leg cannot drop a command or run one twice. A job named
# here that the event does not run contributes no command, so the rust-doc pair
# pins no command for push. A change to what a job runs edits this table in the
# same pull request.
TRANSPORT_FEATURES = "quic,http3,udp,coap,nostr,webrtc"
APPLE_FEATURES = "apple,sync,sqlite,filesystem,file,encrypting,testing"
DOC_FEATURES = (
    "scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,"
    "scp-runtime/testing,scp-runtime/saga-witness-test-mint,"
    "scp-ffi/outlet-capability-test-grant,scp-ffi-napi/outlet-capability-test-grant,"
    "scp-ffi-uniffi/outlet-capability-test-grant,scp-node/cloud-blobs,scp-relay/cloud-blobs"
)
CLIPPY_WORKSPACE_FEATURES = (
    "scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,"
    "scp-runtime/testing,scp-runtime/saga-witness-test-mint,scp-ffi/testing,"
    "scp-ffi/outlet-capability-test-grant,scp-ffi-napi/testing,"
    "scp-ffi-napi/outlet-capability-test-grant,scp-ffi-uniffi/testing,"
    "scp-ffi-uniffi/outlet-capability-test-grant"
)
NEXTEST = "cargo nextest run --no-tests=fail"
# rust-test's four package shards. scripts/check-test-shard-features.py holds each
# shard's packages and features to the workspace resolution; this table pins the
# commands so a leg cannot drop or repeat one.
RUST_TEST_SHARDS = (
    (
        f"{NEXTEST} -p scp-ffi -p scp-ffi-common -p scp-ffi-napi -p scp-ffi-napi-test-stubs "
        "-p scp-ffi-uniffi --features scp-ffi-uniffi/testing,scp-ffi/testing,"
        "scp-ffi-napi/testing,scp-ffi/outlet-capability-test-grant,"
        "scp-ffi-napi/outlet-capability-test-grant,scp-ffi-uniffi/outlet-capability-test-grant,"
        "scp-platform/filesystem,scp-testing/testing"
    ),
    (
        f"{NEXTEST} -p scp-runtime -p scp-core --features scp-core/testing,"
        "scp-core/allow_unencrypted_storage,scp-runtime/testing,"
        "scp-runtime/saga-witness-test-mint,scp-core/outlet-capability-test-grant,"
        "serde_json/raw_value,serde_json/unbounded_depth,tracing/log,"
        "scp-runtime/outlet-capability-test-grant,scp-dht/production-dht,"
        "scp-identity/production-dht,scp-platform/file,scp-platform/sqlite,tokio-util/codec,"
        "tokio-util/io"
    ),
    (
        f"{NEXTEST} -p scp-testing -p scp-platform --features openmls_basic_credential/test-utils,"
        "serde_json/unbounded_depth,scp-core/outlet-capability-test-grant,tokio/test-util,"
        "scp-runtime/outlet-capability-test-grant,scp-runtime/saga-witness-test-mint,"
        "scp-platform/filesystem,scp-ffi-common/custody,scp-ffi-common/server,"
        "scp-ffi-common/testing"
    ),
    (
        f"{NEXTEST} -p scp-alloc -p scp-sqlite-pools -p scp-clock -p scp-crypto -p scp-did "
        "-p scp-kel -p scp-dht -p scp-identity -p scp-event-log -p scp-protocol "
        "-p scp-relay-client -p scp-mls -p scp-client -p scp-client-wasm -p scp-relay-mock "
        "-p scp-transport -p scp-mcp -p scp-media -p scp-node -p scp-relay --features "
        "serde_json/unbounded_depth,rustix/net,scp-crypto/testing,scp-identity/testing,scp-testing/testing,"
        "scp-core/outlet-capability-test-grant,scp-mcp/testing,"
        "scp-node/allow_unencrypted_storage,scp-node/testing"
    ),
)
LEG_COMMANDS: tuple[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]], ...] = (
    (("rust-test",), ("merge_group", "pull_request"), RUST_TEST_SHARDS),
    (
        ("rust-test-macos",),
        ("merge_group", "pull_request"),
        (
            "cargo test -p scp-transport --features combined,local-cache",
            (
                f"{NEXTEST} -p scp-transport --features {TRANSPORT_FEATURES} -E "
                "'not (binary(nostr_roundtrip) | binary(webrtc_roundtrip) | "
                "test(/^nostr::/) | test(/^webrtc::/))'"
            ),
            f"{NEXTEST} -p scp-transport --features {TRANSPORT_FEATURES} --test nostr_roundtrip",
            f"{NEXTEST} -p scp-transport --features {TRANSPORT_FEATURES} --test webrtc_roundtrip",
            (
                f"{NEXTEST} -p scp-transport --features {TRANSPORT_FEATURES} --lib "
                "-E 'test(/^nostr::/)'"
            ),
            (
                f"{NEXTEST} -p scp-transport --features {TRANSPORT_FEATURES} --lib "
                "-E 'test(/^webrtc::/)'"
            ),
            f"{NEXTEST} -p scp-transport --features sqlite-blob,redb-blob,startup",
            f"{NEXTEST} -p scp-platform --features {APPLE_FEATURES} --lib -E 'test(/^apple::/)'",
            (
                f"{NEXTEST} -p scp-platform --features {APPLE_FEATURES} --lib "
                "-E 'test(/^syncable::tests::storage_conformance::/)'"
            ),
            (
                f"{NEXTEST} -p scp-platform --features {APPLE_FEATURES} --lib "
                "-E 'test(/^syncable::tests::/) - test(/^syncable::tests::storage_conformance::/)'"
            ),
            (
                f"{NEXTEST} -p scp-platform --features {APPLE_FEATURES} "
                "-E 'not (test(/^apple::/) | test(/^syncable::tests::/))'"
            ),
        ),
    ),
    (
        ("rust-clippy",),
        ("merge_group", "pull_request"),
        (
            (
                f"cargo clippy --workspace --all-targets --features {CLIPPY_WORKSPACE_FEATURES} "
                "-- -D warnings"
            ),
            "bash scripts/check-examples-compile.sh",
            "bash scripts/tests/examples-compile/run-tests.sh",
            (
                f"cargo clippy -p scp-transport --features {TRANSPORT_FEATURES},push-store "
                "--all-targets -- -D warnings"
            ),
            (
                "cargo clippy -p scp-transport --features quic,http3,udp,push-store,testing "
                "--all-targets -- -D warnings"
            ),
            (
                "cargo clippy -p scp-node --features quic,http3,udp,coap,upnp,testing --all-targets "
                "-- -D warnings"
            ),
            (
                f"cargo clippy -p scp-platform --features {APPLE_FEATURES} --all-targets "
                "-- -D warnings"
            ),
            "cargo clippy -p scp-testing --features sync,combined --all-targets -- -D warnings",
            (
                "cargo clippy -p scp-transport --features "
                "sqlite-blob,redb-blob,postgres-blob,s3-blob,startup --all-targets -- -D warnings"
            ),
            (
                "cargo clippy -p scp-transport --features "
                "sqlite-blob,redb-blob,postgres-blob,s3-blob,startup,webpush --all-targets "
                "-- -D warnings"
            ),
            "cargo clippy -p scp-transport --features push-store --all-targets -- -D warnings",
            (
                "cargo clippy -p scp-transport --features push-store,testing --all-targets "
                "-- -D warnings"
            ),
            (
                "cargo clippy -p scp-transport --features combined,local-cache,push-store,"
                "relay-persistence,testing,upnp --all-targets -- -D warnings"
            ),
            "cargo clippy -p scp-node --features cloud-blobs,testing --all-targets -- -D warnings",
            "cargo clippy -p scp-relay --features cloud-blobs --all-targets -- -D warnings",
            "cargo clippy -p scp-node --no-default-features --lib -- -D warnings",
            (
                "cargo clippy -p scp-node --no-default-features --features testing --all-targets "
                "-- -D warnings"
            ),
        ),
    ),
    # Job rust-test-optional-features, whose `group` axis runs the transport
    # group's commands on four legs. The table pins every command of every group,
    # as the one-leg job ran them.
    (
        ("rust-test-optional-features",),
        ("merge_group", "pull_request"),
        (
            'cargo test -p scp-transport --features combined,local-cache',
            "cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,coap,nostr,webrtc,push-store -E 'not (binary(nostr_roundtrip) | binary(webrtc_roundtrip) | test(/^nostr::/) | test(/^webrtc::/) | test(=quic::listener::tests::enabled_quic_listener_rejects_a_tier3_publish_with_4060) | test(=udp::listener::tests::enabled_udp_listener_rejects_a_tier3_publish_with_4060) | test(=webtransport::server::tests::enabled_webtransport_listener_rejects_a_tier3_publish_with_4060))'",
            'cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,coap,nostr,webrtc,push-store --test nostr_roundtrip',
            'cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,coap,nostr,webrtc,push-store --test webrtc_roundtrip',
            "cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,coap,nostr,webrtc,push-store --lib -E 'test(/^nostr::/)'",
            "cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,coap,nostr,webrtc,push-store --lib -E 'test(/^webrtc::/)'",
            "cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,coap,nostr,webrtc,push-store --lib -E 'test(=quic::listener::tests::enabled_quic_listener_rejects_a_tier3_publish_with_4060)'",
            "cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,coap,nostr,webrtc,push-store --lib -E 'test(=udp::listener::tests::enabled_udp_listener_rejects_a_tier3_publish_with_4060)'",
            "cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,coap,nostr,webrtc,push-store --lib -E 'test(=webtransport::server::tests::enabled_webtransport_listener_rejects_a_tier3_publish_with_4060)'",
            "cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,push-store,testing --lib -E 'test(/^quic::listener::tests::wake::/)'",
            "cargo nextest run --no-tests=fail -p scp-transport --features quic,http3,udp,push-store,testing --lib -E 'test(/^udp::listener::tests::wake::/)'",
            'cargo nextest run --no-tests=fail -p scp-transport --features sqlite-blob,redb-blob,postgres-blob,s3-blob,startup --lib startup::tests',
            'cargo nextest run --no-tests=fail -p scp-transport --features sqlite-blob,redb-blob,postgres-blob,s3-blob,startup --test postgres_blob_fail_closed --test s3_blob_fail_closed',
            "cargo nextest run --no-tests=fail -p scp-transport --features sqlite-blob,redb-blob,postgres-blob,s3-blob,startup --lib -E 'test(/^native::postgres_blob::tests::/)'",
            "cargo nextest run --no-tests=fail -p scp-transport --features sqlite-blob,redb-blob,postgres-blob,s3-blob,startup --lib -E 'test(/^native::s3_blob::tests::/)'",
            'cargo nextest run --no-tests=fail -p scp-transport --features sqlite-blob,redb-blob,postgres-blob,s3-blob,startup --test postgres_blob_conformance --test s3_blob_conformance',
            'cargo nextest run --no-tests=fail -p scp-transport --features push-store,testing --lib --tests',
            'cargo nextest run --no-tests=fail -p scp-transport --features push-store --lib --tests',
            'cargo nextest run --no-tests=fail -p scp-transport --features push-store --lib store_without_testing_has_only_the_sqlite_arm',
            'cargo nextest run --no-tests=fail -p scp-node --features quic,testing --test quic_listener',
            'cargo nextest run --no-tests=fail -p scp-node --features quic,testing --test quic_cross_transport',
            "cargo nextest run --no-tests=fail -p scp-node --features http3,udp,testing --lib -E 'test(=well_known::tests::advertised_transports_includes_webtransport_with_feature)'",
            "cargo nextest run --no-tests=fail -p scp-node --features http3,udp,testing --lib -E 'test(=well_known::tests::advertised_transports_includes_udp_dtls_with_feature)'",
            "cargo nextest run --no-tests=fail -p scp-node --features http3,testing --lib -E 'test(=http::tests::http3_well_known_carries_the_key_and_cors_star)'",
            'cargo nextest run --no-tests=fail -p scp-node --features cloud-blobs,testing --test storage_backend_selection',
            'cargo nextest run --no-tests=fail -p scp-relay --features cloud-blobs --test storage_backend',
            "cargo nextest run --no-tests=fail -p scp-platform --features apple,sync,sqlite,filesystem,file,encrypting,testing --lib -E 'test(/^apple::/)'",
            "cargo nextest run --no-tests=fail -p scp-platform --features apple,sync,sqlite,filesystem,file,encrypting,testing --lib -E 'test(/^syncable::tests::storage_conformance::/)'",
            "cargo nextest run --no-tests=fail -p scp-platform --features apple,sync,sqlite,filesystem,file,encrypting,testing --lib -E 'test(/^syncable::tests::/) - test(/^syncable::tests::storage_conformance::/)'",
            "cargo nextest run --no-tests=fail -p scp-testing --features sync,combined --test persistence_advanced -E 'test(=syncable_storage_export_apply_roundtrip)'",
            "cargo nextest run --no-tests=fail -p scp-testing --features sync,combined --test persistence_advanced -E 'test(=combined_node_storage_both_traits_roundtrip)'",
            "cargo nextest run --no-tests=fail -p scp-testing --features sqlite --test persistence -E 'test(/^sqlite::/)'",
            'cargo nextest run --no-tests=fail -p scp-testing --features sqlite --test persistence_sdk',
            "cargo nextest run --no-tests=fail -p scp-testing --features sqlite --test saga_bridge_journal_swap -E 'test(=journal_swap_sqlite_durable_crash_recovery_round_trips_on_disk)'",
            'cargo check -p scp-testing --lib',
            'cargo check -p scp-testing --lib --features testing',
            "cargo nextest run --no-tests=fail -p scp-sqlite-pools --lib --run-ignored only -E 'test(=tests::open_refuses_a_sqlite_built_without_memory_management)'",
        ),
    ),
    (
        ("rust-doc", "rust-doctest"),
        ("pull_request",),
        (
            f"cargo test --workspace --doc --features {DOC_FEATURES}",
            f"cargo doc --workspace --no-deps --document-private-items --features {DOC_FEATURES}",
        ),
    ),
)


def event_runs_job(job: dict, event: str) -> bool:
    """Report whether a job's `if:` can hold on `event`, through push_runs_step.

    Only `github.event_name` (and `github.ref`, which push_runs_step fixes at
    `main`) is known; every filter output stays free, so the answer is no only
    when the condition rules the event out whatever the outputs say. A condition
    outside the grammar counts as running, so the commands it guards still count.
    """
    try:
        return push_runs_step({"if": job.get("if")}, {"github.event_name": event})
    except ValueError:
        return True


# The matrix axes a split job in LEG_COMMANDS divides its commands over, in the
# order leg_command_gaps looks for them.
SPLIT_AXES = ("leg", "group")


def leg_command_gaps(doc: dict) -> list[str]:
    """Return each way a split job's legs disagree with LEG_COMMANDS.

    CRITERION: for each group of jobs in LEG_COMMANDS and each event it names,
    the legs that event runs (every value of the job's split axis, `leg` or else
    `group`, for that event, or the one leg of a job with neither axis; a job
    whose `if:` rules the event
    out runs none) run, by leg_commands, each pinned command exactly once, and no
    command the table does not pin. A leg whose steps leg_commands cannot read is
    reported. A job named in the table and absent from the workflow is reported.
    """
    gaps = []
    for job_ids, events, pinned in LEG_COMMANDS:
        label = " + ".join(job_ids)
        missing = [job_id for job_id in job_ids if job_id not in doc["jobs"]]
        if missing:
            gaps.append(f"{label}: the workflow has no job {', '.join(missing)}")
            continue
        for event in events:
            ran: list[str] = []
            for job_id in job_ids:
                job = doc["jobs"][job_id]
                if not event_runs_job(job, event):
                    continue
                matrix = (job.get("strategy") or {}).get("matrix") or {}
                axis = next((name for name in SPLIT_AXES if name in matrix), None)
                lists = axis_event_values(matrix[axis]) if axis else None
                if axis and lists is None:
                    gaps.append(f"{job_id}: matrix axis {axis} {matrix[axis]!r} is unreadable")
                    continue
                key = "push" if event == "push" else "other"
                for value in lists[key] if lists else [None]:
                    commands = leg_commands(job, axis if lists else None, value)
                    if commands is None:
                        gaps.append(
                            f"{job_id} leg {value}: a step `if:` leaves open whether "
                            f"the leg runs it"
                        )
                        continue
                    ran.extend(commands)
            for command in pinned:
                count = ran.count(command)
                if count != 1:
                    gaps.append(
                        f"{label} on {event}: {command!r} runs on {count} legs, not one"
                    )
            for command in dict.fromkeys(ran):
                if command not in pinned:
                    gaps.append(
                        f"{label} on {event}: {command!r} runs, and LEG_COMMANDS does "
                        f"not pin it"
                    )
    return gaps


def check_leg_commands(doc: dict) -> None:
    """The live legs run the pinned commands, and mutants of them are reported."""
    gaps = leg_command_gaps(doc)
    check("every split job's legs run each pinned command exactly once", not gaps, f"{gaps}")

    def steps_running(mutant: dict, job_id: str, command: str) -> list[dict]:
        return [
            step
            for step in mutant["jobs"][job_id]["steps"]
            if isinstance(step, dict) and command in logical_lines(step.get("run") or "")
        ]

    for job_ids, events, pinned in LEG_COMMANDS:
        command = pinned[-1]
        holder = next(
            (job_id for job_id in job_ids if steps_running(doc, job_id, command)), None
        )
        check(
            f"{' + '.join(job_ids)} has a step running {command[:40]!r} for the controls",
            holder is not None,
            "no step runs it",
        )
        if holder is None:
            continue
        event = events[-1]

        deleted = copy.deepcopy(doc)
        step = steps_running(deleted, holder, command)[0]
        step["run"] = "\n".join(
            line for line in logical_lines(step["run"]) if line != command
        ) or "true"
        gaps = leg_command_gaps(deleted)
        check(
            f"deleting {command[:40]!r} from {holder} is reported",
            any(f"on {event}: {command!r} runs on 0 legs" in gap for gap in gaps),
            f"{gaps}",
        )

        twice = copy.deepcopy(doc)
        step = steps_running(twice, holder, command)[0]
        job = twice["jobs"][holder]
        if "if" in step:
            step.pop("if")
        else:
            job["steps"].append(copy.deepcopy(step))
        gaps = leg_command_gaps(twice)
        check(
            f"running {command[:40]!r} on every {holder} leg is reported",
            any(f"on {event}: {command!r} runs on " in gap and "not one" in gap for gap in gaps),
            f"{gaps}",
        )

        added = copy.deepcopy(doc)
        added["jobs"][holder]["steps"].append({"run": "cargo test -p scp-unpinned"})
        gaps = leg_command_gaps(added)
        check(
            f"a command LEG_COMMANDS does not pin in {holder} is reported",
            any("'cargo test -p scp-unpinned' runs, and LEG_COMMANDS" in gap for gap in gaps),
            f"{gaps}",
        )

    # Dropping one pull-request leg value leaves that leg's commands unrun.
    for job_id, value in (
        ("rust-test-macos", "platform"),
        ("rust-clippy", "packages-blob"),
        ("rust-test-optional-features", "transport-network"),
    ):
        dropped = copy.deepcopy(doc)
        matrix = dropped["jobs"][job_id]["strategy"]["matrix"]
        axis = next((name for name in SPLIT_AXES if name in matrix), "leg")
        lists = axis_event_values(matrix.get(axis))
        check(f"{job_id}'s pull-request legs include {value}", bool(lists) and value in lists["other"], f"{matrix.get(axis)!r}")
        if not lists:
            continue
        other = [leg for leg in lists["other"] if leg != value]
        matrix[axis] = (
            f"${{{{ fromJSON(github.event_name == 'push' && "
            f"'{json.dumps(lists['push'])}' || '{json.dumps(other)}') }}}}"
        )
        gaps = leg_command_gaps(dropped)
        check(
            f"dropping {job_id}'s {value} leg is reported",
            any(gap.startswith(f"{job_id} on pull_request: ") and "runs on 0 legs" in gap for gap in gaps),
            f"{gaps}",
        )

    split = copy.deepcopy(doc)
    split["jobs"]["rust-doctest"]["if"] = (
        f"github.event_name == 'push' && ({doc['jobs']['rust-doctest'].get('if') or 'true'})"
    )
    gaps = leg_command_gaps(split)
    check(
        "a rust-doctest that a pull request skips is reported",
        any("rust-doc + rust-doctest on pull_request: 'cargo test --workspace --doc" in gap and "runs on 0 legs" in gap for gap in gaps),
        f"{gaps}",
    )


def matrix_axis_gaps(doc: dict) -> list[str]:
    """Return each disagreement between a job's matrix axes and its steps.

    CRITERION: in every job, an axis of `strategy.matrix` is read when at least
    one step's `if:` reads as axis_terms states: `matrix.<axis> == '<value>'`,
    or an `||` of such comparisons on that one axis. An axis is a list of
    names, or a PUSH_MATRIX expression choosing one list for push and another
    for every other event. For each axis read, every value such a step names
    is in one of the axis lists; when the two lists differ, every such step
    names a value of each, so each event runs it on some leg; and, unless the
    job's `runs-on` reads that axis, every value either list holds is named by
    at least one such step. A value no step names runs legs that skip every
    gated step, and a step naming a value the axis lacks never runs on any
    leg, so its commands run nowhere while every leg passes. An axis `runs-on`
    reads picks each leg's runner, so a step gated to one of its values (a
    macOS-only install) leaves the other legs running every ungated step.
    Another step whose `if:` mentions `matrix.<axis>` for an axis read is
    reported rather than read, because this check could not say which legs
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
            terms = axis_terms(condition)
            if terms and terms[0] not in defined:
                gaps.append(
                    f"{job_id}: {label!r} has `if: {condition}`, but the job's "
                    f"matrix defines no axis {terms[0]}, so it runs on no leg"
                )
        read_axes = sorted(
            {
                terms[0]
                for _, condition in steps
                if (terms := axis_terms(condition))
                and terms[0] in matrix
                and terms[0] not in ("include", "exclude")
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
            lists = axis_event_values(axis)
            if lists is None or not all(
                isinstance(v, str) for values in lists.values() for v in values
            ):
                gaps.append(
                    f"{job_id}: matrix axis {axis_name} {axis!r} is not a list of names"
                )
                continue
            every = list(dict.fromkeys([*lists["push"], *lists["other"]]))
            by_event = (
                ()
                if lists["push"] == lists["other"]
                else (("push", lists["push"]), ("pull_request", lists["other"]))
            )
            mention = re.compile(
                rf"\bmatrix\.{re.escape(axis_name)}(?![A-Za-z0-9_-])", re.IGNORECASE
            )
            named: set[str] = set()
            for label, condition in steps:
                if not mention.search(condition):
                    continue
                terms = axis_terms(condition)
                if terms is None or terms[0] != axis_name:
                    gaps.append(
                        f"{job_id}: {label!r} has `if: {condition}`, which is not "
                        f"`matrix.{axis_name} == '<value>'` or an `||` of such "
                        f"comparisons on that one axis"
                    )
                    continue
                values = terms[1]
                named.update(values)
                for value in values:
                    if value not in every:
                        gaps.append(
                            f"{job_id}: {label!r} names {axis_name} {value!r}, which "
                            f"matrix axis {axis_name} {axis} lacks, so its commands "
                            f"run on no leg"
                        )
                for event, event_values in by_event:
                    if not set(values) & set(event_values):
                        gaps.append(
                            f"{job_id}: {label!r} names {axis_name} {values}, none of "
                            f"which a {event} run's legs {event_values} take, so a "
                            f"{event} run skips its commands"
                        )
            if mention.search(str(job.get("runs-on") or "")):
                continue
            for value in every:
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
        "docker-image-cache",
        "napi-addon",
        "pyo3-module",
        "pyo3-module-macos",
        "uniffi-cdylib-linux",
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


# The rust-cache groups each job wrote on a push to `main` before
# .github/workflows/cache-warm.yml took every cargo group over, by the step `if:`
# naming the leg that wrote it. rust-test and rust-test-macos wrote none.
PUSH_WRITER_SHAPE: dict[str, tuple[str, ...]] = {
    "rust-clippy": ("clippy-examples",),
    "rust-test": (),
    "rust-test-macos": (),
    "rust-test-optional-features": (
        "optional-features",
        "transport-optional-sqlite-without-memory-management",
    ),
}
PUSH_GUARD = "github.event_name != 'push' && "


def push_writer_shape(source: dict) -> dict:
    """Rebuild the jobs PUSH_WRITER_SHAPE names as they ran while they wrote on push.

    ci.yml now writes no cargo group on a push, so a writer detector given only the
    live jobs has no rust-cache writer to read. This copy drops each job's push
    guard and lets each named group's rust-cache step save on `main`, giving the
    controls in check_push_writer_mutants the leg-gated and step-gated writers they
    mutate.
    """
    rebuilt = copy.deepcopy(source)
    for job_id, groups in PUSH_WRITER_SHAPE.items():
        job = rebuilt["jobs"][job_id]
        condition = str(job.get("if") or "")
        if not condition.startswith(PUSH_GUARD):
            raise ValueError(f"{job_id}'s `if:` does not start with the push guard: {condition!r}")
        rest = condition[len(PUSH_GUARD) :]
        if rest.startswith("(") and rest.endswith(")"):
            rest = rest[1:-1]
        job["if"] = rest
        for step in job["steps"]:
            if (
                isinstance(step, dict)
                and str(step.get("uses", "")) == RUST_CACHE_ACTION
                and (step.get("with") or {}).get("shared-key") in groups
            ):
                step["with"]["save-if"] = "${{ github.ref == 'refs/heads/main' }}"
    return rebuilt


def check_push_writer_mutants(live: dict) -> None:
    """Each way of skipping a writer on push, or leaking a push skip, is reported."""

    doc = push_writer_shape(live)
    for job_id, groups in PUSH_WRITER_SHAPE.items():
        check(
            f"the rebuilt {job_id} writes {list(groups) or 'nothing'} and runs on push",
            sorted(
                name.split("`")[1]
                for name in cache_writers(doc, shared=False).get(job_id, [])
                if name.startswith("rust-cache")
            )
            == sorted(groups)
            and "github.event_name" not in str(doc["jobs"][job_id].get("if")),
            f"{doc['jobs'][job_id].get('if')!r} {cache_writers(doc).get(job_id)}",
        )

    # ci.yml runs one literal leg list on every event that runs these jobs, and no
    # push runs them. The controls on push-only
    # legs and on leg-gated writers run against a rebuilt copy of the shape those
    # jobs had while a push-only leg wrote their group: the push list swaps the
    # absorbed legs for one push leg, every step that names only absorbed legs also
    # runs on the push leg, and the rust-cache step those legs run saves only from
    # the push leg on `main`.
    def with_push_leg(
        source: dict, job_id: str, push_leg: str, absorbed: tuple[str, ...] | None = None
    ) -> dict:
        rebuilt = copy.deepcopy(source)
        job = rebuilt["jobs"][job_id]
        legs = job["strategy"]["matrix"]["leg"]
        taken = set(legs if absorbed is None else absorbed)
        pushed = [leg for leg in legs if leg not in taken] + [push_leg]
        job["strategy"]["matrix"]["leg"] = (
            f"${{{{ fromJSON(github.event_name == 'push' && '{json.dumps(pushed)}' "
            f"|| '{json.dumps(legs)}') }}}}"
        )
        for step in job["steps"]:
            if not isinstance(step, dict):
                continue
            terms = axis_terms(step.get("if"))
            named = terms is not None and terms[0] == "leg" and set(terms[1]) <= taken
            if named:
                step["if"] = f"matrix.leg == '{push_leg}' || {step['if']}"
            every_leg = step.get("if") is None and taken == set(legs)
            if str(step.get("uses", "")) == RUST_CACHE_ACTION and (named or every_leg):
                step.setdefault("with", {})["save-if"] = (
                    f"${{{{ github.ref == 'refs/heads/main' && matrix.leg == '{push_leg}' }}}}"
                )
        return rebuilt

    test_writer = with_push_leg(doc, "rust-test", "all")
    macos_writer = with_push_leg(doc, "rust-test-macos", "all")
    clippy_writer = with_push_leg(
        doc,
        "rust-clippy",
        "packages",
        tuple(
            leg
            for leg in doc["jobs"]["rust-clippy"]["strategy"]["matrix"]["leg"]
            if leg.startswith("packages-")
        ),
    )
    for job_id, rebuilt in (
        ("rust-test", test_writer),
        ("rust-test-macos", macos_writer),
        ("rust-clippy", clippy_writer),
    ):
        check(
            f"the rebuilt push-leg {job_id} is read as a cache writer",
            job_id in cache_writers(rebuilt),
            f"{sorted(cache_writers(rebuilt))}",
        )
        check(
            f"the rebuilt push-leg {job_id} is read without a gap",
            not push_writer_gaps(rebuilt),
            f"{push_writer_gaps(rebuilt)}",
        )

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
    # SCENARIOS records the live push guard, so dropping it disagrees.
    check(
        "dropping rust-clippy's push guard disagrees with SCENARIOS",
        any(
            "rust-only, push: rust-clippy runs" in found
            for found in scenario_disagreements(doc)
        ),
        f"{scenario_disagreements(doc)}",
    )

    shard = copy.deepcopy(test_writer)
    shard["jobs"]["rust-test"]["strategy"]["matrix"]["leg"] = (
        "${{ fromJSON(github.event_name == 'push' && '[\"bridges\"]' "
        "|| '[\"bridges\", \"runtime\", \"testing\", \"rest\"]') }}"
    )
    gaps = push_writer_gaps(shard)
    check(
        "a push matrix without the writing leg is reported",
        any("rust-test saves" in gap for gap in gaps),
        f"{gaps}",
    )

    # rust-test-optional-features and rust-clippy each write one rust-cache entry
    # per push value of their axis through a writing step gated on that value. A push matrix dropping a value leaves its entry
    # unwritten; a push matrix keeping every value leaves nothing to report.
    # A job whose `runs-on` reads an `os` axis writes one rust-cache entry per `os`
    # value, because rust-cache keys by platform. No job in ci.yml has such an axis
    # (rust-test and rust-test-optional-features run on ubuntu-latest alone, and
    # rust-test-macos on macos-latest alone), so the `os` cases give rust-test and
    # rust-test-optional-features an `os` axis over both runners, read by
    # `runs-on`, before narrowing it.
    def with_os_axis(source: dict, job_id: str) -> dict:
        widened = copy.deepcopy(source)
        job = widened["jobs"][job_id]
        job["strategy"]["matrix"]["os"] = ["ubuntu-latest", "macos-latest"]
        job["runs-on"] = "${{ matrix.os }}"
        return widened

    for job_id, axis, dropped_value, reported in (
        (
            "rust-test-optional-features",
            "group",
            "sqlite-without-memory-management",
            "only from matrix leg `group == sqlite-without-memory-management`",
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
        ("rust-test-macos", "leg", "all", "only from matrix leg `leg == all`"),
    ):
        writer = {"rust-test": test_writer, "rust-test-macos": macos_writer}.get(job_id, doc)
        base = with_os_axis(writer, job_id) if axis == "os" else writer
        live_axis = base["jobs"][job_id]["strategy"]["matrix"][axis]
        # A literal axis runs one list on every event; an axis that is already a
        # PUSH_MATRIX expression keeps its pull-request list and loses the value
        # from its push list. A push list the drop empties takes the pull-request
        # list instead, since a matrix of no legs is not a push GitHub runs.
        lists = axis_event_values(live_axis)
        check(
            f"{job_id}'s `{axis}` axis lists {dropped_value} for the push-matrix control",
            lists is not None and dropped_value in lists["push"],
            f"{live_axis!r}",
        )
        if lists is None:
            continue
        every = json.dumps(lists["other"])
        pushed = json.dumps(lists["push"])
        fewer_values = [value for value in lists["push"] if value != dropped_value]
        fewer = json.dumps(fewer_values or lists["other"])
        narrowed = copy.deepcopy(base)
        narrowed["jobs"][job_id]["strategy"]["matrix"][axis] = (
            f"${{{{ fromJSON(github.event_name == 'push' && '{fewer}' || '{every}') }}}}"
        )
        gaps = push_writer_gaps(narrowed)
        check(
            f"a push matrix dropping {job_id}'s `{axis}` value {dropped_value} is reported",
            any(gap.startswith(f"{job_id} ") and reported in gap for gap in gaps),
            f"{gaps}",
        )
        whole = copy.deepcopy(base)
        whole["jobs"][job_id]["strategy"]["matrix"][axis] = (
            f"${{{{ fromJSON(github.event_name == 'push' && '{pushed}' || '{every}') }}}}"
        )
        check(
            f"a push matrix keeping every {job_id} `{axis}` value is not reported",
            not any(gap.startswith(f"{job_id} ") for gap in push_writer_gaps(whole)),
            f"{push_writer_gaps(whole)}",
        )

    # An actions/cache key splits by `runs-on` only when it names the platform.
    for key, split in (("deps-${{ runner.os }}-v1", True), ("deps-v1", False)):
        cached = with_os_axis(doc, "rust-test")
        job = cached["jobs"]["rust-test"]
        job["strategy"]["matrix"]["os"] = (
            "${{ fromJSON(github.event_name == 'push' && '[\"ubuntu-latest\"]' "
            "|| '[\"ubuntu-latest\", \"macos-latest\"]') }}"
        )
        job["steps"] = [
            {"uses": "actions/cache@v4", "with": {"path": "deps", "key": key}}
            if str(step.get("uses", "")) == RUST_CACHE_ACTION
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

    def clippy_examples(job: dict) -> dict:
        return step_where(
            job,
            lambda step: step.get("if") == "matrix.leg == 'examples'"
            and str(step.get("uses", "")) == RUST_CACHE_ACTION,
        )

    def test_cache(job: dict) -> dict:
        return step_where(
            job, lambda step: str(step.get("uses", "")) == RUST_CACHE_ACTION
        )

    def pyo3_save(job: dict) -> dict:
        return step_where(
            job, lambda step: str(step.get("uses", "")).startswith("actions/cache/save")
        )

    no_push = "github.event_name != 'push'"
    for label, base, job_id, locate, field, text, reported in (
        (
            "a push exclusion spelled in another case on rust-clippy's rust-cache `if:`",
            doc,
            "rust-clippy",
            clippy_examples,
            "if",
            "matrix.leg == 'examples' && GitHub.Event_Name != 'Push'",
            "no push to `main` meets",
        ),
        (
            "a rust-clippy rust-cache `if:` naming a pull-request-only leg in another case",
            clippy_writer,
            "rust-clippy",
            clippy_examples,
            "if",
            "MATRIX.LEG == 'packages-network'",
            "only from matrix leg",
        ),
        (
            "a push exclusion on rust-clippy's examples rust-cache `if:`",
            doc,
            "rust-clippy",
            clippy_examples,
            "if",
            f"matrix.leg == 'examples' && {no_push}",
            "no push to `main` meets",
        ),
        (
            "a merge_group-only rust-test rust-cache `save-if`",
            test_writer,
            "rust-test",
            test_cache,
            "save-if",
            "${{ github.event_name == 'merge_group' && matrix.leg == 'all' }}",
            "no push to `main` meets",
        ),
        (
            "a push exclusion on pyo3-module's cache save `if:`",
            doc,
            "pyo3-module",
            pyo3_save,
            "if",
            f"steps.artifact-cache.outputs.cache-hit != 'true' && {no_push}",
            "no push to `main` meets",
        ),
        (
            "a writing step condition that contradicts itself on one operand pair",
            doc,
            "rust-clippy",
            clippy_examples,
            "if",
            "matrix.leg == 'examples' && matrix.leg != 'examples'",
            "no push to `main` meets",
        ),
        (
            "a writing step `if:` outside the grammar",
            doc,
            "rust-clippy",
            clippy_examples,
            "if",
            "matrix.leg == 'examples' && !cancelled()",
            "this check cannot read",
        ),
        (
            "a writing step `if:` that admits push alongside other events",
            doc,
            "rust-clippy",
            clippy_examples,
            "if",
            f"matrix.leg == 'examples' && ({no_push} || github.ref == 'refs/heads/main')",
            None,
        ),
        (
            "a rust-cache `save-if` naming a leg and the main ref",
            test_writer,
            "rust-test",
            test_cache,
            "save-if",
            "${{ github.ref == 'refs/heads/main' && matrix.leg == 'all' }}",
            None,
        ),
    ):
        changed = copy.deepcopy(base)
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

    push_shards = (
        "${{ fromJSON(github.event_name == 'push' && '[\"all\", \"extra\"]' "
        "|| '[\"bridges\", \"runtime\", \"testing\", \"rest\"]') }}"
    )
    for label, key, value, reported in (
        (
            "a writer matrix that is one expression",
            None,
            "${{ fromJSON(inputs.matrix) }}",
            "through a matrix this check cannot read",
        ),
        (
            "a writer matrix key no pattern reads",
            "leg",
            "${{ fromJSON(inputs.legs) }}",
            "matrix `leg` is an expression this check cannot read",
        ),
        (
            "a push matrix leg outside every other event's legs",
            "leg",
            push_shards,
            "rust-test's matrix `leg` runs ['all', 'extra'] on push",
        ),
    ):
        changed = copy.deepcopy(test_writer)
        strategy = changed["jobs"]["rust-test"]["strategy"]
        if key is None:
            strategy["matrix"] = value
        else:
            strategy["matrix"][key] = value
        gaps = push_writer_gaps(changed)
        check(f"{label} is reported", any(reported in gap for gap in gaps), f"{gaps}")

    # The rebuilt rust-test-macos's push-only `all` leg is allowed because every step it runs
    # is one a pull-request leg runs. A push-only leg that runs a step no
    # pull-request leg runs, whatever its `run:` line starts with or when it is a
    # `uses:` or `env:` difference, or that runs no command, is reported.
    def macos_step(job: dict, value: str) -> dict:
        return step_where(
            job,
            lambda step: (terms := axis_terms(step.get("if"))) is not None
            and terms[1] == ["all", value],
        )

    for label, mutate in (
        (
            "a push-only leg running a command no pull-request leg runs",
            lambda job: macos_step(job, "platform").update(
                {"if": "matrix.leg == 'all'"}
            ),
        ),
        (
            "a push-only leg running a command of its own",
            lambda job: job["steps"].append(
                {
                    "name": "push only",
                    "if": "matrix.leg == 'all'",
                    "run": "cargo test -p scp-push-only",
                }
            ),
        ),
        (
            "a push-only leg running a script no LEG_COMMAND_PREFIXES names",
            lambda job: job["steps"].append(
                {"if": "matrix.leg == 'all'", "run": "./scripts/push-only.sh"}
            ),
        ),
        (
            "a push-only leg running a cargo command behind an assignment",
            lambda job: job["steps"].append(
                {
                    "if": "matrix.leg == 'all'",
                    "run": "RUSTFLAGS=--cfg=x cargo test -p scp-transport",
                }
            ),
        ),
        (
            "a push-only leg running an action of its own",
            lambda job: job["steps"].append(
                {"if": "matrix.leg == 'all'", "uses": "example/push-only@v1"}
            ),
        ),
        (
            "a push-only leg running a pull-request step's script under its own env",
            lambda job: job["steps"].append(
                {
                    **{key: item for key, item in macos_step(job, "platform").items() if key != "if"},
                    "if": "matrix.leg == 'all'",
                    "env": {"RUSTFLAGS": "--cfg=x"},
                }
            ),
        ),
        (
            "a push-only leg whose run line evaluates an expression on its axis",
            lambda job: job["steps"].append(
                {
                    "run": "cargo test -p scp-transport "
                    "${{ matrix.leg == 'all' && '--features evil' || '' }}"
                }
            ),
        ),
        (
            "a push-only leg reading a job env value built from its axis",
            lambda job: (
                job.setdefault("env", {}).update(
                    {"EXTRA": "${{ matrix.leg == 'all' && './push-only.sh' || 'true' }}"}
                ),
                job["steps"].append({"run": "cargo test -p scp-transport && $EXTRA"}),
            ),
        ),
        (
            "a push-only leg whose run line reads its strategy job index",
            lambda job: job["steps"].append(
                {"run": "cargo test -p scp-transport ${{ strategy.job-index }}"}
            ),
        ),
        (
            "a push-only leg whose run line reads its strategy job index in another case",
            lambda job: job["steps"].append(
                {"run": "cargo test -p scp-transport ${{ Strategy.job-index }}"}
            ),
        ),
        (
            "a push-only leg reading a job env value that is its leg in another case",
            lambda job: (
                job.setdefault("env", {}).update({"LEG": "${{ Matrix.leg }}"}),
                job["steps"].append(
                    {
                        "run": "cargo test -p scp-transport && "
                        'if [ "$LEG" = all ]; then ./push-only.sh; fi'
                    }
                ),
            ),
        ),
        (
            "a push-only leg reading a step env value that is its leg in another case",
            lambda job: job["steps"].append(
                {
                    "env": {"LEG": "${{ matrix.LEG }}"},
                    "run": 'cargo test -p scp-transport && if [ "$LEG" = all ]; '
                    "then ./push-only.sh; fi",
                }
            ),
        ),
        (
            "a push-only leg running a step whose `if:` names its leg in another case",
            lambda job: job["steps"].append(
                {"if": "matrix.leg == 'ALL'", "run": "./scripts/push-only.sh"}
            ),
        ),
        (
            "a push-only leg reading a matrix key an include adds",
            lambda job: job["steps"].append(
                {"run": "cargo test -p scp-transport ${{ matrix['extra'] }}"}
            ),
        ),
        (
            "a push-only leg that runs no command",
            lambda job: [
                step.update({"if": step["if"].replace("matrix.leg == 'all' || ", "")})
                for step in job["steps"]
                if isinstance(step, dict) and "matrix.leg == 'all' || " in str(step.get("if"))
            ],
        ),
    ):
        changed = copy.deepcopy(macos_writer)
        mutate(changed["jobs"]["rust-test-macos"])
        gaps = push_writer_gaps(changed)
        check(
            f"{label} is reported",
            any(
                gap.startswith("rust-test-macos's matrix `leg` runs") and "push-only leg" in gap
                for gap in gaps
            ),
            f"{gaps}",
        )
    # A job key outside `steps` holding the exact `${{ matrix.leg }}` placeholder
    # hands each leg its own value, which a step every leg runs reads with text
    # that is the same on every leg: a job `env:` a step's shell reads, or a
    # `defaults:` working directory a step's relative path resolves under. Both
    # rebuilt jobs with a push-only leg report it; the same keys holding no matrix
    # value report nothing.
    leg_writers = {"rust-test-macos": macos_writer, "rust-clippy": clippy_writer}
    for job_id in ("rust-test-macos", "rust-clippy"):
        for label, key, item, run, reported in (
            (
                "a job env value that is its leg",
                "env",
                {"LEG": "${{ matrix.leg }}"},
                'cargo test -p scp-transport && if [ "$LEG" = all ]; then ./push-only.sh; fi',
                True,
            ),
            (
                "a job defaults working directory named after its leg",
                "defaults",
                {"run": {"working-directory": "legs/${{ matrix.leg }}"}},
                "cargo test -p scp-transport && ./run.sh",
                True,
            ),
            (
                "a job env value that names no matrix axis",
                "env",
                {"LEG": "${{ github.sha }}"},
                'cargo test -p scp-transport && if [ "$LEG" = all ]; then ./push-only.sh; fi',
                False,
            ),
        ):
            changed = copy.deepcopy(leg_writers[job_id])
            job = changed["jobs"][job_id]
            job[key] = item
            job["steps"].append({"run": run})
            gaps = [
                gap
                for gap in push_writer_gaps(changed)
                if gap.startswith(f"{job_id}'s matrix `leg` runs") and "push-only leg" in gap
            ]
            check(
                f"{job_id} with a push-only leg reading {label} is "
                f"{'reported' if reported else 'not reported'}",
                bool(gaps) is reported,
                f"{push_writer_gaps(changed)}",
            )
    # GitHub reads `matrix.leg` and `matrix.LEG` as one name, so a matrix holding
    # both axes leaves a writing step's `matrix.leg` naming neither for certain.
    ambiguous = copy.deepcopy(doc)
    ambiguous["jobs"]["rust-clippy"]["strategy"]["matrix"]["LEG"] = ["workspace"]
    gaps = push_writer_gaps(ambiguous)
    check(
        "a writer matrix holding axes leg and LEG is reported",
        any(gap.startswith("rust-clippy ") and "differ only in case" in gap for gap in gaps),
        f"{gaps}",
    )
    check(
        "the unmutated rust-test matrix is read without a gap",
        not any(gap.startswith("rust-test") for gap in push_writer_gaps(doc)),
        f"{push_writer_gaps(doc)}",
    )
    for job_id in ("rust-test-macos", "rust-clippy"):
        unrelated = copy.deepcopy(leg_writers[job_id])
        unrelated["jobs"][job_id]["steps"].append(
            {"run": "cargo test -p scp-transport ${{ github.sha }}"}
        )
        check(
            f"{job_id} with a step every leg runs under a non-matrix expression "
            "is read without a gap",
            not any(gap.startswith(job_id) for gap in push_writer_gaps(unrelated)),
            f"{push_writer_gaps(unrelated)}",
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

    bun = copy.deepcopy(live)
    bun["jobs"]["error-codes"].setdefault("steps", []).append(
        {"uses": "oven-sh/setup-bun@v2"}
    )
    # The workflows install bun through .github/actions/pinned-tool, so no live job
    # writes the setup-bun cache; this cache-warm stands in for one that does.
    warm_bun = {
        "on": {"push": {"branches": ["main"]}},
        "jobs": {"bun": {"steps": [{"uses": "oven-sh/setup-bun@v2"}]}},
    }
    check(
        "a setup-bun write in a push-skipped job is not reported while a push writes it",
        not skipped_writers(bun) and not push_writer_gaps(bun, warm=warm_bun),
        f"{skipped_writers(bun)} {push_writer_gaps(bun, warm=warm_bun)}",
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
    check(
        "warm_pushed_caches reads a cache-warm job writing the setup-bun cache",
        "the setup-bun executable cache" in warm_pushed_caches(warm_bun),
    )
    gaps = push_writer_gaps(bun, warm={"on": {"push": {"branches": ["main"]}}, "jobs": {}})
    check(
        "no push running any setup-bun writer is reported",
        any("setup-bun executable cache and no push" in gap for gap in gaps),
        f"{gaps}",
    )

    # Every writer reaches the draft gate through `changes`, which carries
    # check-draft's `if:` instead of needing check-draft. A push skip on `changes`
    # is reported as a dependency gap; a push skip on check-draft alone is reported
    # as a divergence between the two draft conditions.
    draft = copy.deepcopy(doc)
    gate = draft["jobs"]["changes"]
    gate["if"] = f"github.event_name != 'push' && ({gate['if']})"
    gaps = dependency_condition_gaps(draft)
    check(
        "a push skip on changes, which every writer needs, is reported",
        any("and changes skips on event push" in gap for gap in gaps),
        f"{gaps}",
    )
    draft = copy.deepcopy(doc)
    gate = draft["jobs"]["check-draft"]
    gate["if"] = f"github.event_name != 'push' && ({gate['if']})"
    gaps = dependency_condition_gaps(draft) + draft_condition_gaps(draft)
    check(
        "a push skip on check-draft is reported",
        any("not check-draft's" in gap for gap in gaps),
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


# CRITERION for macos_bridge_gaps: on a pull_request event, each of the four macOS
# bridge jobs runs only when the `changes` job's `swift` output or `python` output is
# true; those outputs read the `swift` and `python` filters, which between them hold
# bindings/swift/**, bindings/python/**, crates/scp-ffi/uniffi/**,
# crates/scp-ffi/common/** and crates/scp-ffi/src/**, and each ORs in the
# `toolchain` filter; on a
# merge_group event each also runs on the `rust` output; on a push the two producers
# also run on `rust`, because each writes a cache.
#
# INDICATORS, not the criterion: each case below names one file a pull request in
# that path group would touch. A case maps an event to the jobs that run; every job
# MACOS_BRIDGE_JOBS lists and a case leaves out skips. swift-build-test is absent
# from the python case on every event, because it runs a Swift suite whose
# XCFramework no file under bindings/python/ or crates/scp-ffi/src/ reaches.
MACOS_PRODUCERS = frozenset(("pyo3-module-macos", "xcframework"))
MACOS_ALL = frozenset(MACOS_BRIDGE_JOBS)
MACOS_PYTHON = frozenset(("bridge-parity-swift", "pyo3-module-macos", "xcframework"))
MACOS_BRIDGE_PATH_CASES = (
    (
        "crates-only",
        "crates/scp-runtime/src/lib.rs",
        {"pull_request": frozenset(), "merge_group": MACOS_ALL, "push": MACOS_PRODUCERS},
    ),
    (
        "swift",
        "bindings/swift/Package.swift",
        {"pull_request": MACOS_ALL, "merge_group": MACOS_ALL, "push": MACOS_PRODUCERS},
    ),
    (
        "uniffi",
        "crates/scp-ffi/uniffi/src/lib.rs",
        {"pull_request": MACOS_ALL, "merge_group": MACOS_ALL, "push": MACOS_PRODUCERS},
    ),
    (
        "common",
        "crates/scp-ffi/common/src/lib.rs",
        {"pull_request": MACOS_ALL, "merge_group": MACOS_ALL, "push": MACOS_PRODUCERS},
    ),
    (
        "python",
        "bindings/python/pyproject.toml",
        {
            "pull_request": MACOS_PYTHON,
            "merge_group": MACOS_PYTHON,
            "push": MACOS_PRODUCERS,
        },
    ),
    (
        "pyo3",
        "crates/scp-ffi/src/lib.rs",
        {"pull_request": MACOS_PYTHON, "merge_group": MACOS_ALL, "push": MACOS_PRODUCERS},
    ),
)

STEP_FILTER_OUTPUT = re.compile(r"steps\.filter\.outputs\.([A-Za-z0-9_-]+)")


def changed_path_outputs(doc: dict, path: str) -> dict[str, str]:
    """Return the outputs `changes` publishes when a run changes one file.

    Every output in ci.yml ORs together `steps.filter.outputs.<key> == 'true'`
    comparisons, or reads one key bare, so an output is true when any filter it
    names lists a pattern selecting the path. An output naming no filter key, or a
    key the filter step does not define, raises, which stops the check rather than
    publishing a "false" no run would publish.
    """
    filters = path_filters(doc["jobs"])
    outputs: dict[str, str] = {}
    for name, expression in (doc["jobs"]["changes"].get("outputs") or {}).items():
        keys = STEP_FILTER_OUTPUT.findall(str(expression))
        if not keys or any(key not in filters for key in keys):
            raise ValueError(f"`changes` output {name!r} reads {keys}, not a filter key")
        selected = any(pattern_covers(set(filters[key]), path) for key in keys)
        outputs[name] = "true" if selected else "false"
    return outputs


def macos_bridge_gaps(doc: dict) -> list[str]:
    """Return each (path group, event) whose macOS bridge jobs differ from the cases."""
    gaps: list[str] = []
    for label, path, expected in MACOS_BRIDGE_PATH_CASES:
        try:
            outputs = changed_path_outputs(doc, path)
            for event, runs in expected.items():
                actual = {
                    job_id
                    for job_id in MACOS_BRIDGE_JOBS
                    if selects(doc["jobs"][job_id].get("if") or "true == 'true'", outputs, event)
                }
                if actual != runs:
                    gaps.append(
                        f"{label} ({path}), {event}: runs {sorted(actual)}, "
                        f"expected {sorted(runs)}"
                    )
        except ValueError as unreadable:
            gaps.append(f"{label} ({path}): this check cannot decide ({unreadable})")
    return gaps


def check_macos_bridges_follow_their_paths(doc: dict) -> None:
    for job_id in MACOS_BRIDGE_JOBS:
        check(f"ci.yml defines macOS bridge job {job_id}", job_id in doc["jobs"])
    gaps = macos_bridge_gaps(doc)
    check(
        "ci.yml: a pull request runs the macOS bridge jobs only on their paths, the "
        "merge queue on Rust too, and a push runs both producers on Rust",
        not gaps,
        "; ".join(gaps),
    )


def check_macos_bridge_mutants(doc: dict) -> None:
    """Each way of breaking the macOS bridge rule is reported."""
    guard = "(github.event_name != 'pull_request' && needs.changes.outputs.rust == 'true')"
    crates_only = "crates-only (crates/scp-runtime/src/lib.rs)"

    def with_condition(job_id: str, old: str, new: str) -> dict:
        mutant = copy.deepcopy(doc)
        current = " ".join(str(mutant["jobs"][job_id]["if"]).split())
        check(f"{job_id}'s `if:` holds {old!r} for the mutant", old in current, current)
        mutant["jobs"][job_id]["if"] = current.replace(old, new)
        return mutant

    def reported(mutant: dict, fragment: str) -> tuple[bool, str]:
        gaps = macos_bridge_gaps(mutant)
        return any(fragment in gap for gap in gaps), "; ".join(gaps) or "no gap reported"

    for job_id in MACOS_BRIDGE_JOBS:
        # The `rust` clause read on pull requests too, as it was before this rule.
        mutant = with_condition(job_id, guard, "needs.changes.outputs.rust == 'true'")
        found, detail = reported(mutant, f"{crates_only}, pull_request")
        check(f"{job_id} running on a crates-only pull request is reported", found, detail)
        check(
            f"{job_id} running on a crates-only pull request disagrees with SCENARIOS",
            any(
                f"rust-only, pull_request: {job_id} runs" in line
                for line in scenario_disagreements(mutant)
            ),
            f"{scenario_disagreements(mutant)}",
        )
        # The `rust` clause dropped from the merge queue as well.
        mutant = with_condition(
            job_id, guard, "(github.event_name == 'push' && needs.changes.outputs.rust == 'true')"
        )
        found, detail = reported(mutant, f"{crates_only}, merge_group")
        check(f"{job_id} skipping a crates-only merge_group run is reported", found, detail)

    for job_id in sorted(MACOS_PRODUCERS):
        # The `rust` clause dropped from push, which leaves the producer's cache stale.
        mutant = with_condition(
            job_id,
            guard,
            "(github.event_name == 'merge_group' && needs.changes.outputs.rust == 'true')",
        )
        found, detail = reported(mutant, f"{crates_only}, push")
        check(f"{job_id} skipping a crates-only push is reported", found, detail)
        check(
            f"{job_id} skipping a crates-only push is a push-writer gap",
            any(gap.startswith(f"{job_id} writes") for gap in push_writer_gaps(mutant)),
            f"{push_writer_gaps(mutant)}",
        )

    # Each path group, dropped from the clause that routes it.
    python_pr = "python (bindings/python/pyproject.toml), pull_request"
    swift_pr = "swift (bindings/swift/Package.swift), pull_request"
    for job_id, clause, fragment in (
        ("xcframework", "python", python_pr),
        ("pyo3-module-macos", "python", python_pr),
        ("bridge-parity-swift", "python", python_pr),
        ("xcframework", "swift", swift_pr),
        ("pyo3-module-macos", "swift", swift_pr),
        ("swift-build-test", "swift", swift_pr),
        ("bridge-parity-swift", "swift", swift_pr),
    ):
        mutant = with_condition(job_id, f"needs.changes.outputs.{clause} == 'true' || ", "")
        found, detail = reported(mutant, fragment)
        check(f"{job_id} without its {clause} clause is reported", found, detail)

    # Each path group, dropped from the filter that routes it.
    for label, patterns, fragment in (
        (
            "the uniffi path dropped from the swift filter",
            {"swift": "crates/scp-ffi/uniffi/**"},
            "uniffi (crates/scp-ffi/uniffi/src/lib.rs), pull_request",
        ),
        (
            "the common path dropped from the swift and python filters",
            {"swift": "crates/scp-ffi/common/**", "python": "crates/scp-ffi/common/**"},
            "common (crates/scp-ffi/common/src/lib.rs), pull_request",
        ),
        ("bindings/swift dropped from the swift filter", {"swift": "bindings/swift/**"}, swift_pr),
        (
            "bindings/python dropped from the python filter",
            {"python": "bindings/python/**"},
            python_pr,
        ),
        (
            "the PyO3 bridge path dropped from the python filter",
            {"python": "crates/scp-ffi/src/**"},
            "pyo3 (crates/scp-ffi/src/lib.rs), pull_request",
        ),
    ):
        mutant = copy.deepcopy(doc)
        step = next(
            step
            for step in mutant["jobs"]["changes"]["steps"]
            if str(step.get("uses") or "").startswith("dorny/paths-filter")
        )
        filters = yaml.safe_load(step["with"]["filters"])
        for key, pattern in patterns.items():
            check(f"filter {key} lists {pattern} for the mutant", pattern in filters[key])
            filters[key] = [entry for entry in filters[key] if entry != pattern]
        step["with"]["filters"] = yaml.safe_dump(filters)
        found, detail = reported(mutant, fragment)
        check(f"{label} is reported", found, detail)


# CRITERION for unrouted_paths: a tracked path is routed when the `code` output
# of job `changes` selects it or when it is prose. Prose is every path under
# `.docs/` or `.claude/` except `.docs/migration/`, every `*.md` file at the
# repository root, and every `*.md` file under `docs/guides/`. A pull request that
# changes only prose skips every job the `code` output guards, so a path that is
# neither reaches no such job when it alone changes, whatever that job reads. The
# guides under `.docs/migration/` are not prose, because job examples-typecheck
# type-checks their code blocks.
def is_prose(path: str) -> bool:
    """Report whether a tracked path is prose, which no `code`-guarded job reads."""
    if path.startswith(".docs/migration/"):
        return False
    if path.startswith((".docs/", ".claude/")):
        return True
    if path.endswith(".md"):
        return "/" not in path or path.startswith("docs/guides/")
    return False


def unrouted_paths(doc: dict, paths: list[str]) -> list[str]:
    """Return each path the `code` output does not select and that is not prose.

    The `code` output ORs filter keys together the way every other output does,
    so a path counts as selected when any filter that output names lists a
    pattern covering it; pattern_covers reads a pattern shape it does not know as
    covering nothing, which reports a path rather than passing it.
    """
    patterns = output_patterns(doc, "code")
    if isinstance(patterns, str):
        return [patterns]
    return [path for path in paths if not is_prose(path) and not pattern_covers(patterns, path)]


def output_patterns(doc: dict, output: str) -> set[str] | str:
    """Every pattern of every filter the `changes` output `output` reads, or an error."""
    filters = path_filters(doc["jobs"])
    expression = (doc["jobs"]["changes"].get("outputs") or {}).get(output)
    if expression is None:
        return f"`changes` publishes no `{output}` output"
    keys = STEP_FILTER_OUTPUT.findall(str(expression))
    missing = [key for key in keys if key not in filters]
    if not keys or missing:
        return f"`changes` output `{output}` reads {keys}, not a filter key"
    return set().union(*(filters[key] for key in keys))


# CRITERION for rust_test_reads: a path outside `crates/` is a rust-test input when a
# `crates/**/*.rs` source names it, or names a directory above it, in one of the forms
# rust_read_form_violations admits as the only ways a Rust source reaches outside its
# crate: the literal of an `include_str!`, `include_bytes!` or `#[path = ...]`, resolved
# against the source's directory, and the argument of a `workspace_root().join(...)`,
# a string literal or a `const` bound to one in the same file, resolved against the
# repository root. Because rust_read_form_violations rejects every other way to name a
# path outside the crate, the scan's result is the set of paths outside `crates/` that
# any Rust test can read. An entry that names a tracked directory ends in `/` and stands
# for every tracked path under it. Reads inside `crates/` are dropped: the `rust` output
# selects all of `crates/**`.
#
# The one input this form does not follow is a path a test computes from data and
# joins onto a literal-rooted directory, such as key_state_params.rs joining a module's
# `#[path]` target onto `crates/`; the read sits under that directory, which the scan
# reports, unless the data itself climbs out of it with `..`.
# A rust-test input that no filter routes to rust-test, mapped to the name of the
# always-on step in job `toolchain-wiring` that asserts what rust-test asserts of it.
RUST_TEST_MIRRORED = {"AGENTS.md": "AGENTS.md keeps its enforcement sections"}
RUST_INCLUDE_LITERAL = re.compile(
    r'(?:include_(?:str|bytes)!\(\s*|#\[path\s*=\s*)"((?:[^"\\]|\\.)*)"', re.DOTALL
)
RUST_WORKSPACE_JOIN = re.compile(r'workspace_root\(\)\??\s*\.join\(\s*(?:"([^"]*)"|([A-Z][A-Z0-9_]*))\s*\)')
RUST_STR_CONST = re.compile(r'const ([A-Z][A-Z0-9_]*): &(?:\'static )?str = "([^"]*)";')
# The one admitted definition of `workspace_root`, `N` levels above the manifest
# of the crate that holds the source, which rust_read_form_violations checks. A
# crate whose tests deny `expect` returns the root in a `Result` instead.
RUST_WORKSPACE_ROOT_FN = re.compile(
    r"fn workspace_root\(\) -> (?:(?:std::path::)?PathBuf|Result<(?:std::path::)?PathBuf, \w+>) \{\s*(?:Ok\()?"
    r'(?:std::path::)?Path::new\(env!\("CARGO_MANIFEST_DIR"\)\)\s*\.ancestors\(\)\s*\.nth\((\d+)\)\s*'
    r'(?:\.expect\(\s*"[^"]*"\s*\)|\.ok_or\(\s*"[^"]*"\s*\)\?)\s*\.to_path_buf\(\)\s*\)?\s*\}'
)
# A path inside the crate: the manifest directory joined with, or concatenated to, a
# literal. A literal that climbs with `..` is reported.
RUST_MANIFEST_JOIN = re.compile(
    r'(?:std::path::)?(?:Path::new|PathBuf::from)\(env!\("CARGO_MANIFEST_DIR"\)\)\s*\.join\(\s*"([^"]*)"\s*\)'
    r'|concat!\(\s*env!\("CARGO_MANIFEST_DIR"\),\s*"(/[^"]*)"\s*\)'
)
RUST_STRING_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')
RUST_PARENT_SEGMENT = re.compile(r"(^|/)\.\.(/|$)")
# Locating the repository by any of these is not an admitted form.
RUST_OTHER_ROOTS = ("CARGO_WORKSPACE_DIR", "GITHUB_WORKSPACE", "file!()")


def _rust_code(text: str) -> str:
    """The source without its whole-line comments, which name paths in prose."""
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _tracked_dirs(paths: list[str]) -> set[str]:
    dirs = set()
    for path in paths:
        parent = posixpath.dirname(path)
        while parent:
            dirs.add(parent)
            parent = posixpath.dirname(parent)
    return dirs


def rust_test_reads(
    sources: dict[str, str], paths: list[str] | None = None, dirs: set[str] | None = None
) -> set[str]:
    """Each path outside `crates/` that a `crates/` source can read, a tracked directory ending in `/`.

    `dirs`, when given, is `_tracked_dirs(paths)`, which a caller scanning one source at a
    time computes once.
    """
    if dirs is None:
        dirs = _tracked_dirs(paths) if paths is not None else set()
    reads = set()
    for source, raw in sources.items():
        text = _rust_code(raw)
        for match in RUST_INCLUDE_LITERAL.finditer(text):
            # A backslash before a newline continues a Rust string literal past it.
            literal = re.sub(r"\\\n\s*", "", match.group(1))
            reads.add(posixpath.normpath(posixpath.join(posixpath.dirname(source), literal)))
        consts = dict(RUST_STR_CONST.findall(text))
        for match in RUST_WORKSPACE_JOIN.finditer(text):
            literal = match.group(1) if match.group(1) is not None else consts.get(match.group(2))
            if literal is not None:
                reads.add(posixpath.normpath(literal))
    return {
        f"{path}/" if path in dirs else path
        for path in reads
        if not f"{path}/".startswith("crates/")
    }


def rust_read_form_violations(sources: dict[str, str], paths: list[str]) -> list[str]:
    """Each place a `crates/` source reaches outside its crate in a form rust_test_reads does not read.

    Admitted: an include or `#[path]` literal; the one `workspace_root` definition, at
    the depth of the source's crate; `workspace_root()` followed by `.join` of a
    literal or of a `const` bound to one, or passed to `strip_prefix`; and the manifest
    directory joined with or concatenated to a literal that does not climb with `..`.
    Reported: any other `CARGO_MANIFEST_DIR`, any other `workspace_root()` or
    `workspace_root` definition, a repository root found another way, and a string
    literal that climbs with `..` to a tracked path outside `crates/` from the crate's
    directory, where a test runs, or from the source's own directory.
    """
    tracked = set(paths)
    dirs = _tracked_dirs(paths)
    manifests = sorted(
        (posixpath.dirname(p) for p in paths if p.startswith("crates/") and p.endswith("/Cargo.toml")),
        key=len,
        reverse=True,
    )
    found = []
    for source, raw in sorted(sources.items()):
        crate = next((m for m in manifests if source.startswith(f"{m}/")), None)
        if crate is None:
            found.append(f"{source}: no Cargo.toml above it under crates/")
            continue
        text = _rust_code(raw)
        depth = crate.count("/") + 1
        for match in RUST_WORKSPACE_ROOT_FN.finditer(text):
            if int(match.group(1)) != depth:
                found.append(f"{source}: workspace_root climbs {match.group(1)} levels from a crate {depth} deep")
        rest = RUST_WORKSPACE_ROOT_FN.sub("", text)
        for match in RUST_MANIFEST_JOIN.finditer(rest):
            literal = match.group(1) if match.group(1) is not None else match.group(2)
            if RUST_PARENT_SEGMENT.search(literal):
                found.append(f"{source}: CARGO_MANIFEST_DIR joined with {literal!r}")
        rest = RUST_MANIFEST_JOIN.sub("", rest)
        if "CARGO_MANIFEST_DIR" in rest:
            found.append(f"{source}: CARGO_MANIFEST_DIR outside workspace_root and a literal join")
        if "fn workspace_root" in rest:
            found.append(f"{source}: a workspace_root other than the one admitted definition")
        consts = dict(RUST_STR_CONST.findall(text))
        for match in RUST_WORKSPACE_JOIN.finditer(rest):
            if match.group(2) is not None and match.group(2) not in consts:
                found.append(f"{source}: workspace_root().join({match.group(2)}), no const bound to a literal")
        loose = re.sub(r"strip_prefix\(\s*&?workspace_root\(\)\??\s*\)", "", RUST_WORKSPACE_JOIN.sub("", rest))
        if "workspace_root()" in loose:
            found.append(f"{source}: workspace_root() not followed by .join of a literal")
        for name in RUST_OTHER_ROOTS:
            if name in text:
                found.append(f"{source}: locates the repository through {name}")
        literals = RUST_INCLUDE_LITERAL.sub("", text)
        for match in RUST_STRING_LITERAL.finditer(literals):
            literal = match.group(1)
            if not RUST_PARENT_SEGMENT.search(literal):
                continue
            for base in (crate, posixpath.dirname(source)):
                target = posixpath.normpath(posixpath.join(base, literal))
                if target.startswith("..") or f"{target}/".startswith("crates/"):
                    continue
                if target in tracked or target in dirs or target == ".":
                    found.append(f"{source}: literal {literal!r} reaches {target} from {base}")
                    break
    return found


def crate_sources(paths: list[str]) -> dict[str, str]:
    """The text of every tracked `crates/**/*.rs` path."""
    return {
        path: (REPO / path).read_text(encoding="utf-8")
        for path in paths
        if path.startswith("crates/") and path.endswith(".rs")
    }


def rust_test_inputs_unselected(doc: dict, paths: list[str], reads: set[str]) -> list[str]:
    """Return each tracked rust-test input neither `rust` nor `rust-prose` selects and no step mirrors.

    A read only `rust-prose` selects is routed to job rust-test-prose, and
    check_rust_prose_readers requires that job to run every test target that reads it.
    """
    patterns = output_patterns(doc, "rust")
    if isinstance(patterns, str):
        return [patterns]
    prose = output_patterns(doc, RUST_PROSE_OUTPUT)
    if isinstance(prose, str):
        return [prose]
    under = tuple(entry for entry in reads if entry.endswith("/"))
    inputs = [path for path in paths if path in reads or path.startswith(under)]
    return [
        path
        for path in inputs
        if path not in RUST_TEST_MIRRORED and not pattern_covers(patterns, path) and not pattern_covers(prose, path)
    ]


# CRITERION for check_rust_prose_readers: a pull request that edits only files the
# `rust-prose` output selects and `rust` does not runs job rust-test-prose and none of
# the `rust` lanes, so every test that reads such a file must be one rust-test-prose
# runs, and the file must change no shipped code. A `crates/` source that reads one
# (rust_test_reads, per source) is therefore either a test target's root, named by a
# `[[test]]` path or auto-discovered as `tests/<name>.rs` or `tests/<name>/main.rs`,
# or a library source under `src/` whose every such read sits inside a
# `#[cfg(test)] mod` block that opens and closes at column 0, which rustfmt guarantees
# for a top-level module. Any other reader, a submodule of a test target among them,
# is reported. The (package, target) pairs these sources compile into must equal the
# pairs rust-test-prose's commands select, so the job runs no target that reads none
# of them. Non-Rust readers need no rule here: check_binding_test_reads and
# check_script_reads require each reading job's outputs to select what it reads, and
# no output but `rust-prose` selects these files.
RUST_PROSE_OUTPUT = "rust-prose"
RUST_PROSE_JOB = "rust-test-prose"
RUST_CFG_TEST_MOD = re.compile(r"(?m)^#\[cfg\(test\)\]\n(?:#\[[^\n]*\]\n)*(?:pub(?:\([^)]*\))? )?mod \w+ \{\n")


def _rust_read_sites(text: str) -> list[tuple[int, str]]:
    """(offset, path) of each include literal and workspace_root join in `text`, as rust_test_reads resolves them."""
    sites = []
    for match in RUST_INCLUDE_LITERAL.finditer(text):
        sites.append((match.start(), re.sub(r"\\\n\s*", "", match.group(1))))
    consts = dict(RUST_STR_CONST.findall(text))
    for match in RUST_WORKSPACE_JOIN.finditer(text):
        literal = match.group(1) if match.group(1) is not None else consts.get(match.group(2))
        if literal is not None:
            sites.append((match.start(), f"//{literal}"))
    return sites


def rust_prose_reader_targets(
    sources: dict[str, str], paths: list[str], routed: set[str]
) -> tuple[set[tuple[str, str]], list[str]]:
    """Return the (package, target) pairs whose sources read a `routed` path, and each reader that is not test code."""
    tracked = set(paths)
    dirs = _tracked_dirs(paths)
    manifests = sorted(
        (posixpath.dirname(p) for p in paths if p.startswith("crates/") and p.endswith("/Cargo.toml")),
        key=len,
        reverse=True,
    )

    def hits(read: str) -> bool:
        return read in routed or (read.endswith("/") and any(p.startswith(read) for p in routed))

    def resolved(source: str, literal: str) -> str:
        if literal.startswith("//"):
            path = posixpath.normpath(literal[2:])
        else:
            path = posixpath.normpath(posixpath.join(posixpath.dirname(source), literal))
        return f"{path}/" if path in dirs else path

    targets: set[tuple[str, str]] = set()
    found: list[str] = []
    for source, raw in sorted(sources.items()):
        if not any(hits(read) for read in rust_test_reads({source: raw}, dirs=dirs)):
            continue
        crate = next((m for m in manifests if source.startswith(f"{m}/")), None)
        if crate is None:
            found.append(f"{source}: no Cargo.toml above it under crates/")
            continue
        manifest = tomllib.loads((REPO / crate / "Cargo.toml").read_text(encoding="utf-8")) if (
            f"{crate}/Cargo.toml" in tracked and (REPO / crate / "Cargo.toml").exists()
        ) else {}
        package = str((manifest.get("package") or {}).get("name") or posixpath.basename(crate))
        rel = source[len(crate) + 1 :]
        named = {str(t.get("path")): str(t.get("name")) for t in manifest.get("test") or []}
        auto = (manifest.get("package") or {}).get("autotests", True)
        stem = re.fullmatch(r"tests/([\w-]+)\.rs|tests/([\w-]+)/main\.rs", rel)
        if rel in named:
            targets.add((package, f"test:{named[rel]}"))
        elif stem and auto:
            targets.add((package, f"test:{stem.group(1) or stem.group(2)}"))
        elif rel.startswith("src/") and not rel.startswith("src/bin/") and rel != "src/main.rs":
            text = _rust_code(raw)
            blocks = []
            for match in RUST_CFG_TEST_MOD.finditer(text):
                end = text.find("\n}\n", match.end() - 1)
                blocks.append((match.start(), len(text) if end < 0 else end))
            outside = [
                path
                for offset, literal in _rust_read_sites(text)
                if hits(path := resolved(source, literal))
                and not any(start <= offset < end for start, end in blocks)
            ]
            if outside:
                found.append(f"{source}: reads {outside} outside a #[cfg(test)] module, so the file ships")
            else:
                targets.add((package, "lib"))
        else:
            found.append(f"{source}: reads routed prose and is neither a test target's root nor library test code")
    return targets, found


def rust_prose_job_targets(doc: dict) -> set[tuple[str, str]]:
    """The (package, target) pairs the `cargo nextest run` commands of job rust-test-prose select."""
    selected: set[tuple[str, str]] = set()
    for step in (doc["jobs"].get(RUST_PROSE_JOB) or {}).get("steps") or []:
        for line in str(step.get("run") or "").splitlines():
            tokens = shlex.split(line.strip())
            if tokens[:3] != ["cargo", "nextest", "run"]:
                continue
            packages = [tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t == "-p"]
            chosen = ["lib" for t in tokens if t == "--lib"] + [
                f"test:{tokens[i + 1]}" for i, t in enumerate(tokens[:-1]) if t == "--test"
            ]
            selected |= {(package, target) for package in packages for target in chosen}
    return selected


def rust_prose_routed(doc: dict, paths: list[str]) -> set[str] | str:
    """Each tracked path the `rust-prose` output selects and `rust` does not."""
    rust = output_patterns(doc, "rust")
    prose = output_patterns(doc, RUST_PROSE_OUTPUT)
    for patterns in (rust, prose):
        if isinstance(patterns, str):
            return patterns
    return {path for path in paths if pattern_covers(prose, path) and not pattern_covers(rust, path)}


def check_rust_prose_readers(doc: dict, paths: list[str], sources: dict[str, str]) -> None:
    routed = rust_prose_routed(doc, paths)
    check("ci.yml: `changes` publishes the `rust-prose` output", not isinstance(routed, str), f"{routed}")
    if isinstance(routed, str):
        return
    check(
        "the `rust-prose` output selects only prose",
        routed and all(is_prose(path) for path in routed),
        f"{sorted(p for p in routed if not is_prose(p))[:10]}",
    )
    derived, found = rust_prose_reader_targets(sources, paths, routed)
    check("every Rust reader of `rust-prose` files is test code", not found, f"{found[:10]}")
    job = rust_prose_job_targets(doc)
    check(
        "job rust-test-prose runs exactly the test targets that read `rust-prose` files",
        bool(derived) and derived == job,
        f"derived {sorted(derived)}, job {sorted(job)}",
    )
    for expected in (
        ("scp-testing", "test:ffi_conformance"),
        ("scp-testing", "test:trust"),
        ("scp-protocol", "lib"),
        ("scp-event-log", "lib"),
    ):
        check(f"the reader scan derives {expected[0]} {expected[1]}", expected in derived)
    # Must fail: a library source that reads routed prose outside a test module, a
    # test-target submodule that reads it, and a new test root whose target the job
    # does not run. Must pass: the read inside a #[cfg(test)] module.
    adr = next(path for path in sorted(routed) if path.startswith(".docs/adrs/"))
    climb = "../../../" + adr
    planted = {
        "crates/scp-kel/src/planted.rs": f'const S: &str = include_str!("{climb}");\n',
        "crates/scp-kel/tests/kel/planted.rs": f'const S: &str = include_str!("../{climb}");\n',
    }
    _, reported = rust_prose_reader_targets(planted, paths, routed)
    check(
        "a library read outside #[cfg(test)] and a test-target submodule read are each reported",
        len(reported) == 2 and "outside a #[cfg(test)]" in reported[0] and "neither" in reported[1],
        f"{reported}",
    )
    inside = {
        "crates/scp-kel/src/planted.rs": (
            f'pub fn f() {{}}\n\n#[cfg(test)]\nmod tests {{\n    const S: &str = include_str!("{climb}");\n}}\n'
        ),
    }
    targets, reported = rust_prose_reader_targets(inside, paths, routed)
    check(
        "a read inside a #[cfg(test)] module derives the crate's lib target",
        not reported and targets == {("scp-kel", "lib")},
        f"{targets} {reported}",
    )
    root = {"crates/scp-kel/tests/planted_root.rs": f'const S: &str = include_str!("{climb}");\n'}
    targets, _ = rust_prose_reader_targets(root, paths, routed)
    check(
        "a new test root that reads routed prose derives a target the job does not run",
        targets == {("scp-kel", "test:planted_root")} and not targets <= job,
        f"{targets}",
    )
    mutant = copy.deepcopy(doc)
    for step in mutant["jobs"][RUST_PROSE_JOB]["steps"]:
        if "--test trust" in str(step.get("run") or ""):
            step["run"] = str(step["run"]).replace(" --test trust", "")
    check(
        "a rust-test-prose job that drops `--test trust` no longer matches the derived targets",
        rust_prose_job_targets(mutant) == job - {("scp-testing", "test:trust")},
    )


def tracked_paths() -> list[str]:
    """Every path `git ls-files` lists in this checkout."""
    proc = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    return [path for path in proc.stdout.decode().split("\0") if path]


def check_every_path_routed(doc: dict) -> None:
    paths = tracked_paths()
    check("git ls-files lists this checkout's own ci.yml", ".github/workflows/ci.yml" in paths)
    gaps = unrouted_paths(doc, paths)
    check(
        "ci.yml: every tracked path is prose or selected by the `code` output",
        not gaps,
        f"{len(gaps)} unrouted: {gaps[:20]}",
    )
    # Controls: an unclassified root file, a non-Markdown file under docs/guides/,
    # and a nested Markdown file outside docs/guides/ are each reported; prose is not.
    planted = ["newtool.cfg", "docs/guides/diagram.svg", "docs/notes/plan.md"]
    check(
        "an unrouted path planted beside the tracked ones is reported",
        unrouted_paths(doc, paths + planted) == gaps + planted,
        f"{unrouted_paths(doc, paths + planted)}",
    )
    check(
        "prose paths are not reported",
        not unrouted_paths(doc, ["AGENTS.md", ".docs/specs/x.md", ".claude/a/b.json", "docs/guides/g.md"]),
    )
    mutant = copy.deepcopy(doc)
    step = next(
        step
        for step in mutant["jobs"]["changes"]["steps"]
        if str(step.get("uses") or "").startswith("dorny/paths-filter")
    )
    filters = yaml.safe_load(step["with"]["filters"])
    check("filter code lists 'scripts/**' for the mutant", "scripts/**" in filters["code"])
    filters["code"] = [entry for entry in filters["code"] if entry != "scripts/**"]
    step["with"]["filters"] = yaml.safe_dump(filters)
    check(
        "a `code` filter that drops scripts/** reports scripts/ci-aggregate-result.py",
        "scripts/ci-aggregate-result.py" in unrouted_paths(mutant, paths),
    )
    filters["code"] = [entry for entry in filters["code"] if entry != ".docs/migration/**"]
    step["with"]["filters"] = yaml.safe_dump(filters)
    check(
        "a `code` filter that drops .docs/migration/** reports .docs/migration/phase-4.md",
        ".docs/migration/phase-4.md" in unrouted_paths(mutant, paths),
    )
    sources = crate_sources(paths)
    reads = rust_test_reads(sources, paths)
    # Controls for the scan: a read on one line, a read whose literal continues past a
    # backslash-newline, a workspace_root join of a literal and of a const, a read of a
    # prose file, and a directory each test walks are each found.
    for known in (
        "bindings/python/scp_sdk/identity.py",
        "scripts/tests/bridge-symmetry/fixtures/bad-alias-in-test-module-only/crates/scp-ffi/napi/src/widgets.rs",
        "scripts/pure-helpers-allowlist.txt",
        "bindings/python/scp_sdk/governance.py",
        "AGENTS.md",
        ".docs/standards/sdk-common.md",
        ".docs/adrs/",
        ".docs/prds/",
        "bindings/kotlin/scp-kt-android/src/main/",
        "fuzz/corpus/fuzz_kel_decode_event/",
    ):
        check(f"the include and workspace_root scan finds rust-test input {known}", known in reads)
    missing = sorted(
        entry for entry in reads if entry not in set(paths) and not any(p.startswith(entry) for p in paths)
    )
    check("every path the scan resolves is tracked", not missing, f"{missing[:10]}")
    planted = {
        "crates/a/tests/t.rs": 'include_bytes!(\n    "../../../new/\\\n     x.bin"\n); include_str!("../src/y.rs");',
        "crates/b/src/lib.rs": 'workspace_root().join("new/z.txt")\nconst F: &str = "new/c.txt";\nworkspace_root().join(F)',
        "crates/b/src/m.rs": '#[path = "../../../new/m.rs"]\nmod m;\n// workspace_root().join("new/comment.txt")',
    }
    check(
        "the scan resolves planted reads and drops a read inside crates/ and one in a comment",
        rust_test_reads(planted) == {"new/x.bin", "new/z.txt", "new/c.txt", "new/m.rs"},
        f"{rust_test_reads(planted)}",
    )
    violations = rust_read_form_violations(sources, paths)
    check(
        "every crates/ source reaches outside its crate only in a form rust_test_reads reads",
        not violations,
        f"{violations[:10]}",
    )
    canonical = (
        "fn workspace_root() -> PathBuf {\n    Path::new(env!(\"CARGO_MANIFEST_DIR\"))\n        .ancestors()\n"
        '        .nth(2)\n        .expect("x")\n        .to_path_buf()\n}\n'
    )
    # Must fail: each source below reaches outside its crate in a form the scan does
    # not read. Must pass: the admitted forms, in the last source.
    for label, text in (
        ("a manifest join that climbs", 'Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.docs/x.md")'),
        ("a manifest parent", 'PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent()'),
        ("a manifest popped", 'let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));\np.pop();'),
        ("a workspace_root bound to a name", canonical + "let root = workspace_root();\nroot.join(x)"),
        ("a workspace_root joined with a variable", canonical + "workspace_root().join(name)"),
        ("a workspace_root joined with an unbound const", canonical + "workspace_root().join(NAME)"),
        ("a workspace_root one level short", canonical.replace(".nth(2)", ".nth(1)")),
        ("a workspace_root of another shape", 'fn workspace_root() -> PathBuf { PathBuf::from("/") }'),
        ("a cwd-relative literal that climbs to prose", 'std::fs::read("../../AGENTS.md")'),
        ("a source-relative literal that climbs to the root", 'let r = Path::new("../../..");'),
        ("GITHUB_WORKSPACE", 'std::env::var("GITHUB_WORKSPACE")'),
    ):
        reported = rust_read_form_violations({"crates/scp-kel/tests/planted.rs": text}, paths)
        check(f"rust_read_form_violations reports {label}", bool(reported), f"{reported}")
    admitted = (
        canonical
        + 'const F: &str = "AGENTS.md";\nworkspace_root().join(F);\nworkspace_root().join(".docs/adrs");\n'
        + "p.strip_prefix(&workspace_root());\n"
        + 'Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/x");\n'
        + 'include_str!("../../../AGENTS.md");\n'
        + 'let traversal = "../../etc/passwd";\nlet sibling = "../scp-did/src";\n'
        + '// Path::new(env!("CARGO_MANIFEST_DIR")).parent()\n'
    )
    fallible = (
        "fn workspace_root() -> Result<PathBuf, Error> {\n    Ok(Path::new(env!(\"CARGO_MANIFEST_DIR\"))\n"
        '        .ancestors()\n        .nth(2)\n        .ok_or("x")?\n        .to_path_buf())\n}\n'
        'workspace_root()?.join("fuzz/corpus/fuzz_kel_decode_event");\n'
    )
    reported = rust_read_form_violations(
        {"crates/scp-kel/tests/planted.rs": admitted, "crates/scp-kel/tests/fallible.rs": fallible}, paths
    )
    check("rust_read_form_violations admits the forms rust_test_reads reads", not reported, f"{reported}")
    check(
        "rust_test_reads follows a fallible workspace_root join",
        rust_test_reads({"crates/scp-kel/tests/fallible.rs": fallible}) == {"fuzz/corpus/fuzz_kel_decode_event"},
    )
    wiring_runs = {
        str(step.get("name")): str(step.get("run") or "") for step in doc["jobs"]["toolchain-wiring"].get("steps") or []
    }
    for path, step_name in RUST_TEST_MIRRORED.items():
        check(f"rust-test reads mirrored input {path}", path in reads)
        check(f"job toolchain-wiring runs step '{step_name}' over {path}", path in wiring_runs.get(step_name, ""))
    gaps = rust_test_inputs_unselected(doc, paths, reads)
    check("ci.yml: the `rust` output selects every file rust-test reads", not gaps, f"{gaps[:20]}")
    check(
        "a planted rust-test read that no filter selects is reported",
        rust_test_inputs_unselected(doc, [*paths, "new/x.bin"], reads | {"new/x.bin"}) == [*gaps, "new/x.bin"],
    )
    check(
        "the `rust` output does not select a spec file rust-test never reads",
        not pattern_covers(output_patterns(doc, "rust"), ".docs/specs/01-thesis.md"),
    )
    mutant = copy.deepcopy(doc)
    step = next(
        step
        for step in mutant["jobs"]["changes"]["steps"]
        if str(step.get("uses") or "").startswith("dorny/paths-filter")
    )
    filters = yaml.safe_load(step["with"]["filters"])
    dropped = (".docs/adrs/**", "bindings/python/scp_sdk/**")
    check(
        f"filters rust-prose and rust list {dropped} for the mutant",
        dropped[0] in filters[RUST_PROSE_OUTPUT] and dropped[1] in filters["rust"],
    )
    filters[RUST_PROSE_OUTPUT] = [entry for entry in filters[RUST_PROSE_OUTPUT] if entry != dropped[0]]
    filters["rust"] = [entry for entry in filters["rust"] if entry != dropped[1]]
    step["with"]["filters"] = yaml.safe_dump(filters)
    unselected = rust_test_inputs_unselected(mutant, paths, reads)
    under = tuple(entry for entry in reads if entry.endswith("/"))
    expected = [
        p
        for p in paths
        if p.startswith(".docs/adrs/") or ((p in reads or p.startswith(under)) and p.startswith("bindings/python/"))
    ]
    check(
        f"filters that drop {dropped} report every ADR file and every Python SDK file rust-test reads",
        bool(unselected) and unselected == expected,
        f"{unselected[:5]}",
    )
    check_rust_prose_readers(doc, paths, sources)


# CRITERION for binding_test_scan: a test source under `bindings/` or `tests/` names a
# path outside its own directory in exactly one form per language, and the scan reads
# that form. A definition binds one name to the source's own location climbed a fixed
# number of levels: Python `NAME = Path(__file__).resolve()` followed by `.parents[N]`
# or `.parent` and `/` joins of literals; TypeScript
# `const NAME = fileURLToPath(new URL("<literal>", import.meta.url))`, `import.meta.dir`
# or `dirname(fileURLToPath(import.meta.url))`; Swift
# `let NAME = URL(fileURLWithPath: #filePath)` followed by `.deletingLastPathComponent()`
# calls; Kotlin `val NAME = File(System.getProperty("user.dir"))` followed by
# `.parentFile` steps, where `user.dir` is the Gradle module directory, the nearest
# directory above the source holding a `build.gradle.kts`. A definition that lands on
# the repository root binds a name that is used only joined with string literals, or
# with constants bound to literals in the same file, and each such join is a read; the
# root may also be the base a path is made relative to, which reads nothing. A
# definition that lands outside the source's package (`bindings/<name>`,
# `tests/<name>`) reads the path it lands on and everything under it. A definition that
# lands inside the package binds a name used any way, because whatever it names sits
# under the package, unless a literal joined to it climbs out, which is reported. Every
# other way to name a path above the source is reported: another `__file__`,
# `import.meta`, `#filePath` or `user.dir`, a parent step outside a definition, the
# working directory, `GITHUB_WORKSPACE`, `git rev-parse`, and a string literal whose `..`
# segments reach a tracked path outside the package from the source's directory or from
# the package directory a test runner starts in.
#
# Indicators, not the criterion: the scan reads code with comments and Python
# docstrings removed and treats each string literal as one path. It does not follow a
# path a test assembles from data at run time, such as a `..` held in a variable and
# joined onto a name bound inside the package; the literal rule above catches the
# common spelling of that, and a reviewer catches the rest.
class ReadForm(NamedTuple):
    """How one language names a path outside a test source's own directory."""

    comment: str
    definition: re.Pattern
    # (match, source, tracked paths) -> the path the definition names, repository
    # relative, "" for the root, None for a path above the root.
    landing: Callable[[re.Match, str, set[str]], str | None]
    join: str
    const: str
    relative: tuple[str, ...]
    # Patterns matched against code with every string literal emptied.
    escapes: tuple[str, ...]
    ignore: tuple[str, ...] = ()
    # Patterns matched against code with string literals intact, for a path a
    # string names: an environment variable, a git command, a system property.
    literal_escapes: tuple[str, ...] = (r"GITHUB_WORKSPACE", r"rev-parse")


READ_STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'')
READ_PARENT_SEGMENT = re.compile(r"(^|/)\.\.(/|$)")
# The method names a chained Swift or Kotlin join spells between its literals.
READ_JOIN_CALLS = frozenset({"appendingPathComponent", "resolve"})


def _read_climb(path: str | None, levels: int) -> str | None:
    for _ in range(levels):
        if not path:
            return None
        path = posixpath.dirname(path)
    return path


def _read_join(base: str | None, segments: list[str]) -> str | None:
    if base is None:
        return None
    target = posixpath.normpath(posixpath.join(base or ".", *segments))
    if target == ".." or target.startswith("../"):
        return None
    return "" if target == "." else target


def _read_package(source: str) -> str:
    parts = source.split("/")
    return "/".join(parts[:2]) if parts[0] in ("bindings", "tests") and len(parts) > 2 else parts[0]


def _read_inside(path: str, package: str) -> bool:
    return path == package or path.startswith(f"{package}/")


def _read_literals(arguments: str, consts: dict[str, str]) -> list[str] | None:
    """The segments of a join's arguments, or None when one is neither a literal nor a bound const."""
    segments = []
    for part in re.findall(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|[A-Za-z_][\w.]*', arguments):
        literal = READ_STRING.fullmatch(part)
        if literal:
            segments.append(literal.group(1) if literal.group(1) is not None else literal.group(2))
        elif part in consts:
            segments.append(consts[part])
        elif part not in READ_JOIN_CALLS:
            return None
    return segments


def _python_landing(match: re.Match, source: str, _paths: set[str]) -> str | None:
    levels = int(match.group(2)) + 1 if match.group(2) else (1 if match.group(3) else 0)
    return _read_join(_read_climb(source, levels), re.findall(r'"([^"\n]*)"', match.group(4) or ""))


def _ts_landing(match: re.Match, source: str, _paths: set[str]) -> str | None:
    return _read_join(posixpath.dirname(source), [match.group(2)] if match.group(2) is not None else [])


def _swift_landing(match: re.Match, source: str, _paths: set[str]) -> str | None:
    return _read_climb(source, match.group(2).count("deletingLastPathComponent"))


def _kotlin_landing(match: re.Match, source: str, paths: set[str]) -> str | None:
    module = posixpath.dirname(source)
    while module and f"{module}/build.gradle.kts" not in paths:
        module = posixpath.dirname(module)
    return _read_climb(module, match.group(2).count("parentFile")) if module else None


READ_C_COMMENTS = r"/\*.*?\*/|(?m:^[ \t]*//[^\n]*$)|(?m:[ \t]+//[^\"'\n]*$)"
READ_FORMS: dict[str, ReadForm] = {
    "py": ReadForm(
        comment=r"\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|(?m:^[ \t]*#[^\n]*$)|(?m:[ \t]+#[^\"'\n]*$)",
        definition=re.compile(
            r"^[ \t]*(\w+)(?:[ \t]*:[ \t]*[\w.]+)?[ \t]*=[ \t]*(?:pathlib\.)?Path\(__file__\)\.resolve\(\)"
            r'(?:\.parents\[(\d+)\]|(\.parent))?((?:[ \t]*/[ \t]*"[^"\n]*")*)[ \t]*$',
            re.M,
        ),
        landing=_python_landing,
        join=r"\b{name}((?:\s*/\s*(?:\"[^\"\n]*\"|'[^'\n]*'|[A-Z][A-Z0-9_]*\b))+)",
        const=r"^([A-Z][A-Z0-9_]*)[ \t]*(?::[ \t]*str[ \t]*)?=[ \t]*\"([^\"\n]*)\"[ \t]*$",
        relative=(r"\.relative_to\(\s*{name}\s*\)",),
        escapes=(
            r"__file__",
            r"\.parents?\b",
            r"\bos\.path\.dirname\b",
            r"\bos\.getcwd\b",
            r"\bPath\.cwd\b",
        ),
    ),
    "ts": ReadForm(
        comment=READ_C_COMMENTS,
        definition=re.compile(
            r"^[ \t]*(?:export\s+)?const\s+(\w+)(?:\s*:\s*string)?\s*=\s*(?:"
            r"fileURLToPath\(\s*new URL\(\s*\"([^\"\n]*)\"\s*,\s*import\.meta\.url\s*\)\s*\)"
            r"|import\.meta\.dir|dirname\(\s*fileURLToPath\(\s*import\.meta\.url\s*\)\s*\))\s*;?[ \t]*$",
            re.M,
        ),
        landing=_ts_landing,
        join=r"\b(?:join|resolve)\(\s*{name}\s*,((?:\s*(?:\"[^\"\n]*\"|'[^'\n]*'|[A-Za-z_][\w.]*)\s*,?)+)\)",
        const=r"^[ \t]*(?:export\s+)?const\s+([A-Z][A-Z0-9_]*)\s*=\s*\"([^\"\n]*)\"\s*;?[ \t]*$",
        relative=(r"\brelative\(\s*{name}\s*,",),
        escapes=(
            r"import\.meta\.(?:url|dir|path|dirname|filename)",
            r"__dirname",
            r"__filename",
            r"process\.cwd",
            r"\bdirname\(",
        ),
    ),
    "swift": ReadForm(
        comment=READ_C_COMMENTS,
        definition=re.compile(
            r"^[ \t]*(?:(?:private|fileprivate|internal|static)\s+)*(?:let|var)\s+(\w+)(?:\s*:\s*URL)?\s*=\s*"
            r"URL\(\s*fileURLWithPath:\s*#filePath\s*\)((?:\s*\.deletingLastPathComponent\(\))*)",
            re.M,
        ),
        landing=_swift_landing,
        join=r"\b{name}((?:\s*\.appendingPathComponent\(\s*(?:\"[^\"\n]*\"|[A-Za-z_]\w*)\s*\))+)",
        const=r"^[ \t]*(?:(?:private|fileprivate|static)\s+)*let\s+([A-Za-z_]\w*)\s*=\s*\"([^\"\n]*)\"[ \t]*$",
        relative=(),
        escapes=(r"#filePath", r"#file\b", r"deletingLastPathComponent", r"currentDirectoryPath"),
        # XCTest's `file: StaticString = #filePath` names this source in a failure
        # report and reads nothing.
        ignore=(r"file:\s*StaticString\s*=\s*#filePath",),
    ),
    "kt": ReadForm(
        comment=READ_C_COMMENTS,
        definition=re.compile(
            r"^[ \t]*(?:(?:private|internal)\s+)*val\s+(\w+)(?:\s*:\s*File)?\s*=\s*"
            r"File\(\s*System\.getProperty\(\s*\"user\.dir\"\s*\)\s*\)((?:\s*\.parentFile)*)[ \t]*$",
            re.M,
        ),
        landing=_kotlin_landing,
        join=r"\b{name}((?:\s*\.resolve\(\s*(?:\"[^\"\n$]*\"|[A-Z][A-Z0-9_]*)\s*\))+)",
        const=(
            r"^[ \t]*(?:(?:private|internal)\s+)*(?:const\s+)?val\s+([A-Z][A-Z0-9_]*)\s*(?::\s*String\s*)?="
            r"\s*\"([^\"\n$]*)\"[ \t]*$"
        ),
        relative=(r"\.relativeTo\(\s*{name}\s*\)",),
        escapes=(r"\bparentFile\b", r"\.parent\b", r"Paths\.get"),
        literal_escapes=(r"GITHUB_WORKSPACE", r"rev-parse", r"\"user\.dir\""),
    ),
}
READ_LANGUAGES = {".py": "py", ".ts": "ts", ".mjs": "ts", ".js": "ts", ".swift": "swift", ".kt": "kt"}
READ_TEST_DIR = re.compile(r"(^|/)(tests?|Tests|androidTest)/")


def binding_test_sources(paths: list[str]) -> list[str]:
    """Every tracked test source under `bindings/` or `tests/` in a language READ_FORMS reads."""
    return [
        path
        for path in paths
        if path.startswith(("bindings/", "tests/"))
        and READ_TEST_DIR.search(path)
        and posixpath.splitext(path)[1] in READ_LANGUAGES
        and "/node_modules/" not in path
        and posixpath.basename(path) != "Package.swift"
    ]


def binding_test_scan(source: str, text: str, paths: set[str], dirs: set[str]) -> tuple[set[str], list[str]]:
    """The tracked paths outside its package that `source` reads, and each form it uses that the scan cannot read."""
    form = READ_FORMS[READ_LANGUAGES[posixpath.splitext(source)[1]]]
    package = _read_package(source)
    reads: set[str] = set()
    found: list[str] = []
    code = re.sub(form.comment, lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    for pattern in form.ignore:
        code = re.sub(pattern, "", code)
    consts = {m.group(1): m.group(2) for m in re.finditer(form.const, code, re.M)}
    body = form.definition.sub("", code)
    for definition in form.definition.finditer(code):
        name = re.escape(definition.group(1))
        join = form.join.format(name=name)
        landing = form.landing(definition, source, paths)
        if landing is None:
            found.append(f"{source}: {definition.group(1)} climbs above the repository")
            continue
        if landing and not _read_inside(landing, package):
            # A name bound outside the package reads that path and everything under it.
            reads.add(landing)
            body = re.sub(join, "", body)
            continue
        for use in re.finditer(join, body):
            segments = _read_literals(use.group(1), consts)
            if segments is None:
                if landing == "":
                    found.append(f"{source}: root {definition.group(1)} joined with a non-literal")
                continue
            target = _read_join(landing, segments)
            if target is None:
                found.append(f"{source}: {definition.group(1)} joined with {segments} climbs above the repository")
            elif landing == "" and not target:
                found.append(f"{source}: root {definition.group(1)} joined with {segments} names the root itself")
            elif landing == "" and not _read_inside(target, package):
                reads.add(target)
            elif landing != "" and not _read_inside(target, package):
                found.append(f"{source}: {definition.group(1)} joined with {segments} reaches {target} outside {package}")
        body = re.sub(join, "", body)
        if landing == "":
            rest = body
            for pattern in form.relative:
                rest = re.sub(pattern.format(name=name), "", rest)
            if re.search(rf"\b{name}\b", rest):
                found.append(f"{source}: root {definition.group(1)} used other than joined with a literal")
    blank = READ_STRING.sub('""', body)
    for pattern in form.escapes:
        if re.search(pattern, blank):
            found.append(f"{source}: names a path through {pattern}")
    for pattern in form.literal_escapes:
        if re.search(pattern, body):
            found.append(f"{source}: names a path through {pattern}")
    for match in READ_STRING.finditer(body):
        literal = match.group(1) if match.group(1) is not None else match.group(2)
        if not READ_PARENT_SEGMENT.search(literal):
            continue
        for base in (posixpath.dirname(source), package):
            target = _read_join(base, [literal])
            if target is None or _read_inside(target, package):
                continue
            if target in paths or target in dirs or target == "":
                found.append(f"{source}: literal {literal!r} reaches {target or '.'} from {base}")
                break
    return reads, found


# The ci.yml jobs that run the test sources under each directory, each with a string
# its steps must hold for the claim to stand. A source maps to the longest prefix it
# sits under. A source several jobs run is routed when the outputs of those jobs
# together select each path it reads: the bridge-parity conftest reads
# `bindings/typescript` only for the napi runner, which job bridge-parity runs.
BINDING_TEST_JOBS: dict[str, tuple[tuple[str, str], ...]] = {
    "bindings/python/tests/": (("python-test", 'pytest tests/ -v -m "not parity"'),),
    "bindings/python/tests/bridge_parity/": (
        ("python-test", 'pytest tests/ -v -m "not parity"'),
        ("bridge-parity", "pytest tests/bridge_parity/"),
        ("bridge-parity-kotlin", "pytest tests/bridge_parity/"),
        ("bridge-parity-swift", "pytest tests/bridge_parity/"),
    ),
    "bindings/typescript/tests/": (("typescript-check", "bun test"),),
    "bindings/typescript-wasm/tests/": (("typescript-wasm-check", "bun test"),),
    "bindings/swift/Tests/": (("swift-build-test", "swift test"),),
    "bindings/kotlin/scp-kt/src/test/": (("kotlin-test", ":scp-kt:test"),),
    "bindings/kotlin/scp-kt-android/src/test/": (("kotlin-test", ":scp-kt-android:testDebugUnitTest"),),
    "bindings/kotlin/scp-kt-android/src/androidTest/": (
        ("kotlin-android-instrumented", ":scp-kt-android:connectedDebugAndroidTest"),
    ),
    # No ci.yml step runs `tests/integration/phase3_integration_test.py`; the comment
    # above job python-test's pytest step says why. Its forms are still checked.
    "tests/integration/": (),
}


def binding_test_jobs(source: str) -> tuple[tuple[str, str], ...] | None:
    """The (job, evidence) pairs BINDING_TEST_JOBS names for a source, or None when no prefix holds it."""
    prefix = max((p for p in BINDING_TEST_JOBS if source.startswith(p)), key=len, default=None)
    return None if prefix is None else BINDING_TEST_JOBS[prefix]


def job_selecting_outputs(doc: dict, job_id: str) -> list[str] | None:
    """Each `changes` output that alone makes a job run on a merge_group event, or None for a job no output gates."""
    condition = str(doc["jobs"][job_id].get("if") or "")
    if not FILTER_REFERENCE.search(condition):
        return None
    outputs = sorted((doc["jobs"]["changes"].get("outputs") or {}))
    return [
        output
        for output in outputs
        if selects(condition, {key: "true" if key == output else "false" for key in outputs}, "merge_group")
    ]


def job_patterns(doc: dict, jobs: list[str], by_output: dict[str, set[str]] | None = None) -> set[str] | None:
    """Every filter pattern that makes one of `jobs` run on a merge_group event, or None when one runs on every change.

    output_patterns parses the filter YAML on each call; a caller reading many jobs
    passes `by_output`, which this fills with each output's patterns once.
    """
    by_output = {} if by_output is None else by_output
    patterns: set[str] = set()
    for job_id in jobs:
        selecting = job_selecting_outputs(doc, job_id)
        if selecting is None:
            return None
        for output in selecting:
            if output not in by_output:
                found = output_patterns(doc, output)
                if isinstance(found, str):
                    raise AssertionError(found)
                by_output[output] = found
            patterns |= by_output[output]
    return patterns


def read_members(read: str, paths: list[str]) -> list[str]:
    """The tracked files one read names: the file itself, every file under a directory, or every file a glob selects."""
    if "*" in read:
        return [path for path in paths if glob_selects(read, path)]
    return [path for path in paths if path == read or path.startswith(f"{read}/")]


def reads_unselected(doc: dict, paths: list[str], reads: dict[str, set[str]], jobs: dict[str, list[str]]) -> list[str]:
    """Each `reader: path` whose path no output that runs the reader selects."""
    gaps = []
    by_output: dict[str, set[str]] = {}
    known: dict[tuple[str, ...], set[str] | None] = {}
    for reader, entries in sorted(reads.items()):
        key = tuple(sorted(jobs[reader]))
        if key not in known:
            known[key] = job_patterns(doc, list(key), by_output)
        patterns = known[key]
        if patterns is None:
            continue
        for read in sorted(entries):
            gaps += [f"{reader}: {path}" for path in read_members(read, paths) if not pattern_covers(patterns, path)]
    return gaps


def binding_test_reads(paths: list[str], texts: dict[str, str]) -> tuple[dict[str, set[str]], list[str]]:
    """Each test source's reads and every form violation, over `texts` (source -> text)."""
    tracked = set(paths)
    dirs = _tracked_dirs(paths)
    reads: dict[str, set[str]] = {}
    violations: list[str] = []
    for source, text in sorted(texts.items()):
        found_reads, found = binding_test_scan(source, text, tracked, dirs)
        reads[source] = found_reads
        violations += found
    return reads, violations


def check_binding_test_reads(doc: dict, paths: list[str]) -> None:
    sources = binding_test_sources(paths)
    check("the binding test scan finds Python, TypeScript, Swift and Kotlin sources", all(
        any(source.endswith(suffix) for source in sources) for suffix in (".py", ".ts", ".swift", ".kt")
    ))
    texts = {source: (REPO / source).read_text(encoding="utf-8") for source in sources}
    reads, violations = binding_test_reads(paths, texts)
    check(
        "every binding test source names a path outside its directory only in its language's read form",
        not violations,
        f"{violations[:10]}",
    )
    for source, expected in (
        ("bindings/typescript/tests/server.test.ts", ".docs/standards/sdk-common.md"),
        ("bindings/python/tests/test_server.py", ".docs/standards/sdk-common.md"),
        ("bindings/swift/Tests/SCPTests/NodeStartTests.swift", ".docs/standards/sdk-common.md"),
        (
            "bindings/kotlin/scp-kt/src/test/kotlin/works/limn/scp/OutletsStreamingTest.kt",
            "tests/conformance/vectors/outlet_stream_vectors.json",
        ),
    ):
        check(f"the binding test scan finds {source} reading {expected}", expected in reads.get(source, set()))
    unmapped = [source for source in sources if binding_test_jobs(source) is None]
    check("BINDING_TEST_JOBS names the jobs that run every binding test source", not unmapped, f"{unmapped[:10]}")
    check(
        "a test source under no BINDING_TEST_JOBS prefix is reported",
        binding_test_jobs("bindings/newlang/tests/a.py") is None,
    )
    for prefix, pairs in BINDING_TEST_JOBS.items():
        for job_id, evidence in pairs:
            job = doc["jobs"].get(job_id)
            runs = "\n".join(
                "\n".join(logical_lines(str(step.get("run") or "")))
                + "\n"
                + str((step.get("with") or {}).get("script") or "")
                for step in (job or {}).get("steps") or []
            )
            check(f"job {job_id} runs the tests under {prefix} ({evidence!r})", evidence in runs)
    unrun = [
        job_id
        for job_id, job in doc["jobs"].items()
        for step in job.get("steps") or []
        if "tests/integration" in "\n".join(logical_lines(str(step.get("run") or "")))
    ]
    check("no ci.yml job runs the repository-root tests/integration/", not unrun, f"{unrun}")
    jobs = {source: [job_id for job_id, _ in binding_test_jobs(source) or ()] for source in sources}
    routed = {source: entries for source, entries in reads.items() if jobs.get(source)}
    gaps = reads_unselected(doc, paths, routed, jobs)
    check("ci.yml: the jobs that run each binding test source select every path it reads", not gaps, f"{gaps[:20]}")
    check(
        "a planted binding test read that no filter selects is reported",
        reads_unselected(
            doc,
            [*paths, "new/x.bin"],
            {"bindings/swift/Tests/SCPTests/A.swift": {"new/x.bin"}},
            {"bindings/swift/Tests/SCPTests/A.swift": ["swift-build-test"]},
        )
        == ["bindings/swift/Tests/SCPTests/A.swift: new/x.bin"],
    )
    mutant = copy.deepcopy(doc)
    step = next(
        step
        for step in mutant["jobs"]["changes"]["steps"]
        if str(step.get("uses") or "").startswith("dorny/paths-filter")
    )
    filters = yaml.safe_load(step["with"]["filters"])
    check("filter rust lists 'tests/conformance/**' for the mutant", "tests/conformance/**" in filters["rust"])
    filters["rust"] = [entry for entry in filters["rust"] if entry != "tests/conformance/**"]
    step["with"]["filters"] = yaml.safe_dump(filters)
    narrowed = copy.deepcopy(doc)
    narrowed["jobs"]["python-test"]["if"] = narrow_condition(
        narrowed["jobs"]["python-test"]["if"], "outputs.swift ="
    )
    check(
        "a python-test `if:` without its swift clause reports the SDK surface scan's Swift reads",
        any(
            gap.startswith("bindings/python/tests/test_outlets_streaming.py: bindings/swift/")
            for gap in reads_unselected(narrowed, paths, routed, jobs)
        ),
    )
    check(
        "a `rust` filter that drops tests/conformance/** reports the Kotlin outlet vector read",
        "bindings/kotlin/scp-kt/src/test/kotlin/works/limn/scp/OutletsStreamingTest.kt: "
        "tests/conformance/vectors/outlet_stream_vectors.json"
        in reads_unselected(mutant, paths, routed, jobs),
    )
    # Must fail: each planted source reaches outside its package in a form the scan
    # does not read. Must pass: the admitted forms, with the reads they make.
    tracked = set(paths)
    dirs = _tracked_dirs(paths)
    py = "bindings/python/tests/test_planted.py"
    ts = "bindings/typescript/tests/planted.test.ts"
    swift = "bindings/swift/Tests/SCPTests/PlantedTests.swift"
    kt = "bindings/kotlin/scp-kt/src/test/kotlin/works/limn/scp/PlantedTest.kt"
    py_root = "ROOT = Path(__file__).resolve().parents[3]\n"
    ts_root = 'const ROOT = fileURLToPath(new URL("../../../", import.meta.url));\n'
    swift_root = "let root = URL(fileURLWithPath: #filePath)" + ".deletingLastPathComponent()" * 5 + "\n"
    kt_root = 'val root = File(System.getProperty("user.dir")).parentFile.parentFile.parentFile\n'
    for source, label, text in (
        (py, "a climbing literal", 'open("../../../AGENTS.md")'),
        (py, "another __file__", "x = Path(__file__).parent.parent"),
        (py, "a bare root use", py_root + "subprocess.run(cmd, cwd=ROOT)"),
        (py, "a root joined with a variable", py_root + "ROOT / name"),
        (py, "a parent step outside a definition", "p = here.parent"),
        (py, "the working directory", "Path.cwd() / 'AGENTS.md'"),
        (py, "GITHUB_WORKSPACE", 'Path(os.environ["GITHUB_WORKSPACE"]) / "AGENTS.md"'),
        (py, "the repository top level", 'subprocess.run(["g" "it", "rev-parse", "--show-toplevel"])'),
        (ts, "GITHUB_WORKSPACE", 'join(process.env["GITHUB_WORKSPACE"], "AGENTS.md")'),
        (py, "a definition above the repository", "ROOT = Path(__file__).resolve().parents[9]\nROOT / 'x'"),
        (ts, "a climbing literal", 'readFileSync("../../../AGENTS.md")'),
        (ts, "another import.meta", 'join(import.meta.dir, "..", "..")'),
        (ts, "a bare root use", ts_root + "spawnSync(cmd, { cwd: ROOT });"),
        (ts, "a root joined with a variable", ts_root + "join(ROOT, name)"),
        (ts, "__dirname", 'resolve(__dirname, "x")'),
        (ts, "the working directory", 'join(process.cwd(), "AGENTS.md")'),
        (swift, "a climbing literal", 'let x = "../../../../AGENTS.md"'),
        (swift, "another #filePath", "load(URL(fileURLWithPath: #filePath))"),
        (swift, "a bare root use", swift_root + "let y = root.path"),
        (swift, "a root joined with a variable", swift_root + "root.appendingPathComponent(name)"),
        (swift, "a parent step outside a definition", "let x = here.deletingLastPathComponent()"),
        (swift, "the working directory", "FileManager.default.currentDirectoryPath"),
        (kt, "a climbing literal", 'File("../../tests/conformance")'),
        (kt, "another user.dir", 'File(System.getProperty("user.dir"), "x")'),
        (kt, "a bare root use", kt_root + "ProcessBuilder(cmd).directory(root)"),
        (kt, "a root joined with a variable", kt_root + "root.resolve(name)"),
        (kt, "a parent step outside a definition", "val x = here.parentFile"),
        (kt, "Paths.get", 'Paths.get("x")'),
        (kt, "GITHUB_WORKSPACE", 'File(System.getenv("GITHUB_WORKSPACE"), "AGENTS.md")'),
    ):
        _, reported = binding_test_scan(source, text, tracked, dirs)
        check(f"binding_test_scan reports {label} in {source.rsplit('.', 1)[1]}", bool(reported), f"{reported}")
    for source, text, expected in (
        (
            py,
            py_root
            + 'DOC = "AGENTS.md"\nPKG = Path(__file__).resolve().parents[1]\n'
            + '"""ROOT / "x" in a docstring"""\n'
            + 'a = ROOT / ".docs" / "standards/sdk-common.md"\nb = ROOT / DOC\nc = p.relative_to(ROOT)\n'
            + 'd = PKG / "scp_sdk"\n'
            + 'f = subprocess.run(cmd, cwd=PKG)\n# Path(__file__).parent\n',
            {".docs/standards/sdk-common.md", "AGENTS.md"},
        ),
        (
            ts,
            ts_root
            + 'const PKG = fileURLToPath(new URL("../", import.meta.url));\n'
            + 'join(ROOT, ".docs/standards", "sdk-common.md");\nrelative(ROOT, p);\n'
            + 'spawnSync(cmd, { cwd: PKG });\n// import.meta.dir\nimport x from "../src/index";\n',
            {".docs/standards/sdk-common.md"},
        ),
        (
            swift,
            swift_root
            + 'root.appendingPathComponent(".docs/standards/sdk-common.md")\n'
            + "func f(file: StaticString = #filePath) {}\n// #filePath\n",
            {".docs/standards/sdk-common.md"},
        ),
        (
            kt,
            kt_root + 'root.resolve("tests/conformance")\nval module = File(System.getProperty("user.dir"))\n'
            + "ProcessBuilder(cmd).directory(module)\n",
            {"tests/conformance"},
        ),
    ):
        found_reads, reported = binding_test_scan(source, text, tracked, dirs)
        check(
            f"binding_test_scan admits the {source.rsplit('.', 1)[1]} read form and reads {sorted(expected)}",
            not reported and found_reads == expected,
            f"reads {found_reads}, reported {reported}",
        )


# CRITERION for check_script_reads: every script a filter-gated job runs, named in a
# `run:` of the job or in the code of a script the job runs, is selected by the outputs
# that run the job, and so is every tracked path that script names. A script names a
# path by a token of path shape in its code, resolved from the repository root, where
# every such job starts; a token with a `*` names every tracked file it selects as a
# dorny/paths-filter glob. A script that a job runs only on outputs other than `code`
# walks no tree without a pathspec, because a walk reads every path under the
# directory it starts in. A script a `code`-gated job runs can read any path but prose,
# which `code` never selects, so for those scripts the token rule reports a prose read.
#
# Indicators, not the criterion: the scan reads code with comments and Python
# docstrings removed, and does not follow a path a script assembles in a variable from
# parts; for the Python scripts a narrowly gated job runs, binding_test_scan's Python
# form reads the root joins as it does for tests.
SCRIPT_NAME = re.compile(r"(?<![\w./$}-])(?:\./)?((?:scripts|bindings)/[\w./-]+\.(?:sh|py))")
SCRIPT_PATH_TOKEN = re.compile(
    r"(?<![\w$./{}-])((?:\.?[\w-]+/)+[\w.*-]*|[\w-]+\.(?:toml|lock|json|md|yml|yaml|txt))(?![\w/-])"
)
SCRIPT_TREE_WALK = re.compile(
    r"\bgit(?:\s+-C\s+\S+)?\s+(?:ls-files|grep)\b(?![^\n]*\s--(?:\s|$))"
    r"|\bfind\s+(?:-L\s+)?(?:\.|\"?\$\{?(?:REPO_ROOT|ROOT|repo_root)\}?\"?)(?:\s|$)"
    r"|\bos\.walk\(\s*(?:REPO_ROOT|ROOT)\b|\b(?:REPO_ROOT|ROOT)\.rglob\("
)
# A script the token scan does not read, mapped to the reason its reads are routed.
SCRIPT_READS_ROUTED_ELSEWHERE = {
    "scripts/tests/ci-gate/ci_gate_selftest.py": (
        "names paths as data for its checks; its `docs` group, which job ci-workflow-selftest-docs runs on "
        "every event, holds each check that reads prose"
    ),
}
# A (script, token) pair that names a path the script creates in a scratch repository.
SCRIPT_FIXTURE_TOKENS = {
    ("scripts/tests/toolchain-wiring/run-tests.sh", "README.md"): "the extra root file of a scratch repository",
}


def _script_code(script: str, text: str) -> str:
    if script.endswith(".py"):
        text = re.sub(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'', lambda m: "\n" * m.group(0).count("\n"), text)
    text = re.sub(r"(?m)^[ \t]*#[^\n]*$", "", text)
    return re.sub(r"(?m)[ \t]+#[^\"'\n]*$", "", text)


def gated_scripts(doc: dict, paths: set[str], texts: Callable[[str], str]) -> dict[str, set[str]]:
    """Each tracked script a filter-gated job runs, mapped to the jobs that run it."""
    runs: dict[str, set[str]] = {}
    for job_id, job in doc["jobs"].items():
        if not job_selecting_outputs(doc, job_id):
            continue
        for step in job.get("steps") or []:
            for script in SCRIPT_NAME.findall("\n".join(logical_lines(str(step.get("run") or "")))):
                if script in paths:
                    runs.setdefault(script, set()).add(job_id)
    pending = list(runs)
    while pending:
        script = pending.pop()
        if script in SCRIPT_READS_ROUTED_ELSEWHERE:
            continue
        for named in SCRIPT_NAME.findall(_script_code(script, texts(script))):
            if named in paths and not runs[script] <= runs.get(named, set()):
                runs.setdefault(named, set()).update(runs[script])
                pending.append(named)
    return runs


def script_reads(script: str, text: str, paths: set[str], dirs: set[str]) -> tuple[set[str], list[str]]:
    """The tracked paths and globs a script names, and each tree walk it makes without a pathspec."""
    code = _script_code(script, text)
    reads = set()
    for token in SCRIPT_PATH_TOKEN.findall(code):
        token = token.rstrip("/")
        if (script, token) in SCRIPT_FIXTURE_TOKENS:
            continue
        if "*" in token:
            if any(glob_selects(token, path) for path in paths):
                reads.add(token)
        elif token in paths or token in dirs:
            reads.add(token)
    walks = [f"{script}: walks a tree without a pathspec: {m.group(0).strip()!r}" for m in SCRIPT_TREE_WALK.finditer(code)]
    return reads, walks


def check_script_reads(doc: dict, paths: list[str]) -> None:
    tracked = set(paths)
    dirs = _tracked_dirs(paths)

    def text_of(script: str) -> str:
        return (REPO / script).read_text(encoding="utf-8")

    runs = gated_scripts(doc, tracked, text_of)
    for script, job_id in (
        ("scripts/check-examples-compile.sh", "rust-clippy"),
        ("scripts/check-test-shard-features.py", "rust-test"),
        ("scripts/check-python-falsy-optionals.py", "python-lint"),
        ("scripts/generate-uniffi-kotlin.sh", "uniffi-cdylib-linux"),
        ("scripts/check-wiping-allocator.sh", "wiping-allocator"),
    ):
        check(f"the script scan finds job {job_id} running {script}", job_id in runs.get(script, set()))
    unselected = []
    by_output: dict[str, set[str]] = {}
    by_job = {job_id: job_patterns(doc, [job_id], by_output) for job_ids in runs.values() for job_id in job_ids}
    for script, job_ids in sorted(runs.items()):
        for job_id in sorted(job_ids):
            patterns = by_job[job_id]
            if patterns is not None and not pattern_covers(patterns, script):
                unselected.append(f"{job_id}: {script}")
    check("ci.yml: every job a filter gates is selected by a change to each script it runs", not unselected, f"{unselected}")
    reads: dict[str, set[str]] = {}
    jobs: dict[str, list[str]] = {}
    violations: list[str] = []
    for script, job_ids in sorted(runs.items()):
        if script in SCRIPT_READS_ROUTED_ELSEWHERE:
            continue
        found_reads, walks = script_reads(script, text_of(script), tracked, dirs)
        narrow = any("code" not in (job_selecting_outputs(doc, job_id) or ["code"]) for job_id in job_ids)
        if narrow:
            violations += walks
            if script.endswith(".py"):
                form_reads, found = binding_test_scan(script, text_of(script), tracked, dirs)
                found_reads |= form_reads
                violations += found
        for job_id in sorted(job_ids):
            reads[f"{job_id} {script}"] = found_reads
            jobs[f"{job_id} {script}"] = [job_id]
    check(
        "every script a narrowly gated job runs walks no tree without a pathspec",
        not violations,
        f"{violations[:10]}",
    )
    gaps = reads_unselected(doc, paths, reads, jobs)
    check("ci.yml: the outputs that run each gated script select every path it names", not gaps, f"{gaps[:20]}")
    check(
        "the script scan reads the SDK root check-python-falsy-optionals.py joins",
        "bindings/python/scp_sdk" in reads.get("python-lint scripts/check-python-falsy-optionals.py", set()),
    )
    # Must fail: a prose read in a script a `code`-gated job runs, a script a job runs
    # that its filter does not select, and tree walks in a narrowly gated script.
    planted_reads, _ = script_reads("scripts/x.sh", 'cat .docs/standards/rust.md\ncat AGENTS.md', tracked, dirs)
    check(
        "a prose path named in a script a `code`-gated job runs is reported",
        reads_unselected(doc, paths, {"s": planted_reads}, {"s": ["wiping-allocator"]})
        == ["s: .docs/standards/rust.md", "s: AGENTS.md"],
        f"{planted_reads}",
    )
    for label, text in (
        ("git ls-files with no pathspec", "files=$(git ls-files)"),
        ("git grep with no pathspec", "git grep -n foo"),
        ("find from the root", 'find "$REPO_ROOT" -name x'),
        ("an rglob of the root", "for p in ROOT.rglob('*'):"),
    ):
        _, walks = script_reads("scripts/x.sh" if "ROOT." not in text else "scripts/x.py", text, tracked, dirs)
        check(f"script_reads reports {label}", bool(walks), f"{walks}")
    _, walks = script_reads("scripts/x.sh", "git ls-files -- '*.rs'\nfind \"$pkgdir/examples\" -type f", tracked, dirs)
    check("script_reads admits a walk with a pathspec or below the root", not walks, f"{walks}")
    mutant = copy.deepcopy(doc)
    step = next(
        step
        for step in mutant["jobs"]["changes"]["steps"]
        if str(step.get("uses") or "").startswith("dorny/paths-filter")
    )
    filters = yaml.safe_load(step["with"]["filters"])
    check(
        "filter rust lists 'scripts/check-examples-compile.sh' for the mutant",
        "scripts/check-examples-compile.sh" in filters["rust"],
    )
    filters["rust"] = [entry for entry in filters["rust"] if entry != "scripts/check-examples-compile.sh"]
    step["with"]["filters"] = yaml.safe_dump(filters)
    check(
        "a `rust` filter that drops scripts/check-examples-compile.sh reports job rust-clippy",
        not pattern_covers(job_patterns(mutant, ["rust-clippy"]) or set(), "scripts/check-examples-compile.sh"),
    )


COMPILE_STEPS_SCRIPT = REPO / "scripts/check-workflow-compile-steps.py"


@functools.cache
def compile_steps_module():
    """scripts/check-workflow-compile-steps.py, which owns gated_to_main."""
    return load_module("check_workflow_compile_steps", COMPILE_STEPS_SCRIPT)


def gated_to_main(value: object, bare: bool = False) -> bool:
    """check-workflow-compile-steps.py's gated_to_main, the one owner of the rule."""
    return compile_steps_module().gated_to_main(value, bare)


# setup-gradle's documented form for saving on `main` alone: read-only everywhere else.
GRADLE_READ_ONLY_OFF_MAIN = re.compile(r"github\.ref\s*!=\s*'refs/heads/main'", re.IGNORECASE)


def gradle_read_only_off_main(value: object) -> bool:
    """Whether a `cache-read-only` value is exactly `${{ github.ref != 'refs/heads/main' }}`."""
    module = compile_steps_module()
    body = module.expression_body(value)
    return body is not None and bool(
        GRADLE_READ_ONLY_OFF_MAIN.fullmatch(module.strip_parentheses(body))
    )


def cache_action_key(uses: str) -> str:
    """The CACHE_SAVES key a remote `uses:` names: action_name, or a `docker://` image
    without its tag or digest."""
    if uses.lower().startswith("docker://"):
        image = uses[len("docker://"):].split("@", 1)[0].lower()
        head, _, last = image.rpartition("/")
        return "docker://" + (f"{head}/" if head else "") + last.split(":", 1)[0]
    return action_name(uses)


def unclassified_actions(permitted: dict[str, str], table: dict[str, CacheSaving]) -> list[str]:
    """Each permitted action CACHE_SAVES does not classify, and each classification
    that names an action PERMITTED_ACTIONS does not permit (a `docker://` image
    excepted, which remote_action_gaps reads by digest)."""
    missing = [f"{name} has no CACHE_SAVES entry" for name in sorted(set(permitted) - set(table))]
    stray = [
        f"CACHE_SAVES classifies {name}, which PERMITTED_ACTIONS does not list"
        for name in sorted(set(table) - set(permitted))
        if not name.startswith("docker://")
    ]
    return missing + stray


def local_actions() -> dict[str, dict]:
    """Every local composite action, by the `uses:` that calls it."""
    return {
        f"./{path.parent.relative_to(REPO).as_posix()}": yaml.safe_load(path.read_text()) or {}
        for path in sorted((REPO / ".github/actions").glob("*/action.y*ml"))
    }


CALLER_INPUT = re.compile(r"\binputs\.([\w-]+)", re.IGNORECASE)


def step_inputs(step: dict) -> dict[str, object]:
    """A step's `with:`, keyed by lower-cased input name.

    GitHub exports each input as `INPUT_<NAME>` upper-cased, and the actions read them
    through `getInput`, which upper-cases the name it asks for, so `Cache-To` and
    `cache-to` are one input. Every reader of a step's inputs reads them through here.
    """
    return {str(key).lower(): value for key, value in (step.get("with") or {}).items()}


def fill_inputs(value: object, inputs: dict[str, object], condition: bool = False) -> object:
    """A composite step's field with each `inputs.<name>` replaced by what the caller passed.

    A `with:` field that is `${{ inputs.<name> }}` alone takes the caller's value
    whole, so a literal `false` stays the literal false. An `if:` field (`condition`)
    does so only when the caller passed an expression: a caller's literal text there is
    a string, which is true whenever it is not empty, so it becomes a quoted string
    expression, never an expression to read. Inside a longer expression, a caller's
    expression is put in parentheses and a literal is quoted. An input the caller
    leaves out reads the action's default, which `inputs` already holds.
    """
    if not isinstance(value, str):
        return value

    def quoted(given: object) -> str:
        literal = str(given).lower() if isinstance(given, bool) else str(given)
        return "'" + literal.replace("'", "''") + "'"

    whole = re.fullmatch(r"\$\{\{\s*inputs\.([\w-]+)\s*\}\}", value.strip(), re.IGNORECASE)
    if whole:
        given = inputs.get(whole.group(1).lower(), "")
        if not condition or compile_steps_module().expression_body(given) is not None:
            return given
        return "${{ " + quoted(given) + " }}"

    def replace(match: re.Match) -> str:
        given = inputs.get(match.group(1).lower(), "")
        body = compile_steps_module().expression_body(given)
        return f"({body})" if body is not None else quoted(given)

    return CALLER_INPUT.sub(replace, value)


def literal_value(value: object) -> str | None:
    """A field's literal text, lower-cased, or None when it holds an expression."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    text = str(value).strip()
    return None if "${{" in text else text.lower()


# Every `type=` field of one `cache-to` export line; buildx keeps the last it reads.
CACHE_EXPORT_TYPE = re.compile(r"(?:^|,)\s*type\s*=\s*([^,]*)", re.IGNORECASE)


def save_gate(name: str, inputs: dict) -> tuple[str, list[object]]:
    """How the step running action `name` with `inputs` (step_inputs) saves an entry.

    ("never", []): it saves nothing. ("own-rule", []): it saves on `main` alone by a
    rule this function read, not by a condition. ("gated", texts): it saves wherever
    it runs, unless a gate holds it to `main`; `texts` are the input values that gate
    it, besides its `if:` conditions. The inputs read for each action are the ones
    CACHE_SAVES names.
    """
    saving = CACHE_SAVES[name]
    if not saving.saves:
        return "never", []
    if name in ("actions/cache", "actions/cache/save"):
        return "gated", []
    if name == "swatinem/rust-cache":
        if literal_value(inputs.get("save-if")) == "false":
            return "never", []
        return "gated", [inputs.get("save-if")]
    if name == "gradle/actions/setup-gradle":
        if literal_value(inputs.get("cache-disabled")) == "true":
            return "never", []
        write_only = literal_value(inputs.get("cache-write-only"))
        if "cache-write-only" in inputs and write_only not in ("", "false"):
            # cache-write-only overrides cache-read-only and the default-branch rule.
            return "gated", []
        if "cache-read-only" not in inputs:
            # The action's default keys on `github.ref_name` and a non-null
            # `github.event.repository`, so a tag named `main` saves; every step
            # states the value instead.
            return "gated", []
        read_only = inputs["cache-read-only"]
        if literal_value(read_only) == "true":
            return "never", []
        if gradle_read_only_off_main(read_only):
            return "own-rule", []
        return "gated", []
    if name == "docker/build-push-action":
        # Each line of `cache-to` is one export, and its `type=` field alone picks the
        # backend, so an expression elsewhere in the line (a registry ref) leaves it
        # read. A line can save unless it holds exactly one `type=` field, whose value
        # is a literal other than `gha`; buildx reads a repeated field's last value.
        exports = [line.strip() for line in str(inputs.get("cache-to") or "").splitlines()]
        for line in filter(None, exports):
            types = CACHE_EXPORT_TYPE.findall(line)
            if len(types) != 1 or "${{" in types[0] or types[0].strip().lower() == "gha":
                return "gated", []
        return "never", []
    if name in TOOLCACHE_ACTIONS:
        if literal_value(inputs.get("cache")) == "":
            return "never", []
        return "gated", []
    if name == "github/codeql-action/init":
        # init reads the input, and the variable when the input is empty; an earlier
        # `run:` step can set the variable through $GITHUB_ENV, beyond what this check
        # reads, so only a literal non-saving input holds the step to no save.
        if literal_value(inputs.get("dependency-caching")) in ("false", "none", "restore"):
            return "never", []
        return "gated", []
    raise ValueError(f"CACHE_SAVES says {name} saves, and save_gate does not read it")


def main_only_gaps(
    documents: list[tuple[Path, dict]], actions: dict[str, dict] | None = None
) -> tuple[list[str], list[str]]:
    """Return (judged, gaps): each Actions-cache writer read, and each step that can
    save on a ref other than `main` or that this check cannot classify.

    CRITERION: every step that can save an Actions cache entry is held to
    `refs/heads/main` by gated_to_main: some condition the save depends on (the job's
    `if:`, each calling step's `if:`, the step's own `if:`, or the input CACHE_SAVES
    names) has no top-level `||` and has `github.ref == 'refs/heads/main'` as a
    top-level `&&` term. Those conditions are joined with `&&`, so one such term in
    any of them holds the whole save. setup-gradle is held by its own rule instead:
    with `cache-read-only: ${{ github.ref != 'refs/heads/main' }}` it saves on `main`
    alone. Input names are read without regard to case (step_inputs).

    WHY: GitHub serves an entry to the ref that saved it and to the default branch,
    never to a sibling branch, a pull request or a merge-queue ref. An entry saved
    anywhere but `main` can be restored only by a later run on the same ref, while it
    counts against the repository's 10 GB cap from the moment it is saved. The cap
    evicts the least recently used entries, so a burst of such entries (three napi
    release builds on one pull request ref saved 1.9 GB on 2026-11-03) pushes out the
    entries every pull request restores.

    SCOPE: every step of every workflow, and every step of each local composite action
    a step calls, read with the caller's `with:` filled into its `inputs.*`. A writer
    is found through CACHE_SAVES, which classifies every action PERMITTED_ACTIONS
    allows, so an action is a writer by its entry, not by its spelling. A `uses:` with
    no entry is a gap. Residual: a `run:` step that saves through the cache API
    itself. A branch named `MAIN`, which GitHub's case-insensitive `==` reads as
    `main`, is refused by the repository ruleset "refuse case variants of main".
    """
    actions = local_actions() if actions is None else actions
    judged: list[str] = []
    gaps: list[str] = []

    def walk(where: str, steps: object, conditions: list[object], depth: int) -> None:
        for index, step in enumerate(steps or []):
            if not isinstance(step, dict):
                continue
            uses = step_uses(step)
            label = f"{where}: {step.get('name') or uses or f'step {index}'}"
            gates = [*conditions, step.get("if")]
            if not uses:
                continue
            if uses.startswith("./"):
                action = actions.get(uses.rstrip("/"))
                if action is None or depth > 3:
                    gaps.append(f"{label} calls {uses}, which this check cannot read")
                    continue
                given = step_inputs(step)
                defaults = {
                    k.lower(): (spec or {}).get("default", "")
                    for k, spec in (action.get("inputs") or {}).items()
                }
                values = {**defaults, **given}
                inner = [
                    {
                        **inner_step,
                        "if": fill_inputs(inner_step.get("if"), values, condition=True),
                        "with": {
                            k: fill_inputs(v, values) for k, v in step_inputs(inner_step).items()
                        },
                    }
                    for inner_step in ((action.get("runs") or {}).get("steps") or [])
                    if isinstance(inner_step, dict)
                ]
                walk(f"{label} > {uses}", inner, gates, depth + 1)
                continue
            name = cache_action_key(uses)
            if name not in CACHE_SAVES:
                gaps.append(f"{label} uses {name}, which CACHE_SAVES does not classify")
                continue
            kind, texts = save_gate(name, step_inputs(step))
            if kind == "never":
                continue
            judged.append(label)
            if kind == "own-rule":
                continue
            held = any(gated_to_main(text, bare=True) for text in gates) or any(
                gated_to_main(text) for text in texts
            )
            if not held:
                gaps.append(
                    f"{label} can save through {name} on a ref other than `main`: no "
                    "condition it depends on has `github.ref == 'refs/heads/main'` as a "
                    "top-level `&&` term with no top-level `||`"
                )

    for path, doc in documents:
        for job_id, job in sorted((doc.get("jobs") or {}).items()):
            if isinstance(job, dict):
                walk(f"{path.name}: {job_id}", job.get("steps"), [job.get("if")], 0)
    return judged, gaps


def check_cache_writers_save_on_main_only(documents: list[tuple[Path, dict]]) -> None:
    unclassified = unclassified_actions(PERMITTED_ACTIONS, CACHE_SAVES)
    check("every permitted action has a cache classification", not unclassified, "; ".join(unclassified))
    # Every `uses:` in every composite action, called or not, is classified too.
    composite_gaps = [
        f"{uses}: {step_uses(step)}"
        for uses, action in local_actions().items()
        for step in ((action.get("runs") or {}).get("steps") or [])
        if isinstance(step, dict)
        and step_uses(step)
        and not step_uses(step).startswith("./")
        and cache_action_key(step_uses(step)) not in CACHE_SAVES
    ]
    check("every composite action's `uses:` is classified", not composite_gaps, "; ".join(composite_gaps))
    judged, gaps = main_only_gaps(documents)
    # Every `uses:` was classified (an unclassified one is a gap), and some writer was
    # found, so the gap check below cannot pass over an empty set.
    check("main-only: at least one Actions-cache writer is judged", bool(judged), "nothing judged")
    check("every Actions-cache writer saves only on `main`", not gaps, "; ".join(gaps))


def check_main_only_detects_an_off_main_writer(documents: list[tuple[Path, dict]]) -> None:
    """Planted cases: each writer marked True must be reported, each False accepted."""
    sha = "0057852bfaa89a56745cba8c7296529d2fc39830"
    save = f"actions/cache/save@{sha}"
    gradle = f"gradle/actions/setup-gradle@{sha}"
    build = f"docker/build-push-action@{sha}"
    on_main = "${{ github.ref == 'refs/heads/main' }}"
    planted_action = "./.github/actions/planted-cache"
    gated_action = "./.github/actions/planted-gated-save"
    codeql = f"github/codeql-action/init@{sha}"
    actions = {
        **local_actions(),
        planted_action: {
            "inputs": {"key": {"default": "k"}},
            "runs": {
                "using": "composite",
                "steps": [{"uses": f"actions/cache@{sha}", "with": {"key": "${{ inputs.key }}"}}],
            },
        },
        gated_action: {
            "inputs": {"gate": {"default": ""}},
            "runs": {"using": "composite", "steps": [{"uses": save, "if": "${{ inputs.gate }}"}]},
        },
    }
    cases = (
        ("mixed-case Actions/cache/save", None, {"uses": f"Actions/cache/save@{sha}"}, True),
        ("lower-case swatinem/rust-cache with no save-if", None, {"uses": f"swatinem/rust-cache@{sha}"}, True),
        ("actions/cache inside a planted composite", None, {"uses": planted_action}, True),
        (
            "setup-gradle with cache-write-only",
            None,
            {"uses": gradle, "with": {"cache-write-only": True}},
            True,
        ),
        (
            "setup-gradle with cache-write-only beside cache-read-only",
            None,
            {"uses": gradle, "with": {"cache-write-only": True, "cache-read-only": True}},
            True,
        ),
        (
            "codeql init with dependency-caching",
            None,
            {"uses": f"github/codeql-action/init@{sha}", "with": {"dependency-caching": True}},
            True,
        ),
        ("codeql init with no dependency-caching input", None, {"uses": codeql}, True),
        (
            "codeql init with an empty dependency-caching input",
            None,
            {"uses": codeql, "with": {"dependency-caching": ""}},
            True,
        ),
        ("codeql init with dependency-caching false", None, {"uses": codeql, "with": {"dependency-caching": False}}, False),
        ("setup-gradle with cache-read-only false", None, {"uses": gradle, "with": {"cache-read-only": False}}, True),
        (
            "setup-gradle with cache-read-only gated to main, the inverse",
            None,
            {"uses": gradle, "with": {"cache-read-only": on_main}},
            True,
        ),
        ("setup-gradle with no cache-read-only", None, {"uses": gradle}, True),
        ("setup-gradle with cache-read-only true", None, {"uses": gradle, "with": {"cache-read-only": True}}, False),
        ("mixed-case Cache-Write-Only key", None, {"uses": gradle, "with": {"Cache-Write-Only": True, "cache-read-only": True}}, True),
        ("mixed-case Cache key on setup-python", None, {"uses": f"actions/setup-python@{sha}", "with": {"Cache": "pip"}}, True),
        ("mixed-case Dependency-Caching key", None, {"uses": codeql, "with": {"Dependency-Caching": True}}, True),
        ("mixed-case Cache-To key", None, {"uses": build, "with": {"Cache-To": "type=gha"}}, True),
        (
            "a composite `if: ${{ inputs.gate }}` given a plain string",
            None,
            {"uses": gated_action, "with": {"gate": "github.ref == 'refs/heads/main'"}},
            True,
        ),
        (
            "a composite `if: ${{ inputs.gate }}` given a main-gate expression",
            None,
            {"uses": gated_action, "with": {"gate": on_main}},
            False,
        ),
        (
            "a cache-to line with a second type field",
            None,
            {"uses": build, "with": {"cache-to": "type=registry,ref=r,type=gha"}},
            True,
        ),
        ("an action CACHE_SAVES does not classify", None, {"uses": f"example/unlisted@{sha}"}, True),
        ("a gate on github.ref_name", None, {"uses": save, "if": "github.ref_name == 'main'"}, True),
        (
            "a gate joined to failure() by ||",
            None,
            {"uses": save, "if": "github.ref == 'refs/heads/main' || failure()"},
            True,
        ),
        ("combined actions/cache under no gate", None, {"uses": f"actions/cache@{sha}"}, True),
        ("gha layer cache", None, {"uses": build, "with": {"cache-to": "type=gha"}}, True),
        (
            "setup-gradle read-only off main",
            None,
            {"uses": gradle, "with": {"cache-read-only": "${{ github.ref != 'refs/heads/main' }}"}},
            False,
        ),
        ("save gated to main", None, {"uses": save, "if": "always() && github.ref == 'refs/heads/main'"}, False),
        ("save in a job gated to main", on_main, {"uses": save}, False),
        (
            "rust-cache wrapper gated to main",
            None,
            {"uses": RUST_CACHE_ACTION, "with": {"shared-key": "g", "save-if": on_main}},
            False,
        ),
        ("registry layer cache", None, {"uses": build, "with": {"cache-to": "type=registry,ref=r"}}, False),
        (
            "registry layer cache with an expression in its ref",
            None,
            {"uses": build, "with": {"cache-to": "type=registry,ref=ghcr.io/${{ github.repository }}/c"}},
            False,
        ),
        (
            "layer cache whose type is an expression",
            None,
            {"uses": build, "with": {"cache-to": "type=${{ inputs.kind }},ref=r"}},
            True,
        ),
        (
            "layer cache with a gha export on its second line",
            None,
            {"uses": build, "with": {"cache-to": "type=registry,ref=r\ntype=gha,mode=max"}},
            True,
        ),
    )
    for label, job_if, step, expected in cases:
        job: dict = {"runs-on": "ubuntu-latest", "steps": [step]}
        if job_if is not None:
            job["if"] = job_if
        judged, gaps = main_only_gaps([(Path("planted.yml"), {"jobs": {"j": job}})], actions)
        check(
            f"main-only: {label} is {'reported' if expected else 'accepted'}",
            bool(gaps) is expected,
            "; ".join(gaps) or "; ".join(judged) or "nothing judged",
        )
    # A newly permitted action with no classification is reported.
    check(
        "main-only: a newly permitted action with no cache classification is reported",
        unclassified_actions({**PERMITTED_ACTIONS, "example/new-action": "planted"}, CACHE_SAVES)
        == ["example/new-action has no CACHE_SAVES entry"],
    )
    # `cache: pip` on toolcache-setup's setup-python step reaches every caller.
    mutated = copy.deepcopy(actions)
    for step in mutated[TOOLCACHE_ACTION]["runs"]["steps"]:
        if action_name(step_uses(step)) == "actions/setup-python":
            step.setdefault("with", {})["cache"] = "pip"
    _, gaps = main_only_gaps(documents, mutated)
    check(
        "main-only: `cache: pip` on toolcache-setup's setup-python step is reported",
        any(f"> {TOOLCACHE_ACTION}" in gap for gap in gaps),
        "; ".join(gaps) or "nothing reported",
    )
    # fuzz.yml's corpus saves, with their ref test removed, must be reported.
    for path, doc in documents:
        if path.name != "fuzz.yml":
            continue
        mutant = copy.deepcopy(doc)
        changed = 0
        for job in mutant["jobs"].values():
            for step in job.get("steps") or []:
                if isinstance(step, dict) and step.get("name") == "Save corpus cache":
                    step["if"] = "always()"
                    changed += 1
        _, gaps = main_only_gaps([(path, mutant)])
        check(
            "main-only: fuzz.yml's corpus saves under `always()` alone are reported",
            changed == 2 and len(gaps) == 2,
            f"changed {changed}; {'; '.join(gaps)}",
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
            "changes": {
                "if": "github.event.pull_request.draft == false",
                "outputs": {"rust": "x", "python": "x"},
            },
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

    They mutate rust-test-optional-features' `group` axis, a literal list, and
    the `leg` axes of rust-clippy and rust-test-macos in ci.yml, which are
    PUSH_MATRIX expressions, so a control fails if any job loses its axis as
    well as if the reader stops working.
    """

    def edit_axis(mutant: dict, job_id: str, axis_name: str, edit) -> None:
        """Apply `edit` to each list an axis holds, rewriting an expression axis."""
        matrix = mutant["jobs"][job_id]["strategy"]["matrix"]
        axis = matrix[axis_name]
        if isinstance(axis, list):
            edit(axis)
            return
        lists = axis_event_values(axis)
        assert lists is not None
        push_values, other_values = list(lists["push"]), list(lists["other"])
        edit(push_values)
        edit(other_values)
        matrix[axis_name] = (
            f"${{{{ fromJSON(github.event_name == 'push' && "
            f"'{json.dumps(push_values)}' || '{json.dumps(other_values)}') }}}}"
        )

    for job_id, axis_name, kept, dropped_value in (
        ("rust-test-optional-features", "group", "transport", "platform-testing"),
        ("rust-clippy", "leg", "workspace", "examples"),
        ("rust-test-macos", "leg", "platform", "transport-network"),
    ):
        live = doc["jobs"].get(job_id) or {}
        axis = ((live.get("strategy") or {}).get("matrix") or {}).get(axis_name)
        lists = axis_event_values(axis)

        def gated(mutant: dict, job_id: str = job_id, axis_name: str = axis_name) -> list:
            return [
                step
                for step in mutant["jobs"][job_id]["steps"]
                if isinstance(step, dict)
                and (terms := axis_terms(step.get("if")))
                and terms[0] == axis_name
            ]

        has_gated_step = bool(gated(doc)) if live else False
        ready = (
            lists is not None
            and dropped_value in [*lists["push"], *lists["other"]]
            and has_gated_step
        )
        check(
            f"{job_id} carries the {axis_name} axis and gated steps the controls "
            f"mutate",
            ready,
            f"{axis_name} axis {axis!r}, gated step present: {has_gated_step}",
        )
        if not ready:
            continue

        extra = copy.deepcopy(doc)
        edit_axis(extra, job_id, axis_name, lambda v: v.append("added-by-the-control"))
        gaps = matrix_axis_gaps(extra)
        check(
            f"a {job_id} {axis_name} value no step names is reported",
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
            f"a {job_id} step gated on a {axis_name} value the matrix lacks is reported",
            any(
                f"names {axis_name} 'absent-from-the-matrix', which matrix axis" in gap
                for gap in gaps
            ),
            f"a step no leg runs went unreported: {gaps}",
        )

        either = copy.deepcopy(doc)
        gated(either)[0]["if"] = (
            f"matrix.{axis_name} == '{kept}' || matrix.{axis_name} == "
            f"'absent-from-the-matrix'"
        )
        gaps = matrix_axis_gaps(either)
        check(
            f"a {job_id} step whose `||` names a {axis_name} value the matrix lacks "
            f"is reported",
            any(
                f"names {axis_name} 'absent-from-the-matrix', which matrix axis" in gap
                for gap in gaps
            ),
            f"an `||` naming a value no leg takes went unreported: {gaps}",
        )

        for unreadable in (
            f"matrix.{axis_name} != '{kept}'",
            f"matrix.{axis_name} == '{kept}' && github.event_name == 'push'",
            f"matrix.{axis_name} == '{kept}' || matrix.other-axis == '{kept}'",
        ):
            mutant = copy.deepcopy(doc)
            gated(mutant)[0]["if"] = unreadable
            gaps = matrix_axis_gaps(mutant)
            check(
                f"a {job_id} step gated on `{unreadable}` is reported as unreadable",
                any(
                    f"which is not `matrix.{axis_name} == '<value>'`" in gap
                    for gap in gaps
                ),
                f"a step whose legs this check cannot read went unreported: {gaps}",
            )

        dropped = copy.deepcopy(doc)
        edit_axis(
            dropped,
            job_id,
            axis_name,
            lambda v, gone=dropped_value: v.remove(gone) if gone in v else None,
        )
        gaps = matrix_axis_gaps(dropped)
        check(
            f"deleting {dropped_value} from the {job_id} {axis_name} list is reported",
            any(f"names {axis_name} {dropped_value!r}" in gap for gap in gaps),
            f"steps left without a leg went unreported: {gaps}",
        )

        if lists["push"] != lists["other"]:
            # A step whose every named value is a push-only leg skips on a pull
            # request, and one whose every named value is a pull-request leg
            # skips on push.
            for event, values in (("pull_request", lists["push"]), ("push", lists["other"])):
                elsewhere = lists["other"] if event == "pull_request" else lists["push"]
                only = [v for v in values if v not in elsewhere]
                if not only:
                    continue
                one_event = copy.deepcopy(doc)
                gated(one_event)[0]["if"] = f"matrix.{axis_name} == '{only[0]}'"
                gaps = matrix_axis_gaps(one_event)
                check(
                    f"a {job_id} step only a {event} run skips is reported",
                    any(f"so a {event} run skips its commands" in gap for gap in gaps),
                    f"a step one event never runs went unreported: {gaps}",
                )

        for expander, entries in (
            ("include", [{"os": "ubuntu-latest", axis_name: "added-by-the-control"}]),
            ("exclude", [{axis_name: dropped_value}]),
        ):
            expanded = copy.deepcopy(doc)
            expanded["jobs"][job_id]["strategy"]["matrix"][expander] = entries
            gaps = matrix_axis_gaps(expanded)
            check(
                f"a {job_id} matrix carrying {expander} over {axis_name} is reported",
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


class Inputs(NamedTuple):
    """The parsed workflows every check in CHECKS reads."""

    workflow: dict
    jobs: dict
    documents: list[tuple[Path, dict]]


def load_inputs() -> Inputs:
    workflow = yaml.safe_load(WORKFLOW.read_text())
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
    return Inputs(workflow=workflow, jobs=workflow["jobs"], documents=documents)


ANDROID_SDK_ACTION = "./.github/actions/android-sdk"
ANDROID_SDK_INSTALLER = REPO / ".github/actions/android-sdk/install.py"
PINNED_TOOL_ACTION = "./.github/actions/pinned-tool"
PINNED_TOOL_INSTALLER = REPO / ".github/actions/pinned-tool/install.py"
TOOLCACHE_ACTION = "./.github/actions/toolcache-setup"
TOOLCACHE_ACTION_FILE = ".github/actions/toolcache-setup/action.yml"
TOOLCACHE_GUARD = REPO / ".github/actions/toolcache-setup/guard.py"
VERIFIED_DOWNLOAD_LIB = REPO / ".github/actions/lib"
# CRITERION for verified-download: every file a CI step fetches from outside the
# repository is checked against a digest this repository pins before anything unpacks
# or runs it. The pinned paths: .github/actions/lib/verified_download.py (through
# PINNED_TOOL_ACTION and ANDROID_SDK_ACTION), pip with `--require-hashes` against a
# hashed requirements file, an image reference that names `@sha256:`, and a remote
# action named by its 40-hex commit SHA.
#
# NAMED EXCEPTIONS, each fetching against a digest a lockfile or the publisher's
# signature fixes rather than one this check reads:
#   rustup    ./.github/actions/rust-toolchain and dtolnay/rust-toolchain: rustup checks
#             each component against the channel manifest's SHA-256; the manifest
#             comes over TLS and is pinned nowhere here.
#   cargo     every crate against the checksum Cargo.lock records: this repository's,
#             or the one a pinned-tool CRATES source ships (`cargo install --locked
#             --path`).
#   bun       every package against the integrity bun.lock records
#             (`bun install --frozen-lockfile`).
#   Gradle    the distribution against distributionSha256Sum and every dependency
#             against gradle/verification-metadata.xml (gradle_gaps below).
#   SwiftPM   each package at the commit Package.resolved names.
#   apt-get, dnf, brew
#             publisher-signed: apt and dnf check GPG signatures against keys the
#             runner image or the digest-pinned container image holds, and Homebrew
#             checks each bottle against the SHA-256 in its JWS-signed API.
#
# NAMED EXCEPTION, fetching nothing: the runner image's own Android SDK packages.
#   android-sdk keeps a package the runner image already holds at the revision its
#             pin names (on ubuntu-24.04: platforms;android-35, platform-tools and the
#             NDK) and downloads nothing for it, so no digest is checked for it. The
#             runner image is already trusted, in the same way the toolchain on it is:
#             the JDK toolcache-setup selects, the keys apt checks against, and the
#             command-line tools install.py lists packages with all come from it.
#             The exception holds only while nothing but the image can put a directory
#             under the SDK root before the step, so it carries a rule of its own:
#   CRITERION for the SDK root: in a job or action that uses ANDROID_SDK_ACTION, no
#             step before any use writes under the SDK root, and nothing redirects the
#             root at any use (sdk_root_write_gaps). INDICATORS it reads, not the
#             criterion: a `with: path:`, a `run:` or an `env:` that names
#             ANDROID_HOME, ANDROID_SDK_ROOT, an ANDROID_NDK variable or
#             /usr/local/lib/android, in an earlier step or in a local composite action
#             an earlier step uses; and a workflow, job or use `env:` that sets
#             ANDROID_HOME or ANDROID_SDK_ROOT.
#             A package the image lacks, holds at another revision or holds at a
#             revision install.py cannot read is downloaded and checked against its
#             pinned SHA-256 (android_pin_gaps and
#             check_android_sdk_keeps_only_the_pinned_revision below, which runs
#             install.py's main against a planted SDK root).
#
# THE STRUCTURE IS CLOSED. A remote action passes only when PERMITTED_ACTIONS lists
# it, with the verdict on what it fetches recorded there, and only when the conditions
# that verdict names hold. A remote reference names a full commit SHA. A local action
# is composite, so its steps are read here as steps. A `docker` command passes only
# with a subcommand in DOCKER_SUBCOMMANDS, and every image a docker command, a
# `docker://` step, a job container, a service, a buildx driver or a Dockerfile `FROM`
# names carries a digest. A wasm-pack install comes with the wasm-bindgen Cargo.lock
# names and a pinned wasm-opt, so wasm-pack finds both on PATH and downloads neither.
#
# INDICATORS, not the criterion: FETCH_WORDS lists commands and libraries that fetch
# over the network, read case-insensitively anywhere in a step's `run:` text, its env
# values and a github-script `script:`; each fails outright, because the pinned paths
# above replace all of them. PIP_INSTALL and CARGO_INSTALL read the two package
# managers that have a pinned form, and BUN_UNLOCKED the bun commands that resolve
# outside bun.lock.
TOOLCACHE_GUARDED = "only inside .github/actions/toolcache-setup, between its guard.py steps"
PERMITTED_ACTIONS: dict[str, str] = {
    "actions/checkout": "fetches this repository from GitHub by the commit the event names",
    "actions/cache": "restores and saves cache entries this repository's jobs wrote",
    "actions/cache/restore": "restores cache entries this repository's jobs wrote",
    "actions/cache/save": "saves a cache entry; downloads nothing",
    "swatinem/rust-cache": "restores and saves cache entries this repository's jobs wrote",
    "actions/upload-artifact": "uploads; downloads nothing",
    "actions/download-artifact": (
        "fetches an artifact a job of the same run uploaded; v4.3.0 compares it with "
        "the upload's digest but only warns on a mismatch (src/download-artifact.ts:"
        "188-195), so it trusts GitHub's artifact store as it trusts the runner"
    ),
    "actions/upload-pages-artifact": "uploads; downloads nothing",
    "actions/configure-pages": "reads the Pages configuration; downloads nothing",
    "actions/deploy-pages": "deploys an uploaded artifact; downloads nothing",
    "actions/github-script": "runs its `script:`, which the word scan reads",
    "actions/setup-python": TOOLCACHE_GUARDED,
    "actions/setup-node": TOOLCACHE_GUARDED,
    "actions/setup-java": TOOLCACHE_GUARDED,
    "dorny/paths-filter": "reads the event's changed files from the API; downloads nothing",
    "docker/login-action": "stores registry credentials; downloads nothing",
    "docker/setup-buildx-action": (
        "starts buildkit from the image `driver-opts: image=` names, which must carry a "
        "digest; without a `version:` input it downloads no buildx binary"
    ),
    "docker/build-push-action": (
        "builds a Dockerfile, whose every `FROM` and `ADD` dockerfile_gaps reads"
    ),
    "taiki-e/install-action": (
        "checks each binary against the SHA-256 in the manifest at its pinned commit "
        "(main.sh:60-77); `fallback: none` stops it installing a tool the manifest lacks "
        "through cargo-binstall"
    ),
    "github/codeql-action/init": (
        "unpacks the bundle `tools:` names, the checked file an earlier pinned-tool step "
        "hands over; with any other `tools:` it downloads a bundle unchecked "
        "(src/tools-download.ts:117)"
    ),
    "github/codeql-action/analyze": "runs the CLI init unpacked; downloads nothing",
    "dtolnay/rust-toolchain": "the rustup exception",
    "gradle/actions/setup-gradle": (
        "validates the wrapper jar and runs the wrapper's distribution; a "
        "`gradle-version:` input would download a distribution, so none may be given"
    ),
    "gradle/actions/wrapper-validation": (
        "compares the wrapper jar with the checksums services.gradle.org publishes"
    ),
}
class CacheSaving(NamedTuple):
    """Whether an action can save an Actions cache entry, and what decides it.

    `inputs` names each input (or environment variable) that decides whether it saves;
    empty for an action whose saving only its `if:` decides. save_gate reads them.
    """

    saves: bool
    inputs: tuple[str, ...]
    why: str


def never(why: str) -> CacheSaving:
    return CacheSaving(False, (), why)


# The cache classification of every action PERMITTED_ACTIONS allows, and of every
# `docker://` image a step runs; main-only-writers fails on an allowed action with no
# entry here, and on any `uses:` whose action has none. Each verdict is for the pinned
# version the workflows use.
CACHE_SAVES: dict[str, CacheSaving] = {
    "actions/checkout": never("fetches the repository; holds no cache client"),
    "actions/cache": CacheSaving(True, (), "its post step saves whenever the step ran and missed its key"),
    "actions/cache/restore": never("restores only"),
    "actions/cache/save": CacheSaving(True, (), "saves whenever it runs"),
    "swatinem/rust-cache": CacheSaving(
        True, ("save-if",), "its post step saves unless `save-if` is false; the default is true"
    ),
    "actions/upload-artifact": never("writes the artifact store, not the cache"),
    "actions/download-artifact": never("reads the artifact store"),
    "actions/upload-pages-artifact": never("writes the artifact store"),
    "actions/configure-pages": never("reads the Pages configuration"),
    "actions/deploy-pages": never("deploys an uploaded artifact"),
    "actions/github-script": never(
        "bundles no cache client; its `script:` is read by the verified-download word scan"
    ),
    "actions/setup-python": CacheSaving(True, ("cache",), "saves a package cache only with `cache:`"),
    "actions/setup-node": CacheSaving(
        True, ("cache",), "v4 saves a package cache only with `cache:` (v5 adds a default)"
    ),
    "actions/setup-java": CacheSaving(True, ("cache",), "saves a build-tool cache only with `cache:`"),
    "dorny/paths-filter": never("reads the event's changed files"),
    "docker/login-action": never("stores registry credentials"),
    "docker/setup-buildx-action": never("starts buildkit; the build step decides any cache export"),
    "docker/build-push-action": CacheSaving(
        True, ("cache-to",), "exports layers to the Actions cache only with `cache-to: type=gha`"
    ),
    "taiki-e/install-action": never("installs binaries; holds no cache client"),
    "github/codeql-action/init": CacheSaving(
        True,
        ("dependency-caching",),
        "turns on dependency caching, which analyze saves on any ref, from the input or, "
        "when the input is empty, the CODEQL_ACTION_DEPENDENCY_CACHING variable; its TRAP "
        "cache uploads on the default branch alone",
    ),
    "github/codeql-action/analyze": never(
        "saves only the dependency caches init turned on, judged at the init step"
    ),
    "dtolnay/rust-toolchain": never("runs rustup"),
    "gradle/actions/setup-gradle": CacheSaving(
        True,
        ("cache-disabled", "cache-read-only", "cache-write-only"),
        "saves where `cache-read-only` is not true; its default reads `github.ref_name`, so "
        "every step sets it, and `cache-write-only` overrides it",
    ),
    "gradle/actions/wrapper-validation": never("compares checksums"),
    "docker://ghcr.io/pypa/gh-action-pypi-publish": never("uploads to PyPI; holds no cache client"),
}
# What each kept condition reads, by action.
TOOLCACHE_ACTIONS = ("actions/setup-python", "actions/setup-node", "actions/setup-java")
GRADLE_WRAPPER_VALIDATORS = ("gradle/actions/setup-gradle", "gradle/actions/wrapper-validation")
REMOTE_REF = re.compile(r"^([^@\s]+)@([^\s@]+)$")
# A `uses:` line of a workflow or action file, with the comment after it.
USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^\s'\"#]+)['\"]?\s*(#.*)?$")
FETCH_WORDS = re.compile(
    r"(?<![\w.-])("
    r"curl|wget|aria2c|sdkmanager|invoke-webrequest|iwr|invoke-restmethod|irm"
    r"|start-bitstransfer|urllib|urlretrieve|urlopen|http\.client|httpx|requests\.get"
    r"|podman|skopeo|buildah|crane|nerdctl|pipx|uvx|npx|yarn|pnpm|bunx|cargo-binstall"
    r"|choco|winget|rustup-init|fetch\("
    r"|gh\s+(?:release|run)\s+download|uv\s+(?:pip|tool|run|add|sync)"
    r"|bun\s+(?:x|add|update|upgrade|create|pm)|npm\s+(?:install|i|ci|exec|x|update)"
    r"|go\s+(?:install|get)|gem\s+install|git\s+(?:clone|submodule)"
    r")(?![\w-])",
    re.IGNORECASE,
)
# The one curl the check admits is a health probe of a server the job itself started: it
# reads a loopback URL and discards the body, so nothing from outside the runner lands on
# disk. The exemption is a closed form, not a list of refused options: the options must be
# `-s`, `-f`, `-sf` or `-o /dev/null`, and the one URL a plain-http 127.0.0.1 address with
# a port and a path (no userinfo, query, or other host spelling). wget is never exempt.
PROBE_OPTIONS = frozenset({"-s", "-f", "-sf"})
PROBE_URL = re.compile(r"http://127\.0\.0\.1:\d+/[A-Za-z0-9._/-]*")
PIP_INSTALL = re.compile(r"(?<![\w.-])pip(?:3(?:\.\d+)?)?\s+(install|download|wheel)\b", re.I)
PIP_REQUIREMENT = re.compile(r"(?<!\S)(?:-r|--requirement)(?:\s+|=)(\S+)")
CARGO_INSTALL = re.compile(r"(?<![\w./-])cargo\s+(?:\+\S+\s+)?install\b")
BUN_INSTALL = re.compile(r"(?<![\w./-])bun\s+(?:install|i)\b")
DOCKER_WORD = re.compile(r"(?<![\w./-])docker(?![\w-])", re.IGNORECASE)
# The docker subcommands a step may run. `run`, `create` and `pull` pull the image they
# name, which docker_image parses and which must carry a digest; the rest act on
# images and containers already present and fetch nothing.
DOCKER_SUBCOMMANDS = {
    "run": "pulls its image when absent",
    "create": "pulls its image when absent",
    "pull": "pulls its image",
    "inspect": "reads a local object",
    "images": "lists local images",
    "ps": "lists local containers",
    "rm": "removes a container",
    "rmi": "removes a local image",
    "logs": "reads a container's log",
    "exec": "runs a command in a running container, pulling nothing",
    "info": "reads the daemon's state",
    "version": "reads the client and daemon versions",
}
DOCKER_PULLING = {"run", "create", "pull"}
# Options of `docker run`/`create`/`pull` that take a value as the next word. Any
# option in neither table fails, so an option this table misreads cannot hide which
# word is the image.
DOCKER_VALUE_FLAGS = {
    "-v", "--volume", "-w", "--workdir", "-e", "--env", "--env-file", "--name",
    "-u", "--user", "--entrypoint", "--network", "--platform", "--mount", "-p",
    "--publish", "--label", "-l", "--cpus", "-m", "--memory", "--shm-size", "-h",
    "--hostname", "--add-host", "--cap-add", "--cap-drop", "--security-opt", "--ulimit",
    "--tmpfs", "--device", "--pull",
}
DOCKER_BOOLEAN_FLAGS = {
    "--rm", "-i", "--interactive", "-t", "--tty", "-it", "-d", "--detach", "--init",
    "--privileged", "--read-only", "-q", "--quiet", "--disable-content-trust",
}
PINNED_IMAGE = re.compile(r"@sha256:[0-9a-f]{64}$")
SHELL_VARIABLE = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")
MATRIX_EXPRESSION = re.compile(r"^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$")
STEP_OUTPUT_PATH = re.compile(r"^\$\{\{\s*steps\.([\w-]+)\.outputs\.path\s*\}\}$")
GRADLEW = re.compile(r"(?<![\w./-])((?:[\w.-]+/)*gradlew)(?![\w.-])")
GRADLE_PROJECT_DIR = re.compile(r"(?<!\S)(?:-p|--project-dir)[ =]+(\S+)")


def action_name(uses: str) -> str:
    """The action a remote `uses:` names, lower-cased as GitHub resolves it."""
    return uses.split("@", 1)[0].lower()


def runs_guard(step: object, mode: str) -> bool:
    """Whether a step runs toolcache-setup's guard.py in `mode` (before or after)."""
    run = str(step.get("run") or "") if isinstance(step, dict) else ""
    return bool(re.search(rf'\$GITHUB_ACTION_PATH/guard\.py"?\s+{mode}\b', run))


def pinned_tool_installs(step: object, tool: str) -> bool:
    return (
        isinstance(step, dict)
        and step_uses(step) == PINNED_TOOL_ACTION
        and str((step.get("with") or {}).get("tool")) == tool
    )


def load_module(name: str, path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.cache
def locked_version(crate: str) -> str | None:
    """The version of `crate` the workspace's Cargo.lock records, if it records one."""
    lock = tomllib.loads((REPO / "Cargo.lock").read_text())
    versions = {p["version"] for p in lock.get("package", []) if p.get("name") == crate}
    return versions.pop() if len(versions) == 1 else None


def matrix_values(job: dict | None, key: str) -> list[str]:
    """Every value a job's matrix gives `key`, from its axis and its `include` entries."""
    matrix = ((job or {}).get("strategy") or {}).get("matrix") or {}
    if not isinstance(matrix, dict):
        return []
    values = [str(v) for v in matrix.get(key) or []] if isinstance(matrix.get(key), list) else []
    for entry in matrix.get("include") or []:
        if isinstance(entry, dict) and key in entry:
            values.append(str(entry[key]))
    return values


def image_values(reference: str, step: dict | None, job: dict | None) -> list[str]:
    """What an image reference can expand to.

    A `$NAME` or `${NAME}` reads the step's, then the job's, `env:`; a
    `${{ matrix.KEY }}` reads every matrix value of KEY. Anything else is literal, so
    a reference this cannot resolve is read as unpinned.
    """
    reference = reference.strip().strip("\"'")
    variable = SHELL_VARIABLE.match(reference)
    if variable:
        env = {**((job or {}).get("env") or {}), **((step or {}).get("env") or {})}
        if variable.group(1) not in env:
            return [reference]
        reference = str(env[variable.group(1)]).strip()
    matrix = MATRIX_EXPRESSION.match(reference)
    if matrix:
        return matrix_values(job, matrix.group(1)) or [reference]
    return [reference]


def image_pinned(reference: str, step: dict | None, job: dict | None) -> bool:
    return all(PINNED_IMAGE.search(v) for v in image_values(reference, step, job))


def docker_image(arguments: list[str]) -> tuple[str | None, str | None]:
    """(the image a `docker run|create|pull` names, None) or (None, why it cannot be read).

    `arguments` starts at the subcommand. The image is the first word after the
    options, each option read through DOCKER_VALUE_FLAGS and DOCKER_BOOLEAN_FLAGS.
    """
    index = 1
    while index < len(arguments):
        word = arguments[index]
        if not word.startswith("-") or word == "-":
            return word, None
        flag = word.split("=", 1)[0]
        if flag in DOCKER_VALUE_FLAGS:
            index += 1 if "=" in word else 2
        elif flag in DOCKER_BOOLEAN_FLAGS:
            index += 1
        else:
            return None, f"option {word!r}, which neither docker flag table lists"
    return None, "no image"


def docker_gaps(label: str, script: str, step: dict, job: dict | None) -> list[str]:
    """Each docker command in a script that is not permitted or pulls an unpinned image."""
    gaps, parsed = [], 0
    for line in logical_lines(script):
        for word, rest in command_words(line) or []:
            if posixpath.basename(word) != "docker":
                continue
            parsed += 1
            arguments = []
            for token in rest:
                if token in SHELL_SEPARATORS:
                    break
                arguments.append(token)
            if arguments[:1] == ["image"] or arguments[:1] == ["container"]:
                arguments = arguments[1:]
            subcommand = arguments[0] if arguments else ""
            if subcommand not in DOCKER_SUBCOMMANDS:
                gaps.append(
                    f"{label} runs `docker {subcommand}`, which DOCKER_SUBCOMMANDS does not "
                    "permit"
                )
                continue
            if subcommand not in DOCKER_PULLING:
                continue
            image, why = docker_image(arguments)
            if image is None:
                gaps.append(f"{label} runs `docker {subcommand}` whose image is unreadable: {why}")
            elif not image_pinned(image, step, job):
                gaps.append(
                    f"{label} runs `docker {subcommand}` on {image!r}, not named by digest "
                    "(`@sha256:`), so Docker checks nothing it pulls"
                )
    mentioned = len(DOCKER_WORD.findall(script_text(script)))
    if mentioned != parsed:
        gaps.append(
            f"{label} names docker {mentioned} times outside comments but runs "
            f"{parsed} docker commands the check can read; run each directly, not "
            "through `bash -c`, a variable or an unsplittable line"
        )
    return gaps


def script_text(script: str) -> str:
    """A script's logical lines, comments dropped."""
    return "\n".join(logical_lines(script))


def scanned_text(step: dict) -> str:
    """Every text of a step the shell or an interpreter runs: `run:`, env values, `script:`."""
    texts = [script_text(str(step.get("run") or ""))]
    texts += [str(v) for v in (step.get("env") or {}).values()]
    script = (step.get("with") or {}).get("script")
    if script is not None:
        texts.append(str(script))
    return "\n".join(texts)


def loopback_probe(text: str, match: re.Match) -> bool:
    """Whether a curl command is exactly the closed health-probe form PROBE_URL admits."""
    if match.group(1) != "curl":
        return False
    command = re.split(r"&&|\|\||[;|\n]", text[match.end() :], maxsplit=1)[0]
    tokens = command.split()
    urls = 0
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in PROBE_OPTIONS:
            i += 1
        elif token == "-o" and i + 1 < len(tokens) and tokens[i + 1] == "/dev/null":
            i += 2
        elif PROBE_URL.fullmatch(token):
            urls += 1
            i += 1
        else:
            return False
    return urls == 1


def run_gaps(label: str, step: dict, job: dict | None) -> list[str]:
    """Each fetch in a step's run text that bypasses the pinned paths."""
    gaps = []
    text = scanned_text(step)
    words = sorted({
        m.group(1).lower() for m in FETCH_WORDS.finditer(text) if not loopback_probe(text, m)
    })
    if words:
        gaps.append(
            f"{label} runs {', '.join(words)}, which fetches outside the pinned paths; "
            f"download through {PINNED_TOOL_ACTION} (verified_download.py) instead"
        )
    default = ((job or {}).get("defaults") or {}).get("run") or {}
    cwd = str(step.get("working-directory") or default.get("working-directory") or ".")
    cwd = re.sub(r"^\$\{\{\s*github\.workspace\s*\}\}", ".", cwd)
    for line in text.splitlines():
        if PIP_INSTALL.search(line) and "--require-hashes" not in line:
            gaps.append(
                f"{label} runs pip without --require-hashes: {line.strip()!r}; install a "
                "hashed file under .github/requirements/"
            )
        # A hashed install fails at run time when its file is missing from the directory
        # the step runs in, so each requirements path must name a tracked file from there.
        if PIP_INSTALL.search(line):
            for req in PIP_REQUIREMENT.findall(line):
                req = req.strip("\"'")
                resolved = posixpath.normpath(posixpath.join(cwd, req))
                if "$" in req or "$" in cwd or not (REPO / resolved).is_file():
                    gaps.append(
                        f"{label} installs requirements {req!r} from working directory "
                        f"{cwd!r}, which names no file in the repository"
                    )
        if CARGO_INSTALL.search(line) and not (
            re.search(r"(?<!\S)--locked(?!\S)", line) and re.search(r"(?<!\S)--path[ =]", line)
        ):
            gaps.append(
                f"{label} runs cargo install without both --locked and --path: "
                f"{line.strip()!r}; install the source a {PINNED_TOOL_ACTION} CRATES pin "
                "hands over"
            )
        if BUN_INSTALL.search(line) and "--frozen-lockfile" not in line:
            gaps.append(
                f"{label} runs bun install without --frozen-lockfile: {line.strip()!r}"
            )
    gaps += docker_gaps(label, str(step.get("run") or ""), step, job)
    return gaps


def local_action_gaps(label: str, uses: str) -> list[str]:
    """A local action must be a composite action, so its steps are read as steps."""
    if uses.endswith((".yml", ".yaml")):
        return []
    directory = REPO / uses.removeprefix("./")
    files = [directory / "action.yml", directory / "action.yaml"]
    found = next((f for f in files if f.is_file()), None)
    if found is None:
        return [f"{label} uses {uses}, which has no action.yml"]
    using = str(((yaml.safe_load(found.read_text()) or {}).get("runs") or {}).get("using"))
    if using != "composite":
        return [
            f"{label} uses {uses}, a {using!r} action; only composite local actions are "
            "read step by step"
        ]
    return []


def remote_action_gaps(
    where: str, label: str, step: dict, steps: list, index: int
) -> list[str]:
    """A remote action must be on PERMITTED_ACTIONS, at a commit SHA, under its conditions."""
    uses = step_uses(step)
    if uses.startswith("docker://"):
        if image_pinned(uses[len("docker://"):], step, None):
            return []
        return [f"{label} uses {uses}, an image not named by digest"]
    match = REMOTE_REF.match(uses)
    if not match:
        return [f"{label} uses {uses!r}, which names no ref"]
    name, ref = action_name(uses), match.group(2)
    gaps = []
    if not COMMIT_SHA.fullmatch(ref):
        gaps.append(
            f"{label} uses {uses}, whose ref {ref!r} is not a 40-hex commit SHA, so "
            "whoever moves it chooses the code that runs"
        )
    if name not in PERMITTED_ACTIONS:
        return gaps + [
            f"{label} uses {name}, which PERMITTED_ACTIONS does not list; record what it "
            "fetches there, or replace it with a step that fetches through "
            f"{PINNED_TOOL_ACTION}"
        ]
    inputs = step.get("with") or {}
    if name in TOOLCACHE_ACTIONS and not (
        where == TOOLCACHE_ACTION_FILE
        and any(runs_guard(s, "before") for s in steps[:index])
        and any(runs_guard(s, "after") for s in steps[index + 1:])
    ):
        gaps.append(f"{label} uses {name}, permitted {TOOLCACHE_GUARDED}; use {TOOLCACHE_ACTION}")
    if name == "docker/setup-buildx-action":
        image = re.search(r"(?:^|[\s,])image=(\S+)", str(inputs.get("driver-opts") or ""))
        if image is None or not PINNED_IMAGE.search(image.group(1).rstrip(",")):
            gaps.append(
                f"{label} starts buildkit from an image not named by digest; pass "
                "`driver-opts: image=<ref>@sha256:<digest>`"
            )
        if "version" in inputs:
            gaps.append(f"{label} passes `version:`, which downloads a buildx binary")
    if name == "taiki-e/install-action":
        if str(inputs.get("fallback")) != "none":
            gaps.append(f"{label} omits `fallback: none`, so a tool the manifest lacks installs unchecked")
        if str(inputs.get("checksum", "true")).lower() == "false":
            gaps.append(f"{label} turns the checksum off")
        tools = [t.strip() for t in str(inputs.get("tool") or "").split(",")]
        if any(t.split("@")[0] == "wasm-pack" for t in tools):
            gaps += wasm_pack_gaps(label, tools, steps)
    if name == "github/codeql-action/init":
        output = STEP_OUTPUT_PATH.match(str(inputs.get("tools") or ""))
        if output is None or not any(
            isinstance(s, dict)
            and str(s.get("id")) == output.group(1)
            and step_uses(s) == PINNED_TOOL_ACTION
            for s in steps[:index]
        ):
            gaps.append(
                f"{label} passes `tools:` {inputs.get('tools')!r}, not the `path` output "
                f"of an earlier {PINNED_TOOL_ACTION} step, so init downloads its bundle "
                "unchecked"
            )
    if name == "gradle/actions/setup-gradle" and "gradle-version" in inputs:
        gaps.append(f"{label} passes `gradle-version:`, which downloads a distribution unchecked")
    return gaps


def wasm_pack_gaps(label: str, tools: list[str], steps: list) -> list[str]:
    """wasm-pack must find the locked wasm-bindgen and a pinned wasm-opt on PATH."""
    gaps = []
    bindgen = locked_version("wasm-bindgen")
    if f"wasm-bindgen@{bindgen}" not in tools:
        gaps.append(
            f"{label} installs wasm-pack without wasm-bindgen@{bindgen}, the version "
            "Cargo.lock names, so wasm-pack downloads wasm-bindgen unchecked"
        )
    if not any(pinned_tool_installs(s, "wasm-opt") for s in steps):
        gaps.append(
            f"{label} installs wasm-pack in a job with no {PINNED_TOOL_ACTION} wasm-opt "
            "step, so wasm-pack downloads wasm-opt unchecked"
        )
    return gaps


SDK_ROOT_NAMES = re.compile(r"ANDROID_HOME|ANDROID_SDK_ROOT|ANDROID_NDK\w*|/usr/local/lib/android")
SDK_ROOT_VARIABLES = ("ANDROID_HOME", "ANDROID_SDK_ROOT")


def local_action_steps(uses: str) -> list:
    """The steps of a local composite action, or [] for anything else."""
    if not uses.startswith("./") or uses.endswith((".yml", ".yaml")):
        return []
    directory = REPO / uses.removeprefix("./")
    found = next(
        (f for f in (directory / "action.yml", directory / "action.yaml") if f.is_file()),
        None,
    )
    if found is None:
        return []
    runs = (yaml.safe_load(found.read_text()) or {}).get("runs") or {}
    steps = runs.get("steps") if runs.get("using") == "composite" else None
    return steps if isinstance(steps, list) else []


def sdk_root_writes(label: str, step: dict, seen: frozenset = frozenset()) -> list[str]:
    """Each way `step`, or a local action it uses, can write under the SDK root."""
    found = []
    path = str((step.get("with") or {}).get("path") or "")
    if SDK_ROOT_NAMES.search(path):
        found.append(f"{label} writes to `path:` {path!r}")
    run = script_text(str(step.get("run") or ""))
    if SDK_ROOT_NAMES.search(run):
        found.append(f"{label} runs a command that names {SDK_ROOT_NAMES.search(run)[0]}")
    for key, value in (step.get("env") or {}).items():
        if SDK_ROOT_NAMES.search(f"{key}={value}"):
            found.append(f"{label} sets `env:` {key}={value!r}")
    uses = step_uses(step)
    if uses not in seen and uses != ANDROID_SDK_ACTION:
        for index, inner in enumerate(local_action_steps(uses)):
            if isinstance(inner, dict):
                found += sdk_root_writes(f"{label} > {uses} step {index}", inner, seen | {uses})
    return found


def sdk_root_write_gaps(where: str, steps: list, job: dict | None = None) -> list[str]:
    """No step before any ANDROID_SDK_ACTION use writes under the SDK root, nor redirects it.

    install.py keeps a directory that already names its pinned revision without
    checking a digest; that is safe only while the runner image alone wrote it. So for
    each use, every earlier step is read, and the env in effect at the use (`job`'s
    `env:`, which download_step_lists merges over the workflow's, and the use's own)
    must not set the root.
    """
    uses = [
        index
        for index, step in enumerate(steps)
        if isinstance(step, dict) and step_uses(step) == ANDROID_SDK_ACTION
    ]
    if not uses:
        return []
    why = (
        f"before {ANDROID_SDK_ACTION}, which keeps a directory at its pinned revision "
        "unchecked and so trusts that only the runner image wrote under the SDK root"
    )
    gaps = [
        f"{where} sets {key} in the workflow's or job's `env:`, so {ANDROID_SDK_ACTION} "
        "reads a root the runner image did not fill"
        for key in (job or {}).get("env") or {}
        if key in SDK_ROOT_VARIABLES
    ]
    for use in uses:
        for key in steps[use].get("env") or {}:
            if key in SDK_ROOT_VARIABLES:
                gaps.append(f"{where} step {use} sets {key} for {ANDROID_SDK_ACTION}")
    # Every step before the last use precedes some use; an earlier use is itself read,
    # so an `env:` it sets for its own run is reported once, above, not twice.
    for index, step in enumerate(steps[: uses[-1]]):
        if isinstance(step, dict) and index not in uses:
            label = f"{where} step {index} ({step.get('name') or step_uses(step) or 'run'})"
            gaps += [f"{write}, {why}" for write in sdk_root_writes(label, step)]
    return gaps


def unverified_download_gaps(where: str, steps: object, job: dict | None = None) -> list[str]:
    """Return each way a step under `where` fetches outside the pinned paths.

    `job` is the workflow job the steps belong to, None for a local action; image
    references resolve against its `env:` and matrix.
    """
    steps = steps if isinstance(steps, list) else []
    gaps = sdk_root_write_gaps(where, steps, job)
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        label = f"{where} step {index} ({step.get('name') or step_uses(step) or 'run'})"
        uses = step_uses(step)
        if uses.startswith("./"):
            gaps += local_action_gaps(label, uses)
        elif uses:
            gaps += remote_action_gaps(where, label, step, steps, index)
        gaps += run_gaps(label, step, job)
    return gaps


def job_uses_gaps(where: str, job: dict) -> list[str]:
    """A job that calls a reusable workflow may call only a local one."""
    uses = str(job.get("uses") or "")
    if not uses or uses.startswith("./"):
        return []
    return [f"{where} calls the remote workflow {uses}, which PERMITTED_ACTIONS cannot vouch for"]


def job_image_gaps(where: str, job: dict) -> list[str]:
    """A job's `container:` and `services:` images must each be named by digest."""
    images = []
    container = job.get("container")
    if container:
        images.append(("container", container))
    for name, service in sorted((job.get("services") or {}).items()):
        images.append((f"service {name}", service))
    gaps = []
    for what, entry in images:
        image = str(entry.get("image") if isinstance(entry, dict) else entry)
        if not image_pinned(image, None, job):
            gaps.append(f"{where} {what} image {image!r} is not named by digest")
    return gaps


def uses_comment_gaps(where: str, text: str) -> list[str]:
    """Every remote `uses:` line carries the tag its SHA stands for in a comment."""
    gaps = []
    for number, line in enumerate(text.splitlines(), 1):
        match = USES_LINE.match(line)
        if not match or match.group(1).startswith(("./", "docker://")):
            continue
        if not (match.group(2) or "").lstrip("#").strip():
            gaps.append(f"{where}:{number} names {match.group(1)} with no tag comment")
    return gaps


def dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    """(instruction, its arguments) for each instruction, continuations joined."""
    found, current = [], ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not current and (not stripped or stripped.startswith("#")):
            continue
        if stripped.startswith("#"):
            continue
        current += " " + stripped.removesuffix("\\")
        if stripped.endswith("\\"):
            continue
        words = current.split(None, 1)
        found.append((words[0].upper(), words[1] if len(words) > 1 else ""))
        current = ""
    return found


def dockerfile_gaps(where: str, text: str) -> list[str]:
    """Every image a Dockerfile names carries a digest, every URL `ADD` a checksum."""
    gaps, stages, args = [], set(), {}
    for line in text.splitlines():
        directive = re.match(r"#\s*syntax\s*=\s*(\S+)", line.strip(), re.I)
        if directive and not PINNED_IMAGE.search(directive.group(1)):
            gaps.append(f"{where} names the frontend {directive.group(1)} without a digest")
    for instruction, rest in dockerfile_instructions(text):
        words = rest.split()
        if instruction == "ARG" and words:
            name, _, default = words[0].partition("=")
            args[name] = default
        elif instruction == "FROM":
            positional = [w for w in words if not w.startswith("--")]
            image = positional[0] if positional else ""
            if len(positional) >= 3 and positional[1].lower() == "as":
                stage = positional[2].lower()
            else:
                stage = None
            if "${TARGETARCH}" in image or "$TARGETARCH" in image:
                expansions = [
                    image.replace("${TARGETARCH}", arch).replace("$TARGETARCH", arch)
                    for arch in ("amd64", "arm64")
                ]
                missing = [e for e in expansions if e.lower() not in stages]
                if missing:
                    gaps.append(f"{where} FROM {image} expands to {missing}, not earlier stages")
            elif not (
                image == "scratch" or image.lower() in stages or PINNED_IMAGE.search(image)
            ):
                gaps.append(f"{where} FROM {image} is not named by digest")
            if stage:
                stages.add(stage)
        elif instruction in ("COPY", "ADD"):
            source = next((w.split("=", 1)[1] for w in words if w.startswith("--from=")), None)
            if source and not (source.lower() in stages or source.isdigit() or PINNED_IMAGE.search(source)):
                gaps.append(f"{where} {instruction} --from={source} names an image without a digest")
            if instruction == "ADD" and any(re.match(r"(https?|git)[:@]", w) for w in words):
                if not any(w.startswith("--checksum=sha256:") for w in words):
                    gaps.append(f"{where} ADD fetches a URL with no --checksum=sha256:")
        elif instruction == "RUN":
            fetches = sorted({m.group(1).lower() for m in FETCH_WORDS.finditer(rest)})
            if fetches:
                gaps.append(f"{where} RUN fetches with {', '.join(fetches)}")
            if PIP_INSTALL.search(rest) and "--require-hashes" not in rest:
                gaps.append(f"{where} RUN runs pip without --require-hashes")
    return gaps


def tracked_dockerfiles() -> list[Path]:
    listed = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "-z", "--", "*Dockerfile*", "*Containerfile*",
         "*.dockerfile"],
        capture_output=True, text=True, check=True,
    ).stdout.split("\0")
    return [REPO / name for name in listed if name]


def download_step_lists(
    documents: list[tuple[Path, dict]],
) -> list[tuple[str, object, dict | None]]:
    """Every workflow job's steps, with the job, and every local composite action's steps."""
    found = []
    for path, doc in documents:
        workflow_env = doc.get("env") if isinstance(doc.get("env"), dict) else {}
        for job_id, job in sorted((doc.get("jobs") or {}).items()):
            # A job's steps see the workflow's `env:` under the job's own, so the job
            # passed on carries the env in effect for its steps.
            job_env = job.get("env") if isinstance(job.get("env"), dict) else {}
            effective = {**job, "env": {**workflow_env, **job_env}}
            found.append((f"{path.name}:{job_id}", job.get("steps"), effective))
    for action in sorted((REPO / ".github/actions").glob("*/action.y*ml")):
        doc = yaml.safe_load(action.read_text()) or {}
        found.append(
            (str(action.relative_to(REPO)), (doc.get("runs") or {}).get("steps"), None)
        )
    return found


class GradleRun(NamedTuple):
    wrapper_dir: str
    build_root: str


def gradle_runs(job: dict, step: dict) -> list[GradleRun]:
    """Each gradlew a step runs: the wrapper's directory and the build it runs.

    Both are repository-relative: the step's working directory (else the job's) joined
    with the gradlew path, and with `-p`/`--project-dir` where the line passes one.
    """
    default = ((job.get("defaults") or {}).get("run") or {}).get("working-directory")
    cwd = str(step.get("working-directory") or default or ".")
    found = []
    for line in logical_lines(str(step.get("run") or "")):
        for match in GRADLEW.finditer(line):
            wrapper = posixpath.normpath(
                posixpath.join(cwd, posixpath.dirname(match.group(1)))
            )
            project = GRADLE_PROJECT_DIR.search(line[match.end() :])
            root = (
                posixpath.normpath(posixpath.join(cwd, project.group(1).strip("\"'")))
                if project
                else posixpath.normpath(cwd)
            )
            found.append(GradleRun(wrapper, root))
    return found


def wrapper_validation_gaps(where: str, job: dict) -> list[str]:
    """A job that runs gradlew must validate the wrapper jar before the first run."""
    steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
    for index, step in enumerate(steps):
        if not gradle_runs(job, step):
            continue
        validated = any(
            action_name(step_uses(s)) in GRADLE_WRAPPER_VALIDATORS
            and str((s.get("with") or {}).get("validate-wrappers", "true")).lower()
            != "false"
            for s in steps[:index]
        )
        if not validated:
            return [
                f"{where} step {index} runs gradlew with no earlier step using one of "
                f"{list(GRADLE_WRAPPER_VALIDATORS)} (setup-gradle with validate-wrappers "
                "on), so an altered wrapper jar would run unchecked"
            ]
        return []
    return []


def wrapper_properties_gaps(where: str, text: str | None) -> list[str]:
    if text is None:
        return [f"{where} does not exist"]
    if not re.search(r"(?m)^distributionSha256Sum=[0-9a-f]{64}\s*$", text):
        return [
            f"{where} has no distributionSha256Sum, so the wrapper unpacks the "
            "distribution it downloads unchecked"
        ]
    return []


def verification_metadata_gaps(where: str, text: str | None) -> list[str]:
    """gradle/verification-metadata.xml must exist, verify metadata and trust nothing.

    A `<trust>` entry skips the checksum for whatever it matches, whether it names one
    jar or every artifact, so any entry fails: each artifact carries its own sha256.
    """
    import xml.etree.ElementTree as ET

    if text is None:
        return [
            f"{where} does not exist, so Gradle resolves every dependency unchecked"
        ]
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        return [f"{where} does not parse: {error}"]
    namespace = re.match(r"\{[^}]*\}", root.tag)
    ns = namespace.group(0) if namespace else ""
    gaps = []
    verify = root.find(f"{ns}configuration/{ns}verify-metadata")
    if verify is None or (verify.text or "").strip() != "true":
        gaps.append(f"{where} does not set verify-metadata to true")
    for trust in root.iter(f"{ns}trust"):
        gaps.append(f"{where} trusts an artifact without a checksum: {trust.attrib}")
    if not any(True for _ in root.iter(f"{ns}sha256")):
        gaps.append(f"{where} records no sha256 checksum")
    return gaps


def gradle_gaps(documents: list[tuple[Path, dict]]) -> tuple[list[str], int]:
    """Gradle gaps across every workflow job, and how many gradlew runs were read."""
    gaps, runs = [], set()
    for path, doc in documents:
        for job_id, job in sorted((doc.get("jobs") or {}).items()):
            gaps += wrapper_validation_gaps(f"{path.name}:{job_id}", job)
            for step in job.get("steps") or []:
                if isinstance(step, dict):
                    runs.update(gradle_runs(job, step))
    for wrapper in sorted({run.wrapper_dir for run in runs}):
        properties = REPO / wrapper / "gradle/wrapper/gradle-wrapper.properties"
        gaps += wrapper_properties_gaps(
            str(properties.relative_to(REPO)),
            properties.read_text() if properties.is_file() else None,
        )
    for root in sorted({run.build_root for run in runs}):
        metadata = REPO / root / "gradle/verification-metadata.xml"
        gaps += verification_metadata_gaps(
            str(metadata.relative_to(REPO)),
            metadata.read_text() if metadata.is_file() else None,
        )
    return gaps, len(runs)


def load_verified_download():
    """The module both installers import, as they import it."""
    if str(VERIFIED_DOWNLOAD_LIB) not in sys.path:
        sys.path.insert(0, str(VERIFIED_DOWNLOAD_LIB))
    import verified_download

    return verified_download


def check_installer_rejects_a_corrupt_archive() -> None:
    """Feed the shared download a truncated archive and a whole one over file://."""
    import contextlib
    import hashlib
    import io
    import xml.etree.ElementTree as ET
    import zipfile

    installer = load_module("android_sdk_install", ANDROID_SDK_INSTALLER)
    pinned = load_module("pinned_tool_install", PINNED_TOOL_INSTALLER)
    downloads = load_verified_download()
    check(
        "both installers download through verified_download.download_verified",
        installer.download_verified is downloads.download_verified
        and pinned.download_verified is downloads.download_verified,
        f"android-sdk uses {installer.download_verified!r}, pinned-tool uses "
        f"{pinned.download_verified!r}",
    )
    # A mismatched attempt prints a `::warning::`; `quiet` keeps it out of the log so
    # the planted mismatches raise no annotation on the run.
    quiet = functools.partial(contextlib.redirect_stdout, io.StringIO())
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("pkg/source.properties", "Pkg.Revision=1\n")
            archive.writestr("pkg/blob", os.urandom(4096))
        whole = payload.getvalue()
        good = root / "good.zip"
        good.write_bytes(whole)
        truncated = root / "truncated.zip"
        truncated.write_bytes(whole[: len(whole) // 2])
        real_fetch = downloads.fetch_once
        for algorithm in ("sha1", "sha256"):
            digest = hashlib.new(algorithm, whole).hexdigest()
            fetched = []

            def counting_fetch(url, destination, algorithm, *rest, fetched=fetched):
                fetched.append(url)
                return real_fetch(url, destination, algorithm, *rest)

            downloads.fetch_once = counting_fetch
            try:
                with quiet():
                    downloads.download_verified(
                        "planted;truncated",
                        truncated.as_uri(),
                        len(whole),
                        digest,
                        root / "out-truncated.zip",
                        algorithm,
                        attempts=3,
                        backoff=0,
                    )
                error = ""
            except downloads.InstallError as raised:
                error = str(raised)
            check(
                f"verified_download fails on a truncated archive ({algorithm}), naming "
                "the artifact and URL",
                "planted;truncated" in error and truncated.as_uri() in error,
                f"got {error!r}",
            )
            check(
                f"verified_download retries a mismatched archive ({algorithm}) a "
                "bounded number of times",
                len(fetched) == 3 and not (root / "out-truncated.zip").exists(),
                f"fetched {len(fetched)} times; a mismatched archive must be refetched "
                "up to `attempts` times and never left on disk",
            )
            try:
                with quiet():
                    downloads.download_verified(
                        "planted;whole",
                        good.as_uri(),
                        len(whole),
                        digest,
                        root / "out-whole.zip",
                        algorithm,
                        attempts=3,
                        backoff=0,
                    )
                error = ""
            except downloads.InstallError as raised:
                error = str(raised)
            check(
                f"verified_download accepts an archive whose size and {algorithm} "
                "match its pin",
                not error and (root / "out-whole.zip").read_bytes() == whole,
                f"got {error!r}",
            )
            (root / "out-whole.zip").unlink(missing_ok=True)
        # A connection that drops mid-body raises http.client.IncompleteRead, an
        # HTTPException rather than an OSError; the download must retry it like any
        # other failed attempt.
        import http.client

        digest = hashlib.sha256(whole).hexdigest()
        dropped = []

        def dropping_fetch(url, destination, algorithm, *rest, dropped=dropped):
            dropped.append(url)
            if len(dropped) == 1:
                raise http.client.IncompleteRead(b"partial", 100)
            return real_fetch(url, destination, algorithm, *rest)

        downloads.fetch_once = dropping_fetch
        try:
            with quiet():
                downloads.download_verified(
                    "planted;dropped",
                    good.as_uri(),
                    len(whole),
                    digest,
                    root / "out-dropped.zip",
                    "sha256",
                    attempts=3,
                    backoff=0,
                )
            error = ""
        except Exception as raised:  # noqa: BLE001 - any escape is the failure reported
            error = f"{type(raised).__name__}: {raised}"
        check(
            "verified_download retries a body cut short (http.client.IncompleteRead)",
            not error
            and len(dropped) == 2
            and (root / "out-dropped.zip").read_bytes() == whole,
            f"fetched {len(dropped)} times, got {error!r}",
        )
        downloads.fetch_once = real_fetch
    # sdkmanager lists the NDK and the emulator only by the package.xml install.py writes
    # for a pin with a display name; the file must name the package path and revision.
    wrong = []
    for package, pin in installer.PINS.items():
        if pin.display_name is None:
            continue
        local = ET.fromstring(installer.package_xml(package, pin)).find("localPackage")
        revision = local.find("revision") if local is not None else None
        listed = (
            ".".join(part.text or "" for part in revision)
            if revision is not None
            else None
        )
        if local is None or local.get("path") != package or listed != pin.revision:
            path = local.get("path") if local is not None else None
            wrong.append(f"{package}: path {path!r}, revision {listed!r}")
    check(
        "install.py writes a package.xml naming each generic pin's path and revision",
        not wrong,
        "; ".join(wrong),
    )
    # Every pinned-tool pin names an https URL and a whole SHA-256, and every archive
    # and wheel a python-versions package installs from is pinned.
    malformed = [
        f"{key}: {archive.url}"
        for key, archive in [
            *pinned.PINS.items(),
            *pinned.BUNDLES.items(),
            *pinned.CRATES.items(),
            *(("wheel", w) for w in pinned.WHEELS),
        ]
        if not archive.url.startswith("https://")
        or not re.fullmatch(r"[0-9a-f]{64}", archive.sha256)
        or archive.size <= 0
    ]
    check(
        "every pinned-tool pin names an https URL, a size and a SHA-256",
        not malformed,
        "; ".join(malformed),
    )
    with tempfile.TemporaryDirectory() as scratch:
        environment = dict(
            os.environ,
            RUNNER_OS="Plan9",
            RUNNER_ARCH="X64",
            RUNNER_TEMP=scratch,
            RUNNER_TOOL_CACHE=scratch,
            GITHUB_PATH=str(Path(scratch, "path")),
        )
        result = subprocess.run(
            [sys.executable, "-I", str(PINNED_TOOL_INSTALLER), "bun"],
            env=environment,
            capture_output=True,
            text=True,
        )
    check(
        "pinned-tool fails, naming the tool, on a runner it has no pin for",
        result.returncode != 0 and "no pin" in result.stdout and "bun" in result.stdout,
        f"exit {result.returncode}: {result.stdout.strip()!r}",
    )


def android_pin_gaps(pins: dict) -> list[str]:
    """Every android-sdk pin without a relative archive path, a size and a whole SHA-256."""
    return [
        f"{package}: {pin!r}"
        for package, pin in pins.items()
        if not re.fullmatch(r"[0-9a-f]{64}", getattr(pin, "sha256", "") or "")
        or pin.size <= 0
        or not pin.archive
        or "://" in pin.archive
        or pin.archive.startswith("/")
        or not re.fullmatch(r"\d+(\.\d+)*", pin.revision)
    ]


def check_android_sdk_keeps_only_the_pinned_revision() -> None:
    """Every android-sdk pin carries a SHA-256, and only the pinned revision skips a download."""
    installer = load_module("android_sdk_install", ANDROID_SDK_INSTALLER)
    gaps = android_pin_gaps(installer.PINS)
    check(
        "every android-sdk pin names an archive path, a size and a SHA-256",
        not gaps,
        "; ".join(gaps),
    )
    pin = installer.PINS["platform-tools"]
    planted = {
        "a SHA-1 in place of a SHA-256": pin._replace(sha256=pin.sha256[:40]),
        "an empty digest": pin._replace(sha256=""),
        "a zero size": pin._replace(size=0),
        "an absolute URL": pin._replace(archive="https://example.com/p.zip"),
        "a revision install.py cannot read": pin._replace(revision="37.0.2 rc1"),
    }
    for name, bad in planted.items():
        check(
            f"android_pin_gaps reports a planted pin with {name}",
            bool(android_pin_gaps({"planted": bad})),
        )
    with tempfile.TemporaryDirectory() as scratch:
        held = Path(scratch, "held")
        held.mkdir()
        (held / "source.properties").write_text(f"Pkg.Revision={pin.revision}.0\n")
        other = Path(scratch, "other")
        other.mkdir()
        (other / "source.properties").write_text("Pkg.Revision=36.0.0\n")
        bare = Path(scratch, "bare")
        bare.mkdir()
        check(
            "android-sdk keeps a directory that holds the pinned revision",
            installer.held_by_image(held, pin),
        )
        check(
            "android-sdk downloads over a directory at another revision",
            not installer.held_by_image(other, pin),
        )
        check(
            "android-sdk downloads over a directory with no source.properties",
            not installer.held_by_image(bare, pin),
        )
        check(
            "android-sdk downloads a package the SDK root lacks",
            not installer.held_by_image(Path(scratch, "absent"), pin),
        )
        rc = Path(scratch, "rc")
        rc.mkdir()
        (rc / "source.properties").write_text(f"Pkg.Revision={pin.revision} rc1\n")
        try:
            held_rc = installer.held_by_image(rc, pin)
        except Exception as raised:  # noqa: BLE001 - any escape is the failure reported
            held_rc = f"{type(raised).__name__}: {raised}"
        check(
            "android-sdk downloads over a directory whose revision it cannot read",
            held_rc is False,
            f"held_by_image returned {held_rc!r}",
        )
    check_android_sdk_main_against_a_planted_root()


def run_android_sdk_main(
    directories: dict[str, str | None],
    archived: dict[str, str],
    listed: dict[str, str],
) -> tuple[str, list[str], dict[str, str]]:
    """Run install.py's main over a planted SDK root and a planted archive server.

    `directories` maps each planted package name to the source.properties line its
    directory holds before main runs (None: a directory with no source.properties).
    `archived` maps a name to the Pkg.Revision its served archive records, and `listed`
    to the revision the stub sdkmanager lists. Every pin names revision PLANTED_REVISION.
    Returns main's error (empty when it returned), the archive paths requested, and each
    directory's marker afterwards: "image" when main kept it, "downloaded" when replaced.
    """
    import contextlib
    import hashlib
    import http.server
    import io
    import threading
    import zipfile

    installer = load_module("android_sdk_install_main", ANDROID_SDK_INSTALLER)
    archives = {}
    for name, revision in archived.items():
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("pkg/source.properties", f"Pkg.Revision={revision}\n")
            archive.writestr("pkg/marker", "downloaded")
        archives[f"/{name}.zip"] = payload.getvalue()
    requested: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep the planted server out of the log
            pass

        def do_GET(self):  # the name http.server dispatches on
            requested.append(self.path)
            data = archives.get(self.path)
            if data is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    installer.BASE_URL = f"http://127.0.0.1:{server.server_address[1]}/"
    installer.PINS = {
        f"planted;{name}": installer.Pin(
            PLANTED_REVISION,
            f"{name}.zip",
            len(archives.get(f"/{name}.zip", b"x")),
            hashlib.sha256(archives.get(f"/{name}.zip", b"x")).hexdigest(),
        )
        for name in directories
    }
    keys = ("ANDROID_HOME", "ANDROID_SDK_ROOT", "GITHUB_PATH", "GITHUB_ENV")
    saved = {key: os.environ.get(key) for key in keys}
    markers = {}
    try:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch, "sdk")
            tools = root / "cmdline-tools/latest/bin"
            tools.mkdir(parents=True)
            listing = "".join(f"planted;{n} | {r}\\n" for n, r in listed.items())
            (tools / "sdkmanager").write_text(
                f"#!/bin/sh\nprintf 'Path | Version\\n------- | -------\\n{listing}'\n"
            )
            (tools / "sdkmanager").chmod(0o755)
            for name, line in directories.items():
                directory = root / "planted" / name
                directory.mkdir(parents=True)
                (directory / "marker").write_text("image")
                if line is not None:
                    (directory / "source.properties").write_text(line + "\n")
            os.environ.pop("ANDROID_SDK_ROOT", None)
            os.environ["ANDROID_HOME"] = str(root)
            os.environ["GITHUB_PATH"] = str(Path(scratch, "path"))
            os.environ["GITHUB_ENV"] = str(Path(scratch, "env"))
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    installer.main([f"planted;{name}" for name in directories])
                error = ""
            except installer.InstallError as raised:
                error = str(raised)
            except Exception as raised:  # noqa: BLE001 - a traceback is the failure reported
                error = f"TRACEBACK {type(raised).__name__}: {raised}"
            for name in directories:
                marker = root / "planted" / name / "marker"
                markers[name] = marker.read_text() if marker.is_file() else "missing"
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        server.shutdown()
        server.server_close()
    return error, requested, markers


PLANTED_REVISION = "3.1"


def check_android_sdk_main_against_a_planted_root() -> None:
    """install.py's main keeps only a directory at the pin, and names every bad revision."""
    pinned = PLANTED_REVISION
    directories = {
        "held": f"Pkg.Revision={pinned}.0",
        "other": "Pkg.Revision=3.0",
        "bare": None,
        "rc": f"Pkg.Revision={pinned} rc1",
    }
    downloads = {"held": False, "other": True, "bare": True, "rc": True}
    error, requested, markers = run_android_sdk_main(
        directories,
        {name: pinned for name in directories},
        {name: pinned for name in directories},
    )
    check("install.py main installs a planted SDK root", not error, error)
    for name, line in directories.items():
        state = "no source.properties" if line is None else line
        fetched = f"/{name}.zip" in requested
        if downloads[name]:
            check(
                f"install.py main downloads over a directory with {state}",
                fetched and markers[name] == "downloaded",
                f"requested {requested}, marker {markers[name]!r}",
            )
        else:
            check(
                f"install.py main keeps a directory with {state}, downloading nothing",
                not fetched and markers[name] == "image",
                f"requested {requested}, marker {markers[name]!r}",
            )
    # An archive and a listing whose revision is unreadable each fail the step with an
    # InstallError that names the package and the revision text, not a traceback.
    unreadable = f"{pinned} rc1"
    error, _, _ = run_android_sdk_main(
        {"archive": None}, {"archive": unreadable}, {"archive": pinned}
    )
    check(
        "install.py main refuses an archive whose revision it cannot read, naming it",
        not error.startswith("TRACEBACK") and "planted;archive" in error and unreadable in error,
        f"got {error!r}",
    )
    error, requested, _ = run_android_sdk_main(
        {"listed": f"Pkg.Revision={pinned}"}, {}, {"listed": unreadable}
    )
    check(
        "install.py main refuses a listed revision it cannot read, naming it",
        not error.startswith("TRACEBACK")
        and not requested
        and "planted;listed" in error
        and unreadable in error,
        f"got {error!r}, requested {requested}",
    )


def check_download_bounds() -> None:
    """A whole file, a stalled server, a trickling server, an oversized body and a wrong length."""
    import contextlib
    import hashlib
    import http.server
    import io
    import threading

    downloads = load_verified_download()
    body = os.urandom(300_000)
    digest = hashlib.sha256(body).hexdigest()
    limits = downloads.Limits(stall=0.5, min_rate=1 << 30, deadline_floor=1.0)
    # A planted stall holds its connection for `hold` seconds, far past any bound a case
    # asserts, so a download with no read timeout fails the case on time rather than
    # passing on the connection closing; shutdown releases it.
    hold = 10.0
    release = threading.Event()
    trickled = 40
    mode = {"name": "whole"}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep the planted server out of the log
            pass

        def do_GET(self):  # the name http.server dispatches on
            name = mode["name"]
            length = {"oversize": None, "wrong-length": len(body) + 1}.get(name, len(body))
            try:
                self.send_response(200)
                if length is not None:
                    self.send_header("Content-Length", str(length))
                self.end_headers()
                if name == "stall":
                    release.wait(hold)
                elif name == "trickle":
                    # One byte every stall / 2 seconds: no read ever waits `stall`.
                    for byte in body[:trickled]:
                        if release.wait(limits.stall / 2):
                            return
                        self.wfile.write(bytes([byte]))
                elif name == "oversize":
                    self.wfile.write(body + os.urandom(4 << 20))
                elif name == "wrong-length":
                    self.wfile.write(body + b"\0")
                else:
                    self.wfile.write(body)
            except OSError:  # the client gave up first, which is what most cases want
                pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/planted.zip"
    quiet = functools.partial(contextlib.redirect_stdout, io.StringIO())
    real_fetch = downloads.fetch_once
    real_urlopen = downloads.urllib.request.urlopen
    written: list[int] = []
    # Per read: the bytes accepted before it plus the bytes it asks the connection for.
    reach: list[int] = []

    class CountingResponse:
        def __init__(self, response):
            self.response, self.got = response, 0
            self.headers = response.headers

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return self.response.__exit__(*exc)

        def read1(self, n=-1):
            reach.append(self.got + n)
            chunk = self.response.read1(n)
            self.got += len(chunk)
            return chunk

    def counting_urlopen(*args, **kwargs):
        return CountingResponse(real_urlopen(*args, **kwargs))

    def measuring_fetch(url, destination, *rest):
        # The bytes each attempt left on disk before download_verified removes them.
        try:
            return real_fetch(url, destination, *rest)
        finally:
            written.append(destination.stat().st_size if destination.exists() else 0)

    def attempt(name: str, out: Path, attempts: int = 2) -> tuple[str, float]:
        mode["name"] = name
        written.clear()
        started = time.monotonic()
        downloads.fetch_once = measuring_fetch
        try:
            with quiet():
                downloads.download_verified(
                    f"planted;{name}",
                    url,
                    len(body),
                    digest,
                    out,
                    attempts=attempts,
                    backoff=0,
                    limits=limits,
                )
            error = ""
        except Exception as raised:  # noqa: BLE001 - any escape is the failure reported
            error = f"{type(raised).__name__}: {raised}"
        finally:
            downloads.fetch_once = real_fetch
        return error, time.monotonic() - started

    try:
        with tempfile.TemporaryDirectory() as scratch:
            out = Path(scratch, "out.zip")
            error, _ = attempt("whole", out)
            check(
                "verified_download accepts a whole file over HTTP",
                not error and out.read_bytes() == body,
                f"error {error!r}",
            )
            out.unlink(missing_ok=True)
            error, elapsed = attempt("stall", out)
            bound = 2 * limits.stall + 1.5
            check(
                "verified_download fails a stalled server on the read timeout, within "
                "attempts x stall",
                "planted;stall" in error
                and url in error
                and "timed out" in error
                and elapsed < bound
                and not out.exists(),
                f"error {error!r} after {elapsed:.1f} s, bound {bound:.1f} s",
            )
            error, elapsed = attempt("trickle", out)
            bound = 2 * (limits.deadline_floor + limits.stall) + 1.0
            check(
                "verified_download ends a connection that trickles bytes at its deadline",
                "deadline" in error and elapsed < bound and not out.exists(),
                f"error {error!r} after {elapsed:.1f} s, bound {bound:.1f} s",
            )
            reach.clear()
            downloads.urllib.request.urlopen = counting_urlopen
            try:
                error, _ = attempt("oversize", out)
            finally:
                downloads.urllib.request.urlopen = real_urlopen
            check(
                "verified_download never asks the connection for more than one byte past "
                "the pinned size",
                "runs past" in error and reach and max(reach) == len(body) + 1,
                f"error {error!r}, furthest byte each read asked for {sorted(set(reach))}",
            )
            check(
                "verified_download refuses a body that runs past the pinned size, "
                "writing no byte past it",
                "runs past" in error
                and written
                and max(written) <= len(body)
                and not out.exists(),
                f"error {error!r}, bytes written per attempt {written}",
            )
            error, _ = attempt("wrong-length", out)
            check(
                "verified_download refuses a Content-Length other than the pin before "
                "reading the body",
                "Content-Length" in error and written == [0, 0] and not out.exists(),
                f"error {error!r}, bytes written per attempt {written}",
            )
    finally:
        release.set()
        server.shutdown()
        server.server_close()


def check_toolcache_guard() -> None:
    """guard.py must refuse a version the cache lacks and an install the action added."""
    with tempfile.TemporaryDirectory() as scratch:
        cache = Path(scratch, "cache")
        (cache / "Python/3.12.7").mkdir(parents=True)
        (cache / "Python/3.12.7/x64.complete").write_text("")
        environment = dict(
            os.environ,
            RUNNER_TOOL_CACHE=str(cache),
            RUNNER_ARCH="X64",
            RUNNER_TEMP=scratch,
        )

        def guard(*arguments: str) -> int:
            return subprocess.run(
                [sys.executable, "-I", str(TOOLCACHE_GUARD), *arguments],
                env=environment,
                capture_output=True,
            ).returncode

        check(
            "guard.py admits a version the tool cache holds",
            guard("before", "python", "3.12") == 0,
        )
        check(
            "guard.py refuses a version the tool cache lacks",
            guard("before", "python", "3.12\n3.10") != 0,
        )
        check(
            "guard.py refuses a version that only shares a prefix",
            guard("before", "python", "3.1") != 0,
        )
        check(
            "guard.py passes when the action added nothing",
            guard("after", "python") == 0,
        )
        (cache / "Python/3.13.0").mkdir()
        (cache / "Python/3.13.0/x64.complete").write_text("")
        check(
            "guard.py fails when the setup action added an install",
            guard("after", "python") != 0,
        )


def tree_download_gaps(documents: list[tuple[Path, dict]]) -> list[str]:
    """Every verified-download gap in the tree's workflows, local actions and Dockerfiles."""
    gaps = [
        gap
        for where, steps, job in download_step_lists(documents)
        for gap in unverified_download_gaps(where, steps, job)
        + (job_image_gaps(where, job) + job_uses_gaps(where, job) if job else [])
    ]
    texts = [(path.name, path.read_text()) for path, _ in documents]
    texts += [
        (str(action.relative_to(REPO)), action.read_text())
        for action in sorted((REPO / ".github/actions").glob("*/action.y*ml"))
    ]
    for where, text in texts:
        gaps += uses_comment_gaps(where, text)
    for dockerfile in tracked_dockerfiles():
        gaps += dockerfile_gaps(str(dockerfile.relative_to(REPO)), dockerfile.read_text())
    return gaps


def check_verified_downloads(documents: list[tuple[Path, dict]]) -> None:
    gaps = tree_download_gaps(documents)
    check(
        "every workflow, local action and Dockerfile fetches only through a pinned path",
        not gaps,
        "; ".join(gaps),
    )
    check(
        "the tree's Dockerfiles are read",
        any(path.name == "Dockerfile" for path in tracked_dockerfiles()),
        f"git ls-files found {tracked_dockerfiles()}",
    )
    gradle, runs = gradle_gaps(documents)
    check(
        "every gradlew run validates the wrapper jar, pins the distribution digest, and "
        "verifies dependencies",
        runs > 0 and not gradle,
        "; ".join(gradle) or "no gradlew run found",
    )
    # Planted cases, each of which must be reported, and controls that must not be.
    sha = "0123456789abcdef" * 2 + "01234567"
    digest = "@sha256:" + "0" * 64
    bindgen = locked_version("wasm-bindgen")
    taiki = f"taiki-e/install-action@{sha}"
    wasm_opt = {"uses": PINNED_TOOL_ACTION, "with": {"tool": "wasm-opt"}}
    bundle = {"id": "bundle", "uses": PINNED_TOOL_ACTION, "with": {"tool": "codeql-rust"}}
    image_job = {
        "strategy": {"matrix": {"include": [
            {"image": "quay.io/pypa/manylinux_2_28_x86_64" + digest},
            {"image": "quay.io/pypa/manylinux_2_28_aarch64:latest"},
        ]}},
    }
    url = "https://example.invalid/a.zip"
    planted = {
        # The security review's cases.
        "curl then sha256sum without -c": [
            {"run": f"curl -fsSLo a.zip {url} && sha256sum a.zip && unzip a.zip"}
        ],
        "curl then a digest of another file": [
            {"run": f"curl -fsSLo a.zip {url}\nsha256sum README.md\nunzip a.zip"}
        ],
        "curl with sha256sum -c": [
            {"run": f'curl -fsSLo a.zip {url}\necho "$SUM  a.zip" | sha256sum -c -'}
        ],
        "curl inside bash -c": [{"run": f"bash -c 'curl -fsSLo a.zip {url}' && unzip a.zip"}],
        "curl through a variable": [{"run": f"fetch=curl; $fetch -o a.zip {url}"}],
        "wget in a substitution": [
            {"run": 'out="$(wget -qO- https://example.invalid/a.tgz | tar xz)"'}
        ],
        "a python urlretrieve": [
            {"run": f"python3 -c \"import urllib.request as u; u.urlretrieve('{url}','a.zip')\""}
        ],
        "a urllib fetch in a python step": [
            {"shell": "python", "run": f"from urllib.request import urlopen\nurlopen('{url}')"}
        ],
        "gh release download": [{"run": "gh release download v1 -p '*.zip'"}],
        "gh run download": [{"run": "gh run download 1 -n wheels"}],
        "Invoke-WebRequest": [
            {"shell": "pwsh", "run": f"Invoke-WebRequest -Uri {url} -OutFile a.zip"}
        ],
        "iwr": [{"shell": "pwsh", "run": f"iwr {url} -OutFile a.zip"}],
        "pip install maturin": [{"run": "pip install maturin"}],
        "python -m pip install of a pinned version": [
            {"run": "python3 -m pip install maturin==1.16.0"}
        ],
        "pip install -r without hashes": [{"run": "pip3 install -r requirements.txt"}],
        "pip download": [{"run": "pip download -d wheels cffi"}],
        "a fetch in a step env value": [
            {"env": {"SCRIPT": f"curl -o a.zip {url}"}, "run": 'bash -c "$SCRIPT"'}
        ],
        "a fetch in a github-script": [
            {"uses": f"actions/github-script@{sha}",
             "with": {"script": f"await fetch('{url}')"}}
        ],
        "mixed-case setup-python": [{"uses": f"Actions/Setup-Python@{sha}"}],
        "mixed-case setup-bun": [{"uses": f"Oven-sh/setup-bun@{sha}"}],
        "setup-bun": [{"uses": f"oven-sh/setup-bun@{sha}"}],
        "setup-android": [{"uses": f"android-actions/setup-android@{sha}"}],
        "android-emulator-runner": [{"uses": f"reactivecircus/android-emulator-runner@{sha}"}],
        "setup-nasm": [{"uses": f"ilammy/setup-nasm@{sha}"}],
        "maturin-action": [{"uses": f"PyO3/maturin-action@{sha}"}],
        "pypi-publish": [{"uses": f"pypa/gh-action-pypi-publish@{sha}"}],
        "an action by tag": [{"uses": "actions/checkout@v5"}],
        "an action by branch": [{"uses": "dtolnay/rust-toolchain@master"}],
        "an action by a short SHA": [{"uses": "actions/checkout@0123456"}],
        "an action with no ref": [{"uses": "actions/checkout"}],
        "setup-python in a workflow": [{"uses": f"actions/setup-python@{sha}"}],
        "setup-node in a workflow": [{"uses": f"actions/setup-node@{sha}"}],
        "setup-java in a workflow": [{"uses": f"actions/setup-java@{sha}"}],
        "docker run with a digest label and a tagged image": [
            {"run": f"docker run --label x=a{digest} alpine:latest sh"}
        ],
        "docker run with a digest env value and a tagged image": [
            {"run": f"docker run -e IMG=a{digest} alpine:latest sh"}
        ],
        "docker run by tag": [
            {"run": "docker run --rm quay.io/pypa/manylinux_2_28_x86_64:latest true"}
        ],
        "docker run with an option the tables lack": [
            {"run": f"docker run --gpus all alpine{digest} sh"}
        ],
        "docker pull of an unset variable": [{"run": 'docker pull "$IMAGE"'}],
        "docker image pull by tag": [{"run": "docker image pull alpine:3"}],
        "docker build": [{"run": "docker build -t x ."}],
        "docker buildx": [{"run": "docker buildx build ."}],
        "docker inside bash -c": [{"run": f"bash -c 'docker run alpine{digest} true'"}],
        "podman": [{"run": "podman run alpine:3 true"}],
        "skopeo": [{"run": "skopeo copy docker://alpine:3 dir:a"}],
        "a docker:// step by tag": [{"uses": "docker://alpine:3"}],
        "sdkmanager": [{"run": 'sdkmanager "ndk;27.2.12479018"'}],
        "sdkmanager --install": [{"run": "yes | sdkmanager --install emulator --channel=0"}],
        "bun install without --frozen-lockfile": [{"run": "bun install"}],
        "bunx": [{"run": "bunx typedoc"}],
        "bun add": [{"run": "bun add left-pad"}],
        "npx": [{"run": "npx typedoc"}],
        "cargo install from the registry": [{"run": "cargo install --locked cargo-fuzz"}],
        "cargo install --path without --locked": [{"run": 'cargo install --path "$CRATE"'}],
        "cargo +toolchain install from the registry": [
            {"run": "cargo +nightly install cargo-fuzz"}
        ],
        "uv pip": [{"run": "uv pip install maturin"}],
        "hashed pip of a file missing from the step's directory": [
            {"working-directory": "bindings/python",
             "run": "pip install --require-hashes -r .github/requirements/ruff.txt"}
        ],
        "hashed pip of a file that does not exist": [
            {"run": "pip install --require-hashes --requirement=.github/requirements/absent.txt"}
        ],
        "unpinned docker run after `$(…); do`": [
            {"run": "for _ in $(seq 3); do docker run alpine:latest true && break; done"}
        ],
        "curl of a loopback and an outside URL": [
            {"run": "curl -sf http://127.0.0.1:9090/a https://example.invalid/b"}
        ],
        "curl of a loopback-looking host": [
            {"run": "curl -sf http://127.0.0.1.example.invalid/a"}
        ],
        "curl of a computed URL": [{"run": 'curl -sf "http://127.0.0.1:$PORT/a"'}],
        "curl with a URL-less config": [{"run": "curl -K /tmp/urls"}],
        "loopback-looking curl whose userinfo hides an outside host": [
            {"run": "curl -o a.zip http://localhost:80@evil.example/a.zip"}
        ],
        "127.0.0.1 curl whose userinfo hides an outside host": [
            {"run": "curl -o a.zip http://127.0.0.1:1@evil.example/a.zip"}
        ],
        "loopback curl resolved to an outside address": [
            {"run": "curl --resolve localhost:80:203.0.113.5 -o a.zip http://localhost/a.zip"}
        ],
        "loopback curl through an outside proxy": [
            {"run": "curl -x evil.example:8080 -o a.zip http://localhost/a.zip"}
        ],
        "loopback curl with a config file": [{"run": "curl -K urls.txt http://127.0.0.1/"}],
        "loopback curl that keeps the body": [
            {"run": "curl -sf -o probe.out http://127.0.0.1:9090/scp-test"}
        ],
        "wget of a loopback probe URL": [{"run": "wget -q http://127.0.0.1:9090/scp-test"}],
        "loopback curl chained to an outside curl": [
            {"run": "curl -sf http://127.0.0.1:9090/a && curl -sf https://example.invalid/b"}
        ],
        "hashed pip of a computed path": [
            {"run": 'pip install --require-hashes -r "$REQS"'}
        ],
        "git clone": [{"run": "git clone https://example.invalid/a.git"}],
        "taiki-e without fallback none": [{"uses": taiki, "with": {"tool": "cargo-nextest"}}],
        "taiki-e with the checksum off": [
            {"uses": taiki, "with": {"tool": "x", "fallback": "none", "checksum": "false"}}
        ],
        "wasm-pack without wasm-bindgen": [
            {"uses": taiki, "with": {"tool": "wasm-pack@0.14.0", "fallback": "none"}},
            wasm_opt,
        ],
        "wasm-pack with another wasm-bindgen": [
            {"uses": taiki,
             "with": {"tool": "wasm-pack@0.14.0,wasm-bindgen@0.0.1", "fallback": "none"}},
            wasm_opt,
        ],
        "wasm-pack without wasm-opt": [
            {"uses": taiki,
             "with": {"tool": f"wasm-pack@0.14.0,wasm-bindgen@{bindgen}", "fallback": "none"}}
        ],
        "setup-buildx with a tagged buildkit": [
            {"uses": f"docker/setup-buildx-action@{sha}",
             "with": {"driver-opts": "image=moby/buildkit:buildx-stable-1"}}
        ],
        "setup-buildx with no driver image": [{"uses": f"docker/setup-buildx-action@{sha}"}],
        "setup-buildx with a version": [
            {"uses": f"docker/setup-buildx-action@{sha}",
             "with": {"driver-opts": f"image=moby/buildkit{digest}", "version": "latest"}}
        ],
        "codeql init without tools": [{"uses": f"github/codeql-action/init@{sha}"}],
        "codeql init with a version as tools": [
            {"uses": f"github/codeql-action/init@{sha}", "with": {"tools": "linked"}}
        ],
        "codeql init with tools from a later step": [
            {"uses": f"github/codeql-action/init@{sha}",
             "with": {"tools": "${{ steps.bundle.outputs.path }}"}},
            bundle,
        ],
        "setup-gradle with a gradle-version": [
            {"uses": f"gradle/actions/setup-gradle@{sha}", "with": {"gradle-version": "8.14"}}
        ],
        "a local action that is not composite": [{"uses": "./.github/actions/lib"}],
        "cache restored into the NDK before android-sdk": [
            {"uses": f"actions/cache@{sha}",
             "with": {"path": "/usr/local/lib/android/sdk/ndk", "key": "ndk"}},
            {"uses": ANDROID_SDK_ACTION, "with": {"packages": "ndk;27.3.13750724"}},
        ],
        "cache/restore into ANDROID_HOME before android-sdk": [
            {"uses": f"actions/cache/restore@{sha}",
             "with": {"path": "${{ env.ANDROID_HOME }}/emulator", "key": "emulator"}},
            {"uses": ANDROID_SDK_ACTION, "with": {"packages": "emulator"}},
        ],
        "download-artifact into the SDK root before android-sdk": [
            {"uses": f"actions/download-artifact@{sha}",
             "with": {"name": "sdk", "path": "/usr/local/lib/android/sdk"}},
            {"uses": ANDROID_SDK_ACTION, "with": {"packages": "ndk;27.3.13750724"}},
        ],
        "a run that writes under ANDROID_NDK_HOME before android-sdk": [
            {"run": 'tar -xf ndk.tar -C "$ANDROID_NDK_HOME"'},
            {"uses": ANDROID_SDK_ACTION, "with": {"packages": "ndk;27.3.13750724"}},
        ],
        "an env that moves ANDROID_HOME on android-sdk": [
            {"uses": ANDROID_SDK_ACTION, "with": {"packages": "emulator"},
             "env": {"ANDROID_HOME": "/tmp/sdk"}},
        ],
    }
    real_local_action_steps = local_action_steps
    globals()["local_action_steps"] = lambda uses: (
        [{"run": 'cp -r ndk "$ANDROID_HOME/ndk/27.3.13750724"'}]
        if uses == "./planted-action"
        else real_local_action_steps(uses)
    )
    try:
        nested = unverified_download_gaps(
            "planted",
            [
                {"uses": "./planted-action"},
                {"uses": ANDROID_SDK_ACTION, "with": {"packages": "ndk;27.3.13750724"}},
            ],
        )
    finally:
        globals()["local_action_steps"] = real_local_action_steps
    check(
        "verified-download reports a local action before android-sdk that writes under "
        "the SDK root",
        any("planted-action step 0" in gap for gap in nested),
        f"returned {nested}",
    )
    check(
        "verified-download reports a job env that moves ANDROID_HOME under android-sdk",
        bool(
            unverified_download_gaps(
                "planted",
                [{"uses": ANDROID_SDK_ACTION, "with": {"packages": "emulator"}}],
                {"env": {"ANDROID_HOME": "/tmp/sdk"}},
            )
        ),
    )
    between = unverified_download_gaps(
        "planted",
        [
            {"uses": ANDROID_SDK_ACTION, "with": {"packages": "platforms;android-35"}},
            {"uses": f"actions/cache/restore@{'0' * 40}",
             "with": {"path": "/usr/local/lib/android/sdk/ndk", "key": "ndk"}},
            {"uses": ANDROID_SDK_ACTION, "with": {"packages": "ndk;27.3.13750724"}},
        ],
    )
    check(
        "verified-download reports a cache restored into the NDK between two android-sdk "
        "uses",
        any("planted step 1" in gap and "writes to `path:`" in gap for gap in between),
        f"returned {between}",
    )
    workflow = [
        (
            Path("planted.yml"),
            {
                "env": {"ANDROID_HOME": "/tmp/sdk"},
                "jobs": {
                    "sdk": {
                        "steps": [
                            {"uses": ANDROID_SDK_ACTION, "with": {"packages": "emulator"}}
                        ]
                    }
                },
            },
        )
    ]
    moved = [
        gap
        for where, steps, job in download_step_lists(workflow)
        if where == "planted.yml:sdk"
        for gap in unverified_download_gaps(where, steps, job)
    ]
    check(
        "verified-download reports a workflow env that moves ANDROID_HOME under "
        "android-sdk",
        any("sets ANDROID_HOME in the workflow's or job's `env:`" in gap for gap in moved),
        f"returned {moved}",
    )
    through_env = unverified_download_gaps(
        "planted",
        [
            {"env": {"DEST": "/usr/local/lib/android/sdk/ndk"}, "run": 'cp -r ndk "$DEST"'},
            {"uses": ANDROID_SDK_ACTION, "with": {"packages": "ndk;27.3.13750724"}},
        ],
    )
    check(
        "verified-download reports an earlier step whose `env:` points a copy into the "
        "SDK root",
        any("sets `env:` DEST=" in gap for gap in through_env),
        f"returned {through_env}",
    )
    after = [
        {"uses": ANDROID_SDK_ACTION, "with": {"packages": "emulator"}},
        {"run": 'echo "$ANDROID_HOME/emulator" >> "$GITHUB_PATH"'},
    ]
    check(
        "verified-download accepts a step after android-sdk that names ANDROID_HOME",
        not unverified_download_gaps("control", after),
        f"returned {unverified_download_gaps('control', after)}",
    )
    for name, steps in planted.items():
        check(
            f"verified-download reports a planted {name} step",
            bool(unverified_download_gaps("planted", steps)),
            f"{steps} went unreported",
        )
    hashed = {"run": "pip install --require-hashes -r .github/requirements/ruff.txt"}
    in_bindings = {"defaults": {"run": {"working-directory": "bindings/python"}}}
    check(
        "verified-download reports a hashed pip whose file is missing from the job's "
        "default working directory",
        bool(run_gaps("planted", hashed, in_bindings)),
        f"{hashed} under {in_bindings} went unreported",
    )
    check(
        "verified-download accepts the same hashed pip from the repository root",
        not run_gaps("control", hashed, {}),
        f"returned {run_gaps('control', hashed, {})}",
    )
    guarded = [
        {"run": '"$py" -I "$GITHUB_ACTION_PATH/guard.py" before "$T" "$V"'},
        {"uses": f"actions/setup-python@{sha}"},
        {"run": '"$py" -I "$GITHUB_ACTION_PATH/guard.py" after "$T"'},
    ]
    check(
        "verified-download reports setup-python outside toolcache-setup, guarded or not",
        bool(unverified_download_gaps("planted", guarded)),
        f"{guarded} went unreported",
    )
    check(
        "verified-download reports setup-python in toolcache-setup without its after step",
        bool(unverified_download_gaps(TOOLCACHE_ACTION_FILE, guarded[:2])),
        f"{guarded[:2]} went unreported",
    )
    controls = {
        "the android-sdk action": [{"uses": ANDROID_SDK_ACTION, "with": {"packages": "emulator"}}],
        "the pinned-tool action": [{"uses": PINNED_TOOL_ACTION, "with": {"tool": "bun"}}],
        "checkout at a commit SHA": [{"uses": f"actions/checkout@{sha}"}],
        "pip with --require-hashes": [
            {"run": "python3 -m pip install --require-hashes -r .github/requirements/ruff.txt"}
        ],
        "bun install --frozen-lockfile": [{"run": "bun install --frozen-lockfile"}],
        "a loopback health probe": [
            {"run": "for _ in $(seq 60); do curl -sf -o /dev/null "
                    "http://127.0.0.1:9090/scp-test && break; sleep 1; done"}
        ],
        "a bare loopback health probe": [
            {"run": "curl -sf -o /dev/null http://127.0.0.1:9090/scp-test"}
        ],
        "docker exec into a running container": [
            {"run": "docker exec scp-ci-postgres pg_isready -U postgres"}
        ],
        "cargo install of a checked source": [
            {"run": 'cargo +nightly install --locked --path "$CRATE"'}
        ],
        "taiki-e with fallback none": [
            {"uses": taiki, "with": {"tool": "cargo-nextest", "fallback": "none"}}
        ],
        "wasm-pack with the locked wasm-bindgen and wasm-opt": [
            {"uses": taiki,
             "with": {"tool": f"wasm-pack@0.14.0,wasm-bindgen@{bindgen}", "fallback": "none"}},
            wasm_opt,
        ],
        "setup-buildx with a buildkit named by digest": [
            {"uses": f"docker/setup-buildx-action@{sha}",
             "with": {"driver-opts": f"image=moby/buildkit:buildx-stable-1{digest}\n"}}
        ],
        "codeql init with an earlier bundle": [
            bundle,
            {"uses": f"github/codeql-action/init@{sha}",
             "with": {"tools": "${{ steps.bundle.outputs.path }}"}},
        ],
        "docker run of an image named by digest": [
            {"run": f"docker run --rm -v a:/b -e X --env-file e "
                    f"quay.io/pypa/manylinux_2_28_x86_64{digest} true"}
        ],
        "docker inspect, which pulls nothing": [{"run": "docker inspect alpine:3"}],
        "a docker:// step named by digest": [{"uses": f"docker://alpine{digest}"}],
        "a word that merely contains a fetch word": [
            {"run": "echo curly braces; ./scripts/iwrite.sh; cranelift --help"}
        ],
    }
    for name, steps in controls.items():
        check(
            f"verified-download does not report {name}",
            not unverified_download_gaps("control", steps),
            f"{unverified_download_gaps('control', steps)}",
        )
    pinned_pull = {"env": {"IMAGE": "${{ matrix.image }}"}, "run": 'docker pull "$IMAGE"'}
    check(
        "verified-download reports docker pull of a matrix image when one matrix value "
        "has no digest",
        bool(unverified_download_gaps("planted", [pinned_pull], image_job)),
        f"{pinned_pull} with {image_job} went unreported",
    )
    every_pinned = copy.deepcopy(image_job)
    every_pinned["strategy"]["matrix"]["include"][1]["image"] = "alpine" + digest
    check(
        "verified-download does not report docker pull of a matrix image whose every "
        "value has a digest",
        not unverified_download_gaps("control", [pinned_pull], every_pinned),
        f"{unverified_download_gaps('control', [pinned_pull], every_pinned)}",
    )
    for name, job in {
        "a job container by tag": {"container": "node:22"},
        "a job container mapping by tag": {"container": {"image": "node:22"}},
        "a service by tag": {"services": {"db": {"image": "postgres:17"}}},
        "a matrix container with one unpinned value": {
            **image_job,
            "container": "${{ matrix.image }}",
        },
    }.items():
        check(
            f"verified-download reports {name}",
            bool(job_image_gaps("planted", job)),
            f"{job} went unreported",
        )
    pinned_job = {
        "container": {"image": "node" + digest},
        "services": {"db": {"image": "postgres" + digest}},
    }
    check(
        "verified-download does not report job and service images named by digest",
        not job_image_gaps("control", pinned_job),
        f"{job_image_gaps('control', pinned_job)}",
    )
    check(
        "verified-download reports a job calling a remote reusable workflow",
        bool(job_uses_gaps("planted", {"uses": f"octo/ci/.github/workflows/x.yml@{sha}"})),
    )
    check(
        "verified-download does not report a job calling a local reusable workflow",
        not job_uses_gaps("control", {"uses": "./.github/workflows/build-matrix.yml"}),
    )
    check(
        "verified-download reports a remote uses: line with no tag comment",
        bool(uses_comment_gaps("planted", f"      - uses: actions/checkout@{sha}\n")),
    )
    check(
        "verified-download does not report a remote uses: line with its tag comment",
        not uses_comment_gaps("control", f"      - uses: actions/checkout@{sha} # v5.1.0\n"),
    )
    check(
        "verified-download does not report setup-python between guard.py's steps in "
        "toolcache-setup",
        not unverified_download_gaps(TOOLCACHE_ACTION_FILE, guarded),
        f"{unverified_download_gaps(TOOLCACHE_ACTION_FILE, guarded)}",
    )
    planted_dockerfiles = {
        "a FROM by tag": "FROM rust:slim-bookworm\n",
        "a FROM by tag with a platform": "FROM --platform=$BUILDPLATFORM debian:12 AS base\n",
        "a FROM of an expansion with a missing stage": (
            f"FROM alpine{digest} AS deps-amd64\nFROM deps-${{TARGETARCH}}\n"
        ),
        "a COPY --from an external image by tag": (
            f"FROM alpine{digest}\nCOPY --from=busybox:1 /bin/sh /sh\n"
        ),
        "an ADD of a URL with no checksum": f"FROM alpine{digest}\nADD {url} /a.zip\n",
        "a syntax directive by tag": f"# syntax=docker/dockerfile:1\nFROM alpine{digest}\n",
        "a RUN that fetches with curl": (
            f"FROM alpine{digest}\nRUN apk add x && \\\n    curl -o a {url}\n"
        ),
        "a RUN pip install without hashes": f"FROM python{digest}\nRUN pip install x\n",
    }
    for name, text in planted_dockerfiles.items():
        check(
            f"verified-download reports a planted Dockerfile with {name}",
            bool(dockerfile_gaps("planted", text)),
            f"{text!r} went unreported",
        )
    control_dockerfile = (
        f"# syntax=docker/dockerfile:1{digest}\n"
        f"FROM rust:slim{digest} AS build\n"
        f"FROM build AS deps-amd64\nFROM build AS deps-arm64\n"
        "FROM deps-${TARGETARCH} AS deps\n"
        f"ADD --checksum=sha256:{'0' * 64} {url} /a.zip\n"
        "COPY --from=build /a /a\nFROM scratch\n"
        "RUN apt-get install -y curl-dev\n"
    )
    check(
        "verified-download does not report a Dockerfile whose every image has a digest",
        not dockerfile_gaps("control", control_dockerfile),
        f"{dockerfile_gaps('control', control_dockerfile)}",
    )
    gradle_job = {
        "defaults": {"run": {"working-directory": "bindings/kotlin"}},
        "steps": [{"uses": f"actions/checkout@{sha}"}, {"run": "./gradlew :scp-kt:jar"}],
    }
    check(
        "verified-download reports a planted gradlew job with no wrapper validation",
        bool(wrapper_validation_gaps("planted", gradle_job)),
    )
    disabled = copy.deepcopy(gradle_job)
    disabled["steps"].insert(
        1,
        {"uses": f"gradle/actions/setup-gradle@{sha}", "with": {"validate-wrappers": False}},
    )
    check(
        "verified-download reports a planted gradlew job whose setup-gradle skips "
        "wrapper validation",
        bool(wrapper_validation_gaps("planted", disabled)),
    )
    validated = copy.deepcopy(gradle_job)
    validated["steps"].insert(1, {"uses": f"Gradle/Actions/Wrapper-Validation@{sha}"})
    check(
        "verified-download does not report a gradlew job after wrapper-validation, "
        "named in any case",
        not wrapper_validation_gaps("control", validated),
    )
    check(
        "gradle_runs reads the build a `-p` names relative to the working directory",
        gradle_runs({}, {"run": "bindings/kotlin/gradlew -p some/runner \\\n  build"})
        == [GradleRun("bindings/kotlin", "some/runner")],
        f"{gradle_runs({}, {'run': 'bindings/kotlin/gradlew -p some/runner build'})}",
    )
    check(
        "verified-download reports planted wrapper properties without "
        "distributionSha256Sum",
        bool(
            wrapper_properties_gaps(
                "planted",
                "distributionUrl=https\\://services.gradle.org/distributions/"
                "gradle-8.14.4-bin.zip\n",
            )
        ),
    )
    metadata = (
        '<verification-metadata xmlns="https://schema.gradle.org/dependency-'
        'verification"><configuration><verify-metadata>{}</verify-metadata>'
        "<trusted-artifacts>{}</trusted-artifacts></configuration><components>"
        '<component group="g" name="n" version="1"><artifact name="n-1.jar">'
        '<sha256 value="{}" origin="Generated by Gradle"/></artifact></component>'
        "</components></verification-metadata>"
    )
    planted_metadata = {
        "missing": None,
        "with verify-metadata off": metadata.format("false", "", "0" * 64),
        "trusting every group": metadata.format(
            "true", '<trust group=".*" regex="true"/>', "0" * 64
        ),
        "trusting every file": metadata.format(
            "true", '<trust file=".*" regex="true"/>', "0" * 64
        ),
        "trusting every jar": metadata.format(
            "true", '<trust file=".*[.]jar" regex="true"/>', "0" * 64
        ),
        "trusting one sources jar": metadata.format(
            "true", '<trust file=".*-sources[.]jar" regex="true"/>', "0" * 64
        ),
    }
    for name, text in planted_metadata.items():
        check(
            f"verified-download reports planted verification metadata {name}",
            bool(verification_metadata_gaps("planted", text)),
        )
    verifying = metadata.format("true", "", "0" * 64)
    check(
        "verified-download does not report verification metadata that verifies",
        not verification_metadata_gaps("control", verifying),
        f"{verification_metadata_gaps('control', verifying)}",
    )
    check_installer_rejects_a_corrupt_archive()
    check_android_sdk_keeps_only_the_pinned_revision()
    check_download_bounds()
    check_toolcache_guard()


def run_verified_download(inputs: Inputs) -> None:
    print(
        "verified-download — every archive a CI step downloads is checked before it is "
        "unpacked"
    )
    check_verified_downloads(inputs.documents)


def run_timeout(inputs: Inputs) -> None:
    documents = inputs.documents
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


def run_action_ref(inputs: Inputs) -> None:
    documents = inputs.documents
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


def run_doc_flag(inputs: Inputs) -> None:
    documents = inputs.documents
    print("doc-flag — the required check's rustdoc reads every other rustdoc's surface")
    check_required_rustdoc_surface(documents)
    check_rustdoc_surface_detects_a_dropped_flag(documents)


def run_doc_command(inputs: Inputs) -> None:
    documents = inputs.documents
    print("doc-command — a documented rustdoc reports what the merge waits on")
    check_documented_rustdoc_reproduces_the_required_job(documents)
    check_documented_rustdoc_detects_a_feature_drift(documents)
    check_rustdoc_enumerations_sit_in_a_shell_block()
    check_enumeration_scan_reads_the_text_it_is_given()


def run_win_shell(inputs: Inputs) -> None:
    documents = inputs.documents
    print("win-shell — every `run:` step a Windows runner can execute names a shell")
    for path, doc in documents:
        check_windows_shell(path, doc)


def run_matrix_axis(inputs: Inputs) -> None:
    workflow = inputs.workflow
    documents = inputs.documents
    print(
        "matrix-axis — each matrix axis a step gates on and its steps' `if:` "
        "values agree"
    )
    for path, doc in documents:
        check_matrix_axes(path, doc)
    check_matrix_axis_controls(workflow)


def run_leg_commands(inputs: Inputs) -> None:
    print("leg-commands — each split job's legs run its pinned commands exactly once")
    check_leg_commands(inputs.workflow)


# Crates whose off-by-default features gate code that only a clippy command
# naming the feature compiles.
LINTED_FEATURE_CRATES = ("scp-transport", "scp-node")
# Features whose code compiles only for one target (webtransport/mod.rs gates
# the client on `target_arch = "wasm32"`): only a clippy command passing
# `--target` with that target lints them.
TARGET_GATED_FEATURES = {("scp-transport", "webtransport-wasm"): "wasm32-unknown-unknown"}
# Target-gated features no build compiles: scp-transport's unconditional
# tokio-tungstenite dependency pulls mio, which fails to compile for
# wasm32-unknown-unknown. The check fails once a command lints one, so the
# entry goes when the build is fixed.
UNBUILDABLE_FEATURES = (("scp-transport", "webtransport-wasm"),)


class GatedTarget(NamedTuple):
    """A `[[bin]]` or `[[test]]` target Cargo builds only when its `required-features` are on."""

    kind: str  # "bin" or "test"
    name: str
    required: frozenset[str]


def gated_targets(manifest: dict) -> tuple[GatedTarget, ...]:
    """Return each `[[bin]]` and `[[test]]` of `manifest` that declares `required-features`."""
    return tuple(
        GatedTarget(kind, entry["name"], frozenset(entry["required-features"]))
        for kind in ("bin", "test")
        for entry in manifest.get(kind) or []
        if entry.get("required-features")
    )


def clippy_builds(tokens: list[str], target: GatedTarget) -> bool:
    """Return whether the cargo command in `tokens` selects `target` (its features aside).

    With no target-selection flag Cargo checks the library and every binary.
    `--tests` and `--benches` select binaries too, because binaries are test and
    bench targets by default; `--lib`, `--examples`, and `--example` select neither
    kind.
    """
    def named(flag: str) -> set[str]:
        values = {b for a, b in itertools.pairwise(tokens) if a == flag}
        return values | {t.removeprefix(f"{flag}=") for t in tokens if t.startswith(f"{flag}=")}

    selection = {"--lib", "--bins", "--tests", "--benches", "--examples", "--all-targets"}
    singular = ("--bin", "--test", "--bench", "--example")
    if not selection.intersection(tokens) and not any(named(flag) for flag in singular):
        return target.kind == "bin"
    if "--all-targets" in tokens or "--tests" in tokens:
        return True
    if target.kind == "bin":
        return "--bins" in tokens or "--benches" in tokens or target.name in named("--bin")
    return target.name in named("--test")


def unlinted_features(
    doc: dict,
    package: str,
    features: dict[str, list[str]],
    targets: dict[str, str] | None = None,
    gated: tuple[GatedTarget, ...] = (),
) -> list[str]:
    """Return each feature of `package` that no `cargo clippy` command enables.

    CRITERION: a feature counts as linted when some `cargo clippy` command in a
    step of `doc` passes `--all-features` with `-p <package>`, names it (or a
    feature of `package` that enables it, per `features`) in `--features` with
    `-p <package>`, or names `<package>/<feature>`; a feature in `targets`
    counts only from a command whose `--target` is its target. A command with
    `-p <package>` and no `--no-default-features` enables `default`, and so
    every feature `default` enables. A feature that a target in `gated` names
    in its `required-features` counts only when, for every such target, some
    command with `-p <package>` both selects that target and enables all of
    its `required-features`, because Cargo compiles the target's code in no
    other build.
    """
    if targets is None:
        targets = {f: t for (p, f), t in TARGET_GATED_FEATURES.items() if p == package}
    linted: set[str] = set()
    covered: set[GatedTarget] = set()
    for job in doc["jobs"].values():
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            for line in logical_lines(step.get("run") or ""):
                tokens = line.split()
                if tokens[:2] != ["cargo", "clippy"]:
                    continue
                own = package in [b for a, b in itertools.pairwise(tokens) if a == "-p"]
                target = next((b for a, b in itertools.pairwise(tokens) if a == "--target"), None)
                named: set[str] = set(features) if own and "--all-features" in tokens else set()
                if own and "--no-default-features" not in tokens and "default" in features:
                    named.add("default")
                for flag, value in itertools.pairwise(tokens):
                    if flag != "--features":
                        continue
                    for name in value.split(","):
                        if name.startswith(f"{package}/"):
                            named.add(name.removeprefix(f"{package}/"))
                        elif own and "/" not in name:
                            named.add(name)
                built, pending = set(), [name for name in named if name in features]
                while pending:
                    name = pending.pop()
                    if name not in built:
                        built.add(name)
                        pending.extend(dep for dep in features[name] if dep in features)
                linted.update(name for name in built if targets.get(name, target) == target)
                if own:
                    covered.update(t for t in gated if t.required <= built and clippy_builds(tokens, t))
    linted.difference_update(
        name for name in features if any(name in t.required and t not in covered for t in gated)
    )
    return sorted(name for name in features if name not in linted)


def run_linted_features(inputs: Inputs) -> None:
    print("linted-features — every feature of " + ", ".join(LINTED_FEATURE_CRATES) + " is in a clippy command")
    for package in LINTED_FEATURE_CRATES:
        manifest = tomllib.loads((REPO / "crates" / package / "Cargo.toml").read_text())
        features = manifest["features"]
        missing = unlinted_features(inputs.workflow, package, features, gated=gated_targets(manifest))
        unbuildable = sorted(f for p, f in UNBUILDABLE_FEATURES if p == package)
        for name in unbuildable:
            print(f"  NOT LINTED: {package} feature {name}: no build compiles its target-gated code")
        check(f"every buildable {package} feature is linted by a clippy command", missing == unbuildable, f"{missing}")
    features = tomllib.loads((REPO / "crates/scp-transport/Cargo.toml").read_text())["features"]
    check("the scp-transport manifest names upnp", "upnp" in features, f"{sorted(features)}")
    mutant = copy.deepcopy(inputs.workflow)
    for job in mutant["jobs"].values():
        for step in job.get("steps") or []:
            if isinstance(step, dict) and step.get("run"):
                step["run"] = step["run"].replace("upnp", "")
    missing = unlinted_features(mutant, "scp-transport", features)
    check("a workflow that lints no upnp build is reported", missing == ["upnp", "webtransport-wasm"], f"{missing}")

    def synthetic(command: str) -> dict:
        return {"jobs": {"j": {"steps": [{"run": command}]}}}

    missing = unlinted_features(synthetic("cargo clippy -p scp-transport --all-features"), "scp-transport", features)
    check(
        "host-target --all-features lints every scp-transport feature but webtransport-wasm",
        missing == ["webtransport-wasm"],
        f"{missing}",
    )
    toy = {"a": ["b"], "b": [], "c": []}
    missing = unlinted_features(synthetic("cargo clippy -p x --features a"), "x", toy)
    check("a feature another named feature enables counts as linted", missing == ["c"], f"{missing}")
    missing = unlinted_features(synthetic("cargo clippy -p y --features a,c"), "x", toy)
    check("another package's feature of the same name is not counted", missing == ["a", "b", "c"], f"{missing}")
    missing = unlinted_features(synthetic("cargo clippy -p y --features x/c"), "x", toy)
    check("a <package>/<feature> name counts for that package", missing == ["a", "b"], f"{missing}")
    missing = unlinted_features(synthetic("cargo test -p x --features a,c"), "x", toy)
    check("a command other than cargo clippy is not counted", missing == ["a", "b", "c"], f"{missing}")
    defaulted = {"default": ["a"], "a": [], "c": []}
    missing = unlinted_features(synthetic("cargo clippy -p x --features c"), "x", defaulted)
    check("a command keeping default features lints `default` and what it enables", missing == [], f"{missing}")
    missing = unlinted_features(synthetic("cargo clippy -p x --no-default-features --features c"), "x", defaulted)
    check("a --no-default-features command does not lint `default`", missing == ["a", "default"], f"{missing}")
    wasm = {"a": "wasm32-unknown-unknown"}
    missing = unlinted_features(synthetic("cargo clippy -p x --features a"), "x", toy, wasm)
    check("a host-target command does not lint a wasm32-gated feature", missing == ["a", "c"], f"{missing}")
    command = "cargo clippy -p x --features a --target wasm32-unknown-unknown"
    missing = unlinted_features(synthetic(command), "x", toy, wasm)
    check("a wasm32-target command lints a wasm32-gated feature", missing == ["c"], f"{missing}")

    node = tomllib.loads((REPO / "crates/scp-node/Cargo.toml").read_text())
    node_gated = gated_targets(node)
    check(
        "the scp-node manifest gates its binary and both binary-spawning tests on node-bin",
        sorted((t.kind, t.name) for t in node_gated if "node-bin" in t.required)
        == [("bin", "scp-node"), ("test", "run_mode_selection"), ("test", "storage_backend_selection")],
        f"{node_gated}",
    )
    for command, linted in (
        ("cargo clippy -p scp-node --lib -- -D warnings", False),
        ("cargo clippy -p scp-node -- -D warnings", False),
        ("cargo clippy -p scp-node --bin scp-node --test run_mode_selection -- -D warnings", False),
        ("cargo clippy -p scp-node --no-default-features --all-targets -- -D warnings", False),
        ("cargo clippy -p scp-relay --features scp-node/node-bin --all-targets -- -D warnings", False),
        ("cargo clippy -p scp-node --all-targets -- -D warnings", True),
        ("cargo clippy -p scp-node --tests -- -D warnings", True),
        (
            (
                "cargo clippy -p scp-node --bin scp-node --test run_mode_selection "
                "--test storage_backend_selection -- -D warnings"
            ),
            True,
        ),
    ):
        missing = unlinted_features(synthetic(command), "scp-node", node["features"], gated=node_gated)
        verdict = "lints" if linted else "does not lint"
        check(f"{command!r} {verdict} node-bin", ("node-bin" not in missing) == linted, f"{missing}")
    steps = [
        {"run": "cargo clippy -p scp-node --lib -- -D warnings"},
        {"run": "cargo clippy -p scp-node --tests -- -D warnings"},
    ]
    lane = {"jobs": {"j": {"steps": steps}}}
    missing = unlinted_features(lane, "scp-node", node["features"], gated=node_gated)
    check("a --lib lane plus a --tests lane together lint node-bin", "node-bin" not in missing, f"{missing}")
    two = (GatedTarget("test", "t", frozenset({"a", "c"})),)
    missing = unlinted_features(synthetic("cargo clippy -p x --features a --all-targets"), "x", toy, gated=two)
    check(
        "a target counts only from a command enabling all its required-features",
        missing == ["a", "c"],
        f"{missing}",
    )
    missing = unlinted_features(synthetic("cargo clippy -p x --features a,c --test t"), "x", toy, gated=two)
    check("a target selected with --test and all its features on counts", missing == [], f"{missing}")


def run_empty_input(inputs: Inputs) -> None:
    documents = inputs.documents
    print(
        "empty-input — a job publishing a -signed artifact rejects an empty "
        "input set first"
    )
    check_signing_guard(documents)


def run_downloaded_module(inputs: Inputs) -> None:
    workflow = inputs.workflow
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


def run_downloaded_addon(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print(
        "downloaded-addon — a NAPI consumer's unguarded steps before its tests "
        "contain each NAPI assertion fragment"
    )
    napi_artifacts = uploaded_artifact_names(workflow, NAPI_UPLOAD_FILENAME)
    check_a_bridge_upload_reaches_the_gate(
        workflow, NAPI_UPLOAD_FILENAME, napi_artifacts
    )
    check_napi_consumer_assertion_fragments(workflow, napi_artifacts)
    check_napi_shipped_expectation_controls(
        workflow, napi_artifacts, "rust-test-napi-production"
    )
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


def run_retention(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print("retention — a downloaded artifact outlives the re-run window")
    check_shared_uploads_outlive_the_rerun_window(workflow)


def run_profile_env(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print("profile-env — CARGO_PROFILE_* is set for the whole workflow or not at all")
    check_profile_env_is_workflow_level(workflow, "ci.yml")
    check_profile_env_is_workflow_level(
        yaml.safe_load(COMPILE_TIMINGS.read_text()), "compile-timings.yml"
    )


def run_cache_key(inputs: Inputs) -> None:
    print(
        "cache-key — every cargo-cache key holds the root Cargo.toml and every "
        "artifact-changing variable"
    )
    check_cache_key(inputs.documents)


def run_offline_cargo(inputs: Inputs) -> None:
    print(
        "offline-cargo — every job that runs cargo fetches once, after its toolchain "
        "and cache, then runs offline"
    )
    check_offline_cargo(inputs.documents)


def run_pinned_python(inputs: Inputs) -> None:
    print(
        "pinned-python — every job that compiles pyo3 runs on a pinned Python 3.12 "
        "that PYO3_PYTHON names"
    )
    check_pinned_python(inputs.documents)


def run_artifact_key(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print(
        "artifact-key — a bridge producer reuses an artifact only for unchanged inputs"
    )
    check_artifact_cache_keys(workflow)


def run_artifact_digest(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print(
        "artifact-digest — an artifact-inputs step fails when a hashed input is "
        "missing and hashes the workflow env"
    )
    check_artifact_input_digests_fail_closed(workflow)


def run_producer_outputs(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print(
        "producer-outputs — a producer uploading several paths fails on a missing "
        "output"
    )
    check_multi_path_producers_are_listed(workflow)
    for job_id, artifact, marker_name, tracked, rejects_empty in MULTI_PATH_PRODUCERS:
        check_multi_path_outputs_are_verified(
            workflow, job_id, artifact, marker_name, tracked, rejects_empty
        )


def run_package_writers(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print("package-writers — no `packages: write`; the cache token stays in docker-cache")
    check_package_write_and_cache_token(workflow)


def run_needs_condition(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print("needs-condition — a job's dependencies run wherever the job does")
    check_dependency_conditions(workflow)
    check_draft_condition(workflow)
    check_dependency_conditions_detect_a_narrowed_producer(workflow)
    check_dependency_conditions_detect_a_narrowed_awaited_producer(workflow)
    check_dependency_conditions_detect_a_conditionless_consumer(workflow)
    check_dependency_conditions_read_a_status_guarded_consumer(workflow)
    check_awaited_downloads(workflow)
    check_await_script()


def run_push_writers(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print("push-writers — a push to `main` runs every cache writer, and only a push skips")
    check_condition_grammar()
    check_aggregate_grammar()
    check_push_runs_every_cache_writer(workflow)
    check_push_writer_mutants(workflow)


def run_main_only_writers(inputs: Inputs) -> None:
    print("main-only-writers — every Actions-cache writer saves only on `main`")
    check_cache_writers_save_on_main_only(inputs.documents)
    check_main_only_detects_an_off_main_writer(inputs.documents)


def run_macos_bridges(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print("macos-bridges — a pull request runs the macOS bridge jobs only on their paths")
    check_macos_bridges_follow_their_paths(workflow)
    check_macos_bridge_mutants(workflow)


def run_prose_route(inputs: Inputs) -> None:
    workflow = inputs.workflow
    print("prose-route — every tracked path is prose or reaches the `code` output")
    check_every_path_routed(workflow)
    paths = tracked_paths()
    check_binding_test_reads(workflow, paths)
    check_script_reads(workflow, paths)


def run_coverage(inputs: Inputs) -> None:
    jobs = inputs.jobs
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


def run_path_closure(inputs: Inputs) -> None:
    jobs = inputs.jobs
    print("path-closure — a path filter covers every crate its jobs compile")
    check_closure_reads_workspace_inheritance()
    check_resolution_manifests_reach_the_workspace()
    check_path_dep_closures(jobs)
    check_fuzz_filter_selects_every_crate_manifest(jobs)


def run_workspace_scope(inputs: Inputs) -> None:
    documents = inputs.documents
    print(
        "workspace-scope — a filter gating a `--workspace` compile covers every member"
    )
    # Every workflow, not ci.yml alone: docs.yml's `rust-docs` runs
    # `cargo doc --workspace` under a `docs` filter of its own, and that filter
    # named eleven of the twenty-six members the root manifest lists.
    for path, doc in documents:
        check_workspace_scoped_filters(path, doc)
    check_workspace_scope_detects_a_narrowed_filter(documents)


def run_private_items(inputs: Inputs) -> None:
    documents = inputs.documents
    print("private-items — every `cargo doc` reads the links private modules write")
    check_rustdoc_lint_reaches_every_member()
    check_rustdoc_lint_readers_detect_a_lowered_level()
    check_rustdoc_documents_private_items(documents)
    check_private_items_detects_a_dropped_flag(documents)
    check_workspace_and_rustdoc_readers(documents)


def run_no_cargo_gradle(inputs: Inputs) -> None:
    jobs = inputs.jobs
    print("no-cargo-gradle — kotlin-lint's cargo-free Gradle calls skip the daemon")
    check_no_cargo_gradle_calls_skip_the_daemon(jobs)


def run_merge_queue(inputs: Inputs) -> None:
    documents = inputs.documents
    print("merge-queue — a workflow that skips to a success status runs in the queue")
    check_merge_queue_triggers(documents)


def run_step_filter(inputs: Inputs) -> None:
    jobs = inputs.jobs
    print("step-filter — a filter output gates a job, never a step")
    check_filter_outputs_gate_jobs(jobs)


def run_filter_source(inputs: Inputs) -> None:
    documents = inputs.documents
    print("filter-source — a `changes` output reads a filter key that exists")
    # Every workflow, not ci.yml alone: docs.yml declares a `dorny/paths-filter`
    # step of its own, and its `docs` output reads two keys off that step.
    for path, doc in documents:
        check_filter_keys_agree(path, doc)
    check_filter_key_agreement_detects_a_rename(documents)


# CRITERION: each job here lints and tests EVERY target of each package paired
# with it in a build that leaves that package's `testing` feature off: one
# `cargo clippy` over `--all-targets` that denies warnings, and one `cargo
# test`/`cargo nextest run` carrying no target or test selector. Every other
# clippy and test lane enables `testing`, and the filtered commands
# check_shipped_build_assertions_run reads select a handful of tests by name,
# so a test helper only `testing`-gated tests construct (dead code in this
# configuration, which `-D warnings` rejects) and a test needing `testing`
# that carries no gate both reached main with every lane green.
SHIPPED_CONFIG_FULL_RUN_LANES = {
    "rust-build-uniffi-production": {"scp-ffi-uniffi"},
}

# Flags a full-run command may carry: none selects a target or a test. A full
# run is a command made only of these, so any selector (`--lib`, `--test X`,
# `--doc`, `-E`, a name, `-- --skip X`) fails it without being listed.
# LINT_FULL_RUN_SWITCHES adds `--all-targets` for a lint only: on `cargo test`
# it selects every target but the doctests.
FULL_RUN_VALUE_FLAGS = {
    "-p",
    "--package",
    "--features",
    "-F",
    "--profile",
    "--no-tests",
    "-j",
    "--jobs",
    "--target-dir",
}
FULL_RUN_SWITCHES = {
    "--locked",
    "--frozen",
    "--offline",
    "--no-fail-fast",
    "-q",
    "--quiet",
    "-v",
    "--verbose",
}
LINT_FULL_RUN_SWITCHES = FULL_RUN_SWITCHES | {"--all-targets"}
HARNESS_FULL_RUN_VALUE_FLAGS = {"--test-threads"}
HARNESS_FULL_RUN_SWITCHES = {"--nocapture", "--show-output"}


def selects_every_target(tokens: list[str], lint: bool = False) -> bool:
    """Whether a `cargo clippy`/`cargo test`/`cargo nextest run` token list
    carries only FULL_RUN flags, so it selects no target and no test subset.
    A lint command's tokens after `--` are lint levels and are not read.
    """
    cargo_side = tokens[: tokens.index("--")] if "--" in tokens else tokens
    harness_side = tokens[len(cargo_side) + 1 :]
    if lint:
        harness_side = []
    rest = list(cargo_side)
    for word in ("cargo", "clippy", "test", "nextest", "run"):
        if rest and rest[0] == word:
            rest.pop(0)

    def only(side: list[str], value_flags: set, switches: set) -> bool:
        take_next = False
        for token in side:
            if take_next:
                take_next = False
            elif token in value_flags:
                take_next = True
            elif token.split("=", 1)[0] not in value_flags | switches:
                return False
        return not take_next

    switches = LINT_FULL_RUN_SWITCHES if lint else FULL_RUN_SWITCHES
    return only(rest, FULL_RUN_VALUE_FLAGS, switches) and only(
        harness_side, HARNESS_FULL_RUN_VALUE_FLAGS, HARNESS_FULL_RUN_SWITCHES
    )


def shipped_config_full_run_gaps(job: dict, package: str) -> list[str]:
    """Return what `job` lacks of a full lint and test run over `package` with
    `testing` off; an empty list means it has both.
    """

    def testing_off(tokens: list[str]) -> bool:
        return (
            command_covers_package(tokens, package)
            and not command_enables_testing(tokens, package)
            and command_unifies_testing(tokens, package) is None
        )

    lints = tests = False
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        for line in logical_lines(step.get("run") or ""):
            tokens = split_command(line)
            if line.startswith("cargo clippy ") and testing_off(tokens):
                after = tokens[tokens.index("--") + 1 :] if "--" in tokens else []
                denies = any(
                    after[i : i + 2] == ["-D", "warnings"] for i in range(len(after))
                )
                lints = lints or (
                    "--all-targets" in tokens
                    and selects_every_target(tokens, lint=True)
                    and denies
                )
    for tokens in cargo_test_commands(job):
        tests = tests or (selects_every_target(tokens) and testing_off(tokens))
    gaps = []
    if not lints:
        gaps.append(
            f"no `cargo clippy -p {package} --all-targets … -- -D warnings` with "
            f"`testing` off"
        )
    if not tests:
        gaps.append(f"no unfiltered `cargo test -p {package}` with `testing` off")
    return gaps


def check_shipped_config_full_runs(jobs: dict) -> None:
    """Each SHIPPED_CONFIG_FULL_RUN_LANES job lints and tests every target of
    its packages with `testing` off. The criterion sits at the table.
    """
    # A case that must fail: a job running only the build and a filtered
    # nextest command, the shape job rust-build-uniffi-production had when a
    # dead test helper and an ungated `testing` test reached main.
    filtered_only = {
        "steps": [
            {"run": "cargo build -p scp-ffi-uniffi --features server"},
            {
                "run": "cargo nextest run --no-tests=fail -p scp-ffi-uniffi "
                "--features server --lib -E 'test(one)'"
            },
            {
                "run": "cargo clippy -p scp-ffi-uniffi --all-targets "
                "--features scp-ffi-uniffi/testing -- -D warnings"
            },
        ]
    }
    check(
        "a lane with only a filtered test run and a `testing` clippy has two gaps",
        len(shipped_config_full_run_gaps(filtered_only, "scp-ffi-uniffi")) == 2,
        f"returned {shipped_config_full_run_gaps(filtered_only, 'scp-ffi-uniffi')}",
    )
    full = "cargo test -p scp-ffi-uniffi --features server"
    for command in (
        full,
        "cargo nextest run --no-tests=fail -p scp-ffi-uniffi --features server",
        f"{full} -- --test-threads 1",
    ):
        check(
            f"`{command}` counts as a full run",
            selects_every_target(split_command(command)),
            "rejected",
        )
    for suffix in (
        "--lib",
        "--test e2e_bridge",
        "--test=e2e_bridge",
        "--bins",
        "--doc",
        "--examples",
        "--all-targets",
        "lifecycle",
        "-- conformance",
        "-- --skip e2e",
        "-- --ignored",
    ):
        command = f"{full} {suffix}"
        check(
            f"`{command}` does not count as a full run",
            not selects_every_target(split_command(command)),
            "accepted",
        )
    clippy = "cargo clippy -p scp-ffi-uniffi --all-targets --features server"
    check(
        "a full clippy over --all-targets counts as linting every target",
        selects_every_target(split_command(f"{clippy} -- -D warnings"), lint=True),
        "rejected",
    )
    check(
        "a clippy carrying a target selector does not count",
        not selects_every_target(
            split_command(f"{clippy} --lib -- -D warnings"), lint=True
        ),
        "accepted",
    )
    for job_id, packages in sorted(SHIPPED_CONFIG_FULL_RUN_LANES.items()):
        for package in sorted(packages):
            # Looked up by key so a renamed job raises rather than passing.
            gaps = shipped_config_full_run_gaps(jobs[job_id], package)
            check(
                f"{job_id} lints and tests every {package} target with `testing` off",
                not gaps,
                "; ".join(gaps),
            )


def run_shipped_config(inputs: Inputs) -> None:
    jobs = inputs.jobs
    print(
        "shipped-config — a production-config lane runs its bridge's fail-closed "
        "assertions"
    )
    check_shipped_assertion_readers()
    check_testing_unification_readers()
    check_shipped_build_assertions_run(jobs)
    check_shipped_assertion_tripwires(jobs)
    check_shipped_config_full_runs(jobs)


def run_zero_test(inputs: Inputs) -> None:
    documents = inputs.documents
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


def run_rust_fanout(inputs: Inputs) -> None:
    jobs = inputs.jobs
    rust_pr = SCENARIOS["rust-only, pull_request"]
    rust_merge = SCENARIOS["rust-only, merge_group"]
    print("rust-fanout — a Rust-only change runs binding test jobs")
    # SCENARIOS says each job below runs on a Rust-only change, so reporting it
    # `skipped` must reach an aggregate as one named failure. Narrowing that
    # job's `if:` in ci.yml back to its own binding directory makes an aggregate
    # accept that skip, which drops this assertion's exit code to 0. A Rust-only
    # pull request skips swift-build-test, so its case reads the merge_group run,
    # where the `rust` clause still selects it.
    for job_id, scenario in (
        ("python-test", rust_pr),
        ("typescript-check", rust_pr),
        ("kotlin-test", rust_pr),
        ("swift-build-test", rust_merge),
    ):
        needs = build_needs(jobs, scenario)
        needs[job_id]["result"] = "skipped"
        code, out = run_aggregate(needs, scenario.event)
        check(
            f"{job_id} skipped on a Rust-only change ({scenario.event}) -> exit 1 naming it",
            code == 1 and job_id in out,
            out,
        )


def run_macos_bridge_verdicts(inputs: Inputs) -> None:
    jobs = inputs.jobs
    rust_pr = SCENARIOS["rust-only, pull_request"]
    rust_merge = SCENARIOS["rust-only, merge_group"]
    python_pr = SCENARIOS["python-only, pull_request"]
    print("macos-bridges — the aggregate judges a macOS bridge skip by event and path")
    # A Rust-only pull request skips the four macOS bridge jobs and passes. The
    # same skip fails a Rust-only merge_group run and a swift pull request, and
    # the python pull request fails on a skip of each of its three; each failure
    # names the job, so a verdict reached for another reason does not satisfy it.
    needs = build_needs(jobs, rust_pr)
    check(
        "Rust-only pull request reports every macOS bridge job skipped",
        all(needs[job_id]["result"] == "skipped" for job_id in MACOS_BRIDGE_JOBS),
        f"{ {job_id: needs[job_id] for job_id in MACOS_BRIDGE_JOBS} }",
    )
    code, out = run_aggregate(needs, rust_pr.event)
    check("Rust-only pull request, macOS bridge jobs skipped -> exit 0", code == 0, out)
    swift_pr = SCENARIOS["swift-and-typescript, pull_request"]
    for scenario, selected in (
        (rust_merge, MACOS_BRIDGE_JOBS),
        (swift_pr, MACOS_BRIDGE_JOBS),
        (python_pr, ("bridge-parity-swift", "pyo3-module-macos", "xcframework")),
    ):
        for job_id in selected:
            needs = build_needs(jobs, scenario)
            needs[job_id]["result"] = "skipped"
            code, out = run_aggregate(needs, scenario.event)
            check(
                f"{scenario.name}, macOS bridge job {job_id} skipped -> exit 1 naming it",
                code == 1 and f"{job_id}: skipped" in out,
                f"exit {code}: {out}",
            )


def run_python_fanout(inputs: Inputs) -> None:
    jobs = inputs.jobs
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


def run_skip(inputs: Inputs) -> None:
    jobs = inputs.jobs
    rust_pr = SCENARIOS["rust-only, pull_request"]
    docs_pr = SCENARIOS["docs-only, pull_request"]
    docs_push = SCENARIOS["docs-only, push"]
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


def run_push_skips(inputs: Inputs) -> None:
    workflow = inputs.workflow
    jobs = inputs.jobs
    rust_pr = SCENARIOS["rust-only, pull_request"]
    docs_pr = SCENARIOS["docs-only, pull_request"]
    docs_push = SCENARIOS["docs-only, push"]
    rust_merge = SCENARIOS["rust-only, merge_group"]
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

    # `changes` carries check-draft's `if:` rather than needing it, so the two skip
    # together. Either one skipping alone means their conditions diverged.
    needs = build_needs(jobs, docs_pr)
    for entry in needs.values():
        entry["result"] = "skipped"
    needs["changes"] = {"result": "success", "outputs": dict(docs_pr.filters)}
    code, out = run_aggregate(needs, docs_pr.event)
    check(
        "check-draft skipped while changes ran -> exit 1",
        code == 1 and "conditions diverged" in out,
        f"exit {code}: {out}",
    )

    needs = build_needs(jobs, docs_pr)
    needs["changes"] = {"result": "skipped", "outputs": {}}
    code, out = run_aggregate(needs, docs_pr.event)
    check(
        "check-draft ran while changes skipped -> exit 1",
        code == 1 and "changes: skipped" in out,
        f"exit {code}: {out}",
    )

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


def run_filter_key(inputs: Inputs) -> None:
    jobs = inputs.jobs
    rust_pr = SCENARIOS["rust-only, pull_request"]
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


def release_test_features(doc: dict) -> list[tuple[str, set[str]]]:
    """Return (job, `--features` set) for each release-profile `cargo test` in `doc`.

    A release test is a logical `run:` line that starts with `cargo test` and
    carries a `--release` token. A command that names no `--features`
    contributes an empty set, so a dropped flag reads as a mismatch.
    """
    found = []
    for job_name, job in (doc.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            for line in logical_lines(str(step.get("run") or "")):
                if not line.startswith("cargo test"):
                    continue
                tokens = split_command(line)
                if "--release" not in tokens:
                    continue
                found.append((job_name, command_feature_set(tokens)))
    return found


def command_feature_set(tokens: list[str]) -> set[str]:
    """Return the union of every `--features` value among `tokens`."""
    features: set[str] = set()
    for index, token in enumerate(tokens):
        if token == "--features" and index + 1 < len(tokens):
            features |= set(tokens[index + 1].split(","))
        elif token.startswith("--features="):
            features |= set(token.removeprefix("--features=").split(","))
    return features


WORKSPACE_CLIPPY_PREFIX = "cargo clippy --workspace --all-targets"


def workspace_clippy_features(ci: dict) -> list[set[str]]:
    """Return the `--features` set of each workspace clippy command in rust-clippy."""
    found = []
    for step in ci["jobs"]["rust-clippy"].get("steps") or []:
        if not isinstance(step, dict):
            continue
        for line in logical_lines(str(step.get("run") or "")):
            if line.startswith(WORKSPACE_CLIPPY_PREFIX):
                found.append(command_feature_set(split_command(line)))
    return found


def release_test_feature_gaps(
    ci: dict, documents: list[tuple[str, dict]]
) -> list[str]:
    """Return each way a workflow's release test features differ from CI's.

    CRITERION: a `cargo test --release` step in any workflow compiles every
    workspace test target in the release profile, and build-matrix.yml and
    release.yml run theirs under `RUSTFLAGS=-D warnings` at tag time. The
    `workspace` leg of job rust-clippy in ci.yml is the only pull-request build
    that denies warnings across every workspace test target. A
    `#[cfg(feature = ...)]` test or helper is compiled by both exactly when both
    name the same feature set. A feature only one of them names lets a helper be
    live on every pull request and dead, and so a `dead_code` error, at tag time.
    `documents` is (file name, parsed workflow) for every workflow file.
    """
    linted = workspace_clippy_features(ci)
    if len(linted) != 1:
        return [f"ci.yml rust-clippy runs {len(linted)} `{WORKSPACE_CLIPPY_PREFIX}` commands, not 1"]
    gaps = []
    for name, doc in documents:
        for job, released in release_test_features(doc):
            gaps += [
                f"{name}:{job}: only the release test names {f}"
                for f in sorted(released - linted[0])
            ]
            gaps += [
                f"{name}:{job}: only the workspace clippy names {f}"
                for f in sorted(linted[0] - released)
            ]
    return gaps


def run_release_test_features(inputs: Inputs) -> None:
    print(
        "release-test-features — every workflow's release `cargo test` names the "
        "features ci.yml's workspace clippy lints"
    )
    documents = [(path.name, doc) for path, doc in inputs.documents]
    by_name = dict(documents)
    released = {
        name: [job for job, _ in release_test_features(doc)] for name, doc in documents
    }
    released = {name: jobs for name, jobs in released.items() if jobs}
    # The two release tests this check exists for. A rename that hid either from
    # the reader would leave the equality below vacuously true for it.
    check(
        "the reader finds the release tests of build-matrix.yml rust and release.yml",
        "rust" in released.get("build-matrix.yml", [])
        and len(released.get("release.yml", [])) == 1,
        f"{released}",
    )
    gaps = release_test_feature_gaps(inputs.workflow, documents)
    check(
        "every workflow's release test features equal ci.yml's workspace clippy features",
        not gaps,
        "; ".join(gaps),
    )

    # Controls: a narrowed list, a widened list, a release test in a workflow file
    # no check names, and a multi-line `run:` block each report.
    narrow = "cargo test --workspace --release --features scp-core/testing,scp-runtime/saga-witness-test-mint"

    def with_release_command(name: str, command: str) -> list[tuple[str, dict]]:
        mutated = copy.deepcopy(by_name[name])
        for job in mutated["jobs"].values():
            for step in job.get("steps") or []:
                if isinstance(step, dict) and "cargo test --workspace --release" in str(
                    step.get("run") or ""
                ):
                    step["run"] = command
        return [(n, mutated if n == name else d) for n, d in documents]

    gaps = release_test_feature_gaps(
        inputs.workflow, with_release_command("build-matrix.yml", narrow + " --target x")
    )
    check(
        "a build-matrix release test without the bridges' testing features is reported",
        "build-matrix.yml:rust: only the workspace clippy names scp-ffi/testing" in gaps,
        f"{gaps}",
    )
    gaps = release_test_feature_gaps(inputs.workflow, with_release_command("release.yml", narrow))
    check(
        "a release.yml release test without scp-runtime/testing is reported",
        any(
            g.startswith("release.yml:") and g.endswith("only the workspace clippy names scp-runtime/testing")
            for g in gaps
        ),
        f"{gaps}",
    )
    gaps = release_test_feature_gaps(
        inputs.workflow,
        with_release_command(
            "release.yml",
            f"cargo test --workspace --release --features {CLIPPY_WORKSPACE_FEATURES},scp-node/cloud-blobs",
        ),
    )
    check(
        "a release test naming a feature the workspace clippy does not is reported",
        len(gaps) == 1 and gaps[0].endswith("only the release test names scp-node/cloud-blobs"),
        f"{gaps}",
    )
    planted = {
        "jobs": {
            "nightly": {
                "steps": [
                    {"run": "echo start\ncargo test -p scp-core \\\n  --release --features scp-core/testing"}
                ]
            }
        }
    }
    gaps = release_test_feature_gaps(inputs.workflow, [*documents, ("planted.yml", planted)])
    check(
        "a release test in a new workflow file, split across lines, is reported",
        "planted.yml:nightly: only the workspace clippy names scp-ffi/testing" in gaps,
        f"{gaps}",
    )


CHECKS: dict[str, Callable[[Inputs], None]] = {
    "timeout": run_timeout,
    "action-ref": run_action_ref,
    "doc-flag": run_doc_flag,
    "doc-command": run_doc_command,
    "win-shell": run_win_shell,
    "matrix-axis": run_matrix_axis,
    "leg-commands": run_leg_commands,
    "linted-features": run_linted_features,
    "release-test-features": run_release_test_features,
    "empty-input": run_empty_input,
    "downloaded-module": run_downloaded_module,
    "downloaded-addon": run_downloaded_addon,
    "retention": run_retention,
    "profile-env": run_profile_env,
    "cache-key": run_cache_key,
    "offline-cargo": run_offline_cargo,
    "pinned-python": run_pinned_python,
    "artifact-key": run_artifact_key,
    "artifact-digest": run_artifact_digest,
    "producer-outputs": run_producer_outputs,
    "package-writers": run_package_writers,
    "needs-condition": run_needs_condition,
    "push-writers": run_push_writers,
    "main-only-writers": run_main_only_writers,
    "macos-bridges": run_macos_bridges,
    "prose-route": run_prose_route,
    "coverage": run_coverage,
    "path-closure": run_path_closure,
    "workspace-scope": run_workspace_scope,
    "private-items": run_private_items,
    "no-cargo-gradle": run_no_cargo_gradle,
    "merge-queue": run_merge_queue,
    "step-filter": run_step_filter,
    "filter-source": run_filter_source,
    "shipped-config": run_shipped_config,
    "zero-test": run_zero_test,
    "rust-fanout": run_rust_fanout,
    "macos-bridge-verdicts": run_macos_bridge_verdicts,
    "python-fanout": run_python_fanout,
    "skip": run_skip,
    "push-skips": run_push_skips,
    "filter-key": run_filter_key,
    "verified-download": run_verified_download,
}

# CRITERION for GROUPS: a check belongs to `docs` when a file outside the `code`
# output's patterns can change its verdict — it opens such a file (any root-level
# `*.md`, anything under `.docs/` or `.claude/`, a `*.md` under `docs/guides/`), or
# it lists tracked paths, which a prose-only change adds to or removes from. Job
# ci-workflow-selftest runs `rest` under `needs.changes.outputs.code == 'true'`,
# so a prose-only pull request skips it; a check in `rest` that read prose would
# then let that pull request merge without the check ever reading the change.
# Job ci-workflow-selftest-docs runs `docs` on every pull request. Every other
# check opens only `.github/workflows/*`, `scripts/**`, `Cargo.toml` files and
# `crates/**`, which the `code` output selects. The two docs checks:
#   doc-command  `git ls-files '*.md'` and the text of every Markdown file it
#                lists, to compare each documented `cargo doc` with job rust-doc.
#   prose-route  `git ls-files` over the whole tree, and whether `.docs/adrs/`,
#                `.docs/prds/` and AGENTS.md are tracked, which rust-test reads.
GROUPS: dict[str, tuple[str, ...]] = {
    "docs": ("doc-command", "prose-route"),
    "rest": (
        "timeout",
        "action-ref",
        "doc-flag",
        "win-shell",
        "matrix-axis",
        "leg-commands",
        "linted-features",
        "release-test-features",
        "empty-input",
        "downloaded-module",
        "downloaded-addon",
        "retention",
        "profile-env",
        "cache-key",
        "offline-cargo",
        "pinned-python",
        "artifact-key",
        "artifact-digest",
        "producer-outputs",
        "package-writers",
        "needs-condition",
        "push-writers",
        "main-only-writers",
        "macos-bridges",
        "coverage",
        "path-closure",
        "workspace-scope",
        "private-items",
        "no-cargo-gradle",
        "merge-queue",
        "step-filter",
        "filter-source",
        "shipped-config",
        "zero-test",
        "rust-fanout",
        "macos-bridge-verdicts",
        "python-fanout",
        "skip",
        "push-skips",
        "filter-key",
        "verified-download",
    ),
}


def group_partition_gaps(
    checks: dict[str, Callable[[Inputs], None]], groups: dict[str, tuple[str, ...]]
) -> list[str]:
    """Return each way `groups` fails to split `checks` into `docs` and `rest`.

    CRITERION: CI runs `--group docs` in one job and `--group rest` in another, so
    a check in neither group runs in no job, and a check in both runs twice. The
    two groups together must name every check, each exactly once.
    """
    gaps = []
    if set(groups) != {"docs", "rest"}:
        gaps.append(f"groups are {sorted(groups)}, not ['docs', 'rest']")
    assigned = [name for names in groups.values() for name in names]
    gaps += [f"{name} is in no group" for name in checks if name not in assigned]
    gaps += [f"{name} names no check" for name in sorted(set(assigned) - set(checks))]
    gaps += [
        f"{name} is in more than one group"
        for name in sorted({name for name in assigned if assigned.count(name) > 1})
    ]
    return gaps


def check_group_partition() -> None:
    gaps = group_partition_gaps(CHECKS, GROUPS)
    check(
        "docs ∪ rest is every check, and docs ∩ rest is empty",
        not gaps,
        "; ".join(gaps),
    )
    # Controls: a check registered in neither group, and one in both, each report.
    planted = {**CHECKS, "planted-unassigned": lambda _inputs: None}
    check(
        "a check registered in neither group is reported",
        "planted-unassigned is in no group" in group_partition_gaps(planted, GROUPS),
        f"{group_partition_gaps(planted, GROUPS)}",
    )
    shared = GROUPS["rest"][0]
    overlap = {"docs": (*GROUPS["docs"], shared), "rest": GROUPS["rest"]}
    check(
        "a check registered in both groups is reported",
        f"{shared} is in more than one group" in group_partition_gaps(CHECKS, overlap),
        f"{group_partition_gaps(CHECKS, overlap)}",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--group",
        choices=("docs", "rest", "all"),
        default="all",
        help="run the checks GROUPS names under this group; `all` runs every check",
    )
    group = parser.parse_args(argv).group
    print("group-partition — `--group docs` and `--group rest` run every check once")
    check_group_partition()
    inputs = load_inputs()
    selected = [
        name for name in CHECKS if group == "all" or name in GROUPS.get(group, ())
    ]
    timings: list[tuple[float, str]] = []
    for name in selected:
        started = time.perf_counter()
        CHECKS[name](inputs)
        timings.append((time.perf_counter() - started, name))

    print(f"\ntiming — seconds per check, group {group}, slowest first")
    for seconds, name in sorted(timings, reverse=True):
        owner = next((g for g, names in GROUPS.items() if name in names), "none")
        print(f"  {seconds:7.2f}s  {name} ({owner})")
    print(f"  {sum(seconds for seconds, _ in timings):7.2f}s  total")

    print(f"\n{checks - len(failures)} of {checks} assertions passed")
    if failures:
        print("failed: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
