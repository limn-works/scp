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
               comment claiming nothing enables `scp-identity/testing`.
               crates/scp-testing/Cargo.toml declares a normal dependency
               `scp-identity = { path = "../scp-identity", features =
               ["testing"] }`, and one cargo invocation resolves one feature
               set per package, so that job's `cargo nextest run --workspace`
               built scp-identity with `testing` on and compiled its two
               `#[cfg(not(feature = "testing"))]` assertions out — while the
               check reading that table reported each one running by name.
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
  doc-flag     Job rust-doc in ci.yml ran `cargo doc` without
               `--document-private-items`, while the `rust-docs` job of
               docs.yml passed that flag. rustdoc resolves a link written on a
               private item only under that flag, so three unresolved links in
               the private module crates/scp-runtime/src/context/
               outlets_helpers.rs compiled clean under the sole required status
               check and failed only in docs.yml, which the Default ruleset
               does not require. They rode `main` for ten days after pull
               request #2274 merged. Pull request #2329 then repaired the three
               links and added a `push: branches: [main]` trigger to docs.yml,
               which shortened time-to-detection and left the required check
               unable to produce the diagnostic.

Assertions over an aggregate's verdict read which jobs a scenario selects out
of SCENARIOS below, never out of the aggregate itself. Six of them once built
that expectation by calling `evaluate` in scripts/ci-aggregate-result.py, the
same function whose verdict they then judged, so each one agreed with that
function however it behaved.

Run: python3 scripts/tests/ci-gate/ci_gate_selftest.py
"""

from __future__ import annotations

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
# scp-identity's lane: crates/scp-testing/Cargo.toml declares a normal
# dependency `scp-identity = { path = "../scp-identity", features =
# ["testing"] }`, and one cargo invocation resolves one feature set per
# package, so every build that includes scp-testing compiles scp-identity's
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

# Jobs a `changes` filter output selects. cross-layer reads an event rather
# than a filter, so each scenario states cross-layer for itself.
RUST_ONLY_RUNS = {
    "bridge-parity": True,
    "bridge-parity-kotlin": True,
    "bridge-parity-swift": True,
    "docker-image": True,
    "fuzz-build": False,
    "kotlin-lint": False,
    "kotlin-test": True,
    "python-lint": False,
    "python-test": True,
    "rust-build-pyo3-production": True,
    "rust-build-uniffi-production": True,
    "rust-clippy": True,
    "rust-deny": True,
    "rust-doc": True,
    "rust-fmt": True,
    "rust-test": True,
    "rust-test-napi-production": True,
    "scaffold-typescript-web-check": False,
    "swift-build-test": True,
    "swift-lint": False,
    "typescript-check": True,
    "typescript-wasm-check": False,
}
DOCS_ONLY_RUNS = dict.fromkeys(RUST_ONLY_RUNS, False)

SCENARIOS = {
    "rust-only, pull_request": Scenario(
        name="rust-only, pull_request",
        filters=RUST_ONLY,
        event="pull_request",
        runs=RUST_ONLY_RUNS | {"cross-layer": True},
    ),
    "docs-only, pull_request": Scenario(
        name="docs-only, pull_request",
        filters=DOCS_ONLY,
        event="pull_request",
        runs=DOCS_ONLY_RUNS | {"cross-layer": True},
    ),
    "docs-only, push": Scenario(
        name="docs-only, push",
        filters=DOCS_ONLY,
        event="push",
        runs=DOCS_ONLY_RUNS | {"cross-layer": False},
    ),
    "rust-only, merge_group": Scenario(
        name="rust-only, merge_group",
        filters=RUST_ONLY,
        event="merge_group",
        runs=RUST_ONLY_RUNS | {"cross-layer": False},
    ),
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
# three in every manifest it reads: a dev-dependency joins feature unification
# whenever cargo builds that manifest's own test targets, and counting it in a
# dependency's manifest too errs toward reporting a gap rather than toward
# passing one.
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


def shipped_build_assertions() -> dict[str, dict[str, Path]]:
    """Return each package's shipped-build assertions, by test-function name.

    A shipped-build assertion is a function carrying both a test attribute and
    SHIPPED_ONLY_ATTRIBUTE, in either order and with other attributes and
    comment lines between them. Reads every `.rs` file under crates/, so a
    package this repository adds later is scanned without editing this file.
    """
    found: dict[str, dict[str, Path]] = {}
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
            if (
                name
                and any(TEST_ATTRIBUTE.match(a) for a in attributes)
                and SHIPPED_ONLY_ATTRIBUTE in attributes
            ):
                package = owning_package(source)
                found.setdefault(package, {})[name.group(1)] = source
            attributes = []
    return found


def check_shipped_assertion_readers() -> None:
    """Drive the three readers check_shipped_build_assertions_run rests on.

    That check decides whether a fail-closed proof executes anywhere, and it
    decides it by asking command_covers_package, filterset_patterns, and
    command_selects about a command's tokens. A reader that answered "yes" to
    every question would leave that check reporting success over work it did not
    do, so each case below states an input whose answer is known and asserts the
    reader returns it. The synthetic tokens are written here rather than read
    from ci.yml, so a workflow edit cannot make a case vacuous.
    """
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
    """Write a four-crate workspace holding each spelling of a manifest edge
    that turns a sibling's `testing` feature on.

    leaf     declares the feature and no dependencies.
    enabler  depends on leaf with `features = ["testing"]`, the edge
             crates/scp-testing/Cargo.toml carries against scp-identity.
    middle   depends on enabler and never names leaf.
    selfdev  dev-depends on itself with `features = ["testing"]`, the spelling
             crates/scp-dht/Cargo.toml uses to turn its own feature on in its
             tests.
    """
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["leaf", "enabler", "middle", "selfdev"]\n'
    )
    bodies = {
        "leaf": "[features]\ntesting = []\n",
        "enabler": (
            "[dependencies]\n"
            'leaf = { path = "../leaf", features = ["testing"] }\n'
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
    build reads crates/scp-testing/Cargo.toml and compiles both of that
    crate's fail-closed assertions out.
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
                    "--exclude middle"
                ),
                "leaf",
                root,
            )
            is None,
            "leaf and selfdev remain, and neither reaches enabler's manifest",
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
    check(
        "a workspace build turns scp-identity/testing on through scp-testing",
        live_edge is not None and "scp-testing" in str(live_edge),
        f"got {live_edge!r} — crates/scp-testing/Cargo.toml declares "
        f'`scp-identity = {{ features = ["testing"] }}` as a normal '
        f"dependency, and a reader that misses it re-greens pairing "
        f"scp-identity's assertions with a workspace lane",
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
    job its package is paired with.

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


def main() -> int:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    jobs = workflow["jobs"]
    documents = [
        (path, yaml.safe_load(path.read_text()))
        for path in sorted((REPO / ".github/workflows").glob("*.yml"))
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

    print("win-shell — every `run:` step a Windows runner can execute names a shell")
    for path, doc in documents:
        check_windows_shell(path, doc)

    print(
        "empty-input — a job publishing a -signed artifact rejects an empty "
        "input set first"
    )
    check_signing_guard(documents)

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
    check("an unconditional job skipped -> exit 1", code == 1, out)

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
