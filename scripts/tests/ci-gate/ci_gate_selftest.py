#!/usr/bin/env python3
"""Self-test for the CI gate: the workflow's structure and the aggregate's verdict.

Every assertion here corresponds to a defect where a check ran and enforced
nothing:

  timeout      No job set `timeout-minutes`, so a hung job burned the 360-minute
               per-job runner ceiling.
  coverage     Three enforcement jobs (pyi-generated, construction-pattern,
               block-in-place) were not dependencies of `ci`, the only required
               status check, so their failures never blocked a merge.
  skip         The aggregate compared results against "failure" and "cancelled"
               only, so a skipped dependency and a passing dependency produced
               the same verdict.
  rust-fanout  The python, typescript, kotlin and swift filters listed only the
               bindings and their own bridge directory, so a pull request that
               touched crates/scp-runtime/ alone skipped all four test jobs.
  zero-test    `cargo test <filter>` exits 0 when the filter selects no test, so
               a fail-closed lane reported success over zero assertions.
  scaled-input Two fuzz jobs pass a workflow_dispatch input to libFuzzer as
               `-max_total_time`, so an operator sets how long they run. A
               budget fixed above a scheduled run cancelled every dispatch
               asking for longer, killing a run that previously completed.

Run: python3 scripts/tests/ci-gate/ci_gate_selftest.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
WORKFLOW = REPO / ".github/workflows/ci.yml"
AGGREGATE = REPO / "scripts/ci-aggregate-result.py"

# A ci.yml job whose work is a script or a lint finishes in under a minute; one
# that compiles the workspace takes about twenty. The point of a ceiling is that
# a hang costs minutes rather than the six hours GitHub allows by default.
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

# Cargo flags that consume the token after them. Any other bare token following
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


def positional_filters(command: str) -> list[str]:
    """Return the bare test-name arguments a cargo command carries."""
    tokens = shlex.split(command.split(" -- ", 1)[0])
    for word in ("cargo", "test", "nextest", "run"):
        if tokens and tokens[0] == word:
            tokens.pop(0)
    filters, skip_next = [], False
    for token in tokens:
        if skip_next:
            skip_next = False
        elif token in VALUE_FLAGS:
            skip_next = True
        elif not token.startswith("-"):
            filters.append(token)
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


def load_aggregate():
    spec = importlib.util.spec_from_file_location("ci_aggregate_result", AGGREGATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_aggregate(needs: dict, event_name: str) -> tuple[int, str]:
    env = dict(os.environ, NEEDS_JSON=json.dumps(needs), GITHUB_EVENT_NAME=event_name)
    proc = subprocess.run(
        [sys.executable, str(AGGREGATE), str(WORKFLOW)],
        env=env,
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def build_needs(
    jobs: dict, outputs: dict[str, str], event_name: str, aggregate
) -> dict:
    """Every dependency reports the result its own `if:` condition implies."""
    needs = {}
    for job_id in set(jobs) - {"ci"}:
        if job_id == "check-draft":
            needs[job_id] = {"result": "success"}
            continue
        if job_id == "changes":
            needs[job_id] = {"result": "success", "outputs": outputs}
            continue
        condition = jobs[job_id].get("if")
        runs = (
            True
            if condition is None
            else aggregate.evaluate(str(condition), outputs, event_name)
        )
        needs[job_id] = {"result": "success" if runs else "skipped"}
    return needs


def main() -> int:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    jobs = workflow["jobs"]
    aggregate = load_aggregate()

    print("timeout — every job in every workflow bounds its own runtime")
    for path in sorted((REPO / ".github/workflows").glob("*.yml")):
        ceiling = (
            MAX_TIMEOUT_MINUTES
            if path == WORKFLOW
            else MAX_TIMEOUT_MINUTES_OTHER_WORKFLOWS
        )
        doc = yaml.safe_load(path.read_text())
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

    print("coverage — every job reaches the required status check")
    defined = set(jobs) - {"ci"}
    declared = set(jobs["ci"]["needs"])
    check(
        "`ci` depends on every job the workflow defines",
        defined == declared,
        f"missing {sorted(defined - declared)}, unknown {sorted(declared - defined)}",
    )

    print(
        "zero-test — a filtered test selection that matches nothing must exit non-zero"
    )
    for job_id in sorted(jobs):
        for step in jobs[job_id].get("steps", []):
            for line in logical_lines(step.get("run") or ""):
                if line.startswith("cargo test "):
                    filters = positional_filters(line)
                    check(
                        f"{job_id}: {line[:58]}",
                        not filters,
                        f"test-name filter {filters} — `cargo test` exits 0 when its filter "
                        f"selects nothing; use `cargo nextest run --no-tests=fail -E 'test(name)'`",
                    )
                if "cargo nextest run" in line and (
                    " -E " in line or positional_filters(line)
                ):
                    check(
                        f"{job_id}: {line[:58]}",
                        "--no-tests=fail" in line,
                        "a filtered nextest selection must set --no-tests=fail, which exits 4 "
                        "when the selection is empty",
                    )

    rust_only = {
        "rust": "true",
        "python": "false",
        "typescript": "false",
        "typescript-wasm": "false",
        "scaffold-typescript-web": "false",
        "kotlin": "false",
        "swift": "false",
        "fuzz": "false",
    }
    docs_only = dict.fromkeys(rust_only, "false")

    print("rust-fanout — a Rust-only change runs the binding test jobs")
    for job_id in (
        "python-test",
        "typescript-check",
        "kotlin-test",
        "swift-build-test",
    ):
        condition = str(jobs[job_id].get("if"))
        check(
            f"{job_id} runs when only crates/ changed",
            aggregate.evaluate(condition, rust_only, "pull_request"),
            f"if: {condition}",
        )

    print("skip — the aggregate separates a skipped dependency from a passing one")

    needs = build_needs(jobs, rust_only, "pull_request", aggregate)
    code, out = run_aggregate(needs, "pull_request")
    check("Rust-only change, every selected job passed -> exit 0", code == 0, out)

    needs = build_needs(jobs, rust_only, "pull_request", aggregate)
    for job_id in (
        "python-test",
        "typescript-check",
        "kotlin-test",
        "swift-build-test",
    ):
        needs[job_id]["result"] = "skipped"
    code, out = run_aggregate(needs, "pull_request")
    check("Rust-only change, four binding jobs skipped -> exit 1", code == 1, out)
    for job_id in (
        "python-test",
        "typescript-check",
        "kotlin-test",
        "swift-build-test",
    ):
        check(f"  and the failure names {job_id}", job_id in out, out)

    needs = build_needs(jobs, docs_only, "pull_request", aggregate)
    code, out = run_aggregate(needs, "pull_request")
    check("docs-only change, filtered jobs skipped -> exit 0", code == 0, out)

    needs = build_needs(jobs, docs_only, "pull_request", aggregate)
    needs["error-codes"]["result"] = "skipped"
    code, out = run_aggregate(needs, "pull_request")
    check("an unconditional job skipped -> exit 1", code == 1, out)

    # CLAUDE.md §PRD stories states that CI enforces scripts/validate-prd.py.
    # These two cases are what makes that sentence true: the job carries no
    # `if:`, so every event selects it, and the gate rejects both a skip and a
    # failure. A docs-only pull request is the vector that changes a PRD.
    needs = build_needs(jobs, docs_only, "pull_request", aggregate)
    check(
        "prd-validate runs on a pull request that changes nothing else",
        needs["prd-validate"]["result"] == "success",
        f"if: {jobs['prd-validate'].get('if')}",
    )
    needs["prd-validate"]["result"] = "skipped"
    code, out = run_aggregate(needs, "pull_request")
    check("prd-validate skipped -> exit 1", code == 1 and "prd-validate" in out, out)

    needs = build_needs(jobs, docs_only, "pull_request", aggregate)
    needs["prd-validate"]["result"] = "failure"
    code, out = run_aggregate(needs, "pull_request")
    check("prd-validate failed -> exit 1", code == 1 and "prd-validate" in out, out)

    needs = build_needs(jobs, docs_only, "pull_request", aggregate)
    needs["shipped-feature-graph"]["result"] = "failure"
    code, out = run_aggregate(needs, "pull_request")
    check("a job failed -> exit 1", code == 1, out)

    needs = build_needs(jobs, docs_only, "pull_request", aggregate)
    needs["rust-test"]["result"] = "cancelled"
    code, out = run_aggregate(needs, "pull_request")
    check("a job was cancelled -> exit 1", code == 1, out)

    needs = build_needs(jobs, rust_only, "pull_request", aggregate)
    needs["changes"] = {"result": "failure", "outputs": {}}
    for job_id in ("rust-clippy", "rust-fmt", "python-test", "typescript-check"):
        needs[job_id]["result"] = "skipped"
    code, out = run_aggregate(needs, "pull_request")
    check("the filter job failed and its dependants skipped -> exit 1", code == 1, out)

    needs = build_needs(jobs, docs_only, "push", aggregate)
    code, out = run_aggregate(needs, "push")
    check("push event, the pull-request-only job skipped -> exit 0", code == 0, out)

    # merge_group is the event the merge queue runs, so it is the event that
    # actually gates a merge. cross-layer skips there because it diffs against a
    # pull request's base branch, and no other job may.
    needs = build_needs(jobs, rust_only, "merge_group", aggregate)
    code, out = run_aggregate(needs, "merge_group")
    check("merge_group event, a Rust change -> exit 0", code == 0, out)

    needs = build_needs(jobs, rust_only, "merge_group", aggregate)
    needs["rust-test"]["result"] = "skipped"
    code, out = run_aggregate(needs, "merge_group")
    check("merge_group event, the workspace test job skipped -> exit 1", code == 1, out)

    needs = build_needs(jobs, docs_only, "pull_request", aggregate)
    needs["cross-layer"]["result"] = "skipped"
    code, out = run_aggregate(needs, "pull_request")
    check(
        "pull_request event, the pull-request-only job skipped -> exit 1",
        code == 1,
        out,
    )

    needs = build_needs(jobs, docs_only, "pull_request", aggregate)
    for entry in needs.values():
        entry["result"] = "skipped"
    needs["changes"]["outputs"] = docs_only
    code, out = run_aggregate(needs, "pull_request")
    check("draft pull request, every job skipped -> exit 0", code == 0, out)

    needs = build_needs(jobs, docs_only, "pull_request", aggregate)
    needs.pop("wasm-test")
    code, out = run_aggregate(needs, "pull_request")
    check("a job missing from the dependency list -> exit 1", code == 1, out)

    print(f"\n{checks - len(failures)} of {checks} assertions passed")
    if failures:
        print("failed: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
