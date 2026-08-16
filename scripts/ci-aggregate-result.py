#!/usr/bin/env python3
"""Decide whether a `ci` aggregate job passes.

`ci` is one status check this repository's ruleset requires, so `ci` decides
every merge. Before this script, that job compared each dependency's result
against two strings, `failure` and `cancelled`, and let every other value
through, which meant a `skipped` dependency and a `success` dependency produced
one verdict. A path filter that wrongly skipped a job, or a `changes` job that
failed and left every filtered job skipped, therefore reported a green merge
gate over work that never ran.

This script decides, per dependency, whether that dependency was SUPPOSED to
run, and requires `success` from every dependency that was. It reads that
supposed-to-run answer out of a workflow file itself — it evaluates each job's
own `if:` expression against a `changes` job's published filter outputs — so
no answer can drift away from a workflow, as a second hand-maintained copy of
a job list drifts.

Inputs:
  NEEDS_JSON         `toJSON(needs)` from a `ci` job: a map of job id to
                     {"result": ..., "outputs": {...}}.
  GITHUB_EVENT_NAME  whichever event triggered this run.
  argv[1]            path to a workflow file (default .github/workflows/ci.yml).

Exit 0: every dependency that was supposed to run reported success.
Exit 1: a dependency failed, was cancelled, or skipped when it was supposed to
        run; or a workflow and this aggregate disagree about a job list.
Exit 2: a workflow carries an `if:` expression this evaluator cannot read.
        Teach this evaluator that construct — do NOT silence a job.
"""

from __future__ import annotations

import json
import os
import re
import sys

import yaml

AGGREGATE_JOB = "ci"
DRAFT_GATE_JOB = "check-draft"
FILTER_JOB = "changes"

# Literal operands this evaluator understands to a right of `==`.
_QUOTED = re.compile(r"^'([^']*)'$")


class Unreadable(Exception):
    """A workflow uses an `if:` construct this evaluator does not implement."""


def resolve_operand(token: str, outputs: dict[str, str], event_name: str) -> str:
    """Return a value from one side of a comparison, as a string."""
    token = token.strip()
    quoted = _QUOTED.match(token)
    if quoted:
        return quoted.group(1)
    if token in ("true", "false"):
        return token
    if token == "github.event_name":
        return event_name
    prefix = "needs.changes.outputs."
    if token.startswith(prefix):
        return str(outputs.get(token[len(prefix) :], ""))
    raise Unreadable(f"operand {token!r}")


def evaluate(expression: str, outputs: dict[str, str], event_name: str) -> bool:
    """Evaluate a disjunction of equality comparisons.

    Grammar accepted here is exactly what this workflow uses today: one or
    more `LHS == RHS` comparisons joined by `||`. Anything else raises
    Unreadable, so a new construct stops this gate instead of being guessed at.
    """
    expression = " ".join(expression.split())
    if "&&" in expression or "!" in expression or "(" in expression:
        raise Unreadable(f"expression {expression!r}")
    for clause in expression.split("||"):
        if "!=" in clause:
            raise Unreadable(f"clause {clause!r}")
        parts = clause.split("==")
        if len(parts) != 2:
            raise Unreadable(f"clause {clause!r}")
        left = resolve_operand(parts[0], outputs, event_name)
        right = resolve_operand(parts[1], outputs, event_name)
        if left == right:
            return True
    return False


def main() -> int:
    workflow_path = sys.argv[1] if len(sys.argv) > 1 else ".github/workflows/ci.yml"
    with open(workflow_path, encoding="utf-8") as handle:
        workflow = yaml.safe_load(handle)
    jobs = workflow["jobs"]

    needs = json.loads(os.environ["NEEDS_JSON"])
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")

    failures: list[str] = []

    # Drift guard. Every job a workflow defines must be a dependency of this
    # aggregate, or that job's failure never reaches a merge gate. Three
    # enforcement jobs (pyi-generated, construction-pattern, block-in-place)
    # were missing from a dependency list when this guard was written.
    defined = set(jobs) - {AGGREGATE_JOB}
    declared = set(needs)
    if defined != declared:
        for job in sorted(defined - declared):
            failures.append(
                f"{job}: defined in {workflow_path} but not a dependency of `{AGGREGATE_JOB}`"
            )
        for job in sorted(declared - defined):
            failures.append(
                f"{job}: a dependency of `{AGGREGATE_JOB}` but not defined in {workflow_path}"
            )
        for line in failures:
            print(f"::error::{line}")
        return 1

    draft_result = needs[DRAFT_GATE_JOB]["result"]
    if draft_result == "skipped":
        print(
            f"`{DRAFT_GATE_JOB}` skipped: this pull request is a draft, so no CI job ran. "
            "GitHub blocks merging a draft, and a merge queue re-runs this workflow on "
            "a merge_group event, where this gate does apply."
        )
        return 0
    if draft_result != "success":
        print(
            f"::error::{DRAFT_GATE_JOB}: {draft_result} (this gate cannot trust any other result)"
        )
        return 1

    filter_result = needs[FILTER_JOB]["result"]
    if filter_result != "success":
        print(
            f"::error::{FILTER_JOB}: {filter_result} — every path-filtered job skips when "
            "a filter job does not publish its outputs, so no other result is trustworthy"
        )
        return 1
    outputs = needs[FILTER_JOB].get("outputs") or {}

    for job_id in sorted(defined - {DRAFT_GATE_JOB, FILTER_JOB}):
        result = needs[job_id]["result"]
        condition = jobs[job_id].get("if")
        try:
            expected_to_run = (
                True
                if condition is None
                else evaluate(str(condition), outputs, event_name)
            )
        except Unreadable as unreadable:
            print(
                f"::error::{job_id}: this gate cannot read its `if:` condition ({unreadable}). "
                "Add that construct to scripts/ci-aggregate-result.py — a condition this gate "
                "cannot read is a job whose skip it cannot judge."
            )
            return 2
        if result in ("failure", "cancelled"):
            failures.append(f"{job_id}: {result}")
        elif expected_to_run and result != "success":
            failures.append(
                f"{job_id}: {result} — its condition selected it to run "
                f"(if: {condition or 'always'}), so a non-success result is a gap in coverage"
            )

    if failures:
        for line in failures:
            print(f"::error::CI dependency did not pass: {line}")
        return 1

    ran = sum(1 for job_id in defined if needs[job_id]["result"] == "success")
    print(
        f"{ran} of {len(defined)} CI jobs succeeded; every job its condition selected reported success."
    )
    for job_id in sorted(defined):
        print(f"  {needs[job_id]['result']:>9}  {job_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
