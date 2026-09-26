#!/usr/bin/env python3
"""Print the cargo feature list `ci.yml`'s `rust-test` job passes to its workspace nextest run.

WHY IT EXISTS. `.github/workflows/compile-timings.yml` measures the cold compile of the
graph that job builds, so it needs that job's feature list. A copy of the list in the
timings workflow would name one list in two files, and the authoritative one lives in a
file the timings workflow does not own, so a change there would leave the timings job
measuring a different graph while still reading as correct.
`.docs/lessons/route-a-changed-file-to-every-lane-it-decides.md` names that failure.

WHY IT PARSES RATHER THAN GREPS. The first version of this matched the literal text
`cargo nextest run --workspace --features `, which identifies a flag order rather than an
invocation. Cargo accepts those flags in any order, and the sharded form of that job reads
`cargo nextest run --workspace --no-tests=fail --partition count:N/4 --features …`, which
the adjacency pattern misses entirely. Dropping `--features` from the pattern fails the
other way: `ci.yml` holds prose describing that command as well as the command, and a text
scan of one file cannot tell a sentence about a command from the command.

The criterion this script applies: a line inside the `run:` script of the named job that
invokes `cargo nextest run` over `--workspace` and carries `--features`. Reading the job's
`run:` blocks through a YAML parser drops every YAML comment, and skipping lines that open
with `#` drops every shell comment, so only the script's own commands remain. The feature
list is the token after `--features`, wherever in the line that flag sits.

It exits non-zero when the job holds no such line or more than one, so a rename, a second
workspace invocation, or a restructured job stops the caller rather than silently changing
which graph it measures.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

import yaml

JOB = "rust-test"
WORKFLOW = Path(".github/workflows/ci.yml")


def run_scripts(job: dict) -> list[str]:
    """Return the `run:` script of every step in the job."""
    return [step["run"] for step in job.get("steps", []) if isinstance(step, dict) and "run" in step]


def logical_lines(script: str) -> list[str]:
    """Return the script's lines with backslash continuations joined into one line each.

    A shell command may wrap, and this matcher reads one command per line, so a wrapped
    invocation has to be rejoined before the match rather than missed by it.
    """
    joined: list[str] = []
    pending = ""
    for raw in script.splitlines():
        stripped = raw.strip()
        if stripped.endswith("\\"):
            pending += stripped[:-1].rstrip() + " "
            continue
        joined.append(pending + stripped)
        pending = ""
    if pending:
        joined.append(pending.rstrip())
    return joined


def invocation_lines(scripts: list[str]) -> list[str]:
    """Return the command lines that invoke nextest over the whole workspace with features."""
    found = []
    for script in scripts:
        for line in logical_lines(script):
            if line.startswith("#"):
                continue
            if "cargo nextest run" in line and "--workspace" in line and "--features" in line:
                found.append(line)
    return found


def features_of(line: str) -> str:
    """Return the argument the line passes to `--features`."""
    # `shlex` keeps `${{ matrix.shard }}` intact as one token per word, which is enough:
    # this only needs the token that follows `--features`.
    tokens = shlex.split(line, posix=False)
    index = tokens.index("--features")
    if index + 1 >= len(tokens):
        raise SystemExit(f"{WORKFLOW}: `--features` ends the line and names no features")
    return tokens[index + 1]


SELF_TEST_CASES = [
    (
        "the shape ci.yml carries today",
        "cargo nextest run --workspace --features a/x,b/y\n",
        "a/x,b/y",
    ),
    (
        "flags between --workspace and --features, which a sharded job adds",
        "cargo nextest run --workspace --no-tests=fail "
        "--partition count:${{ matrix.shard }}/4 --features a/x,b/y\n",
        "a/x,b/y",
    ),
    (
        "--features before --workspace",
        "cargo nextest run --features a/x,b/y --workspace\n",
        "a/x,b/y",
    ),
    (
        "a shell comment naming the command does not count as the command",
        "# cargo nextest run --workspace --features stale/list\n"
        "cargo nextest run --workspace --features a/x,b/y\n",
        "a/x,b/y",
    ),
    (
        "a narrow -p invocation alongside the workspace one does not count",
        "cargo nextest run --workspace --features a/x,b/y\n"
        "cargo nextest run -p scp-transport --features quic\n",
        "a/x,b/y",
    ),
    (
        "the invocation wrapped across lines with backslash continuations",
        "cargo nextest run --workspace \\\n  --no-tests=fail \\\n  --features a/x,b/y\n",
        "a/x,b/y",
    ),
]

SELF_TEST_REJECTS = [
    ("no workspace invocation at all", "cargo nextest run -p scp-transport --features quic\n"),
    (
        "two workspace invocations carrying features",
        "cargo nextest run --workspace --features a/x\n"
        "cargo nextest run --workspace --features b/y\n",
    ),
    ("a workspace invocation naming no features", "cargo nextest run --workspace\n"),
]


def self_test() -> None:
    """Check the criterion against shapes a future ci.yml could take. Prints and exits."""
    failures = 0
    for name, script, expected in SELF_TEST_CASES:
        document = {"jobs": {JOB: {"steps": [{"run": script}]}}}
        lines = invocation_lines(run_scripts(document["jobs"][JOB]))
        got = features_of(lines[0]) if len(lines) == 1 else f"<{len(lines)} matches>"
        ok = got == expected
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'}  {name} -> {got}")
    for name, script in SELF_TEST_REJECTS:
        document = {"jobs": {JOB: {"steps": [{"run": script}]}}}
        lines = invocation_lines(run_scripts(document["jobs"][JOB]))
        ok = len(lines) != 1
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'}  rejects: {name} -> {len(lines)} matches")
    if failures:
        raise SystemExit(f"{failures} self-test case(s) failed")
    print(f"read-workspace-test-features: {len(SELF_TEST_CASES) + len(SELF_TEST_REJECTS)} cases passed")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
        return
    workflow = Path(sys.argv[1]) if len(sys.argv) > 1 else WORKFLOW
    document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    job = document.get("jobs", {}).get(JOB)
    if job is None:
        raise SystemExit(f"{workflow} declares no job named {JOB}")

    lines = invocation_lines(run_scripts(job))
    if len(lines) != 1:
        raise SystemExit(
            f"{workflow} job {JOB} holds {len(lines)} workspace nextest invocations carrying "
            f"`--features`; exactly one is required"
        )
    print(features_of(lines[0]))


if __name__ == "__main__":
    main()
