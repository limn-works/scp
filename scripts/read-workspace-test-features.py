#!/usr/bin/env python3
"""Print the canonical cargo feature list of `ci.yml`'s `rust-test` job.

WHY IT EXISTS. `.github/workflows/compile-timings.yml` measures the cold compile of the
workspace test graph, so it needs the feature list that graph resolves under. A copy of the
list in the timings workflow would name one list in two files, and the authoritative one
lives in a file the timings workflow does not own, so a change there would leave the timings
job measuring a different graph while still reading as correct.
`.docs/lessons/route-a-changed-file-to-every-lane-it-decides.md` names that failure.

WHERE THE LIST LIVES. Job rust-test runs one `cargo nextest run -p ...` command per package
shard, and no shard command passes the whole list, because cargo accepts `--features
pkg/feature` only for a selected package or a dependency of one. The job's `env:` holds the
list as `TEST_FEATURES`: the feature list of the `cargo nextest run --workspace` command the
shards replaced, and the canonical resolution `scripts/check-test-shard-features.py` holds
each shard's selected packages to. This script prints that value.

It reads the workflow through a YAML parser, so a comment naming a stale list does not
count. It exits non-zero when the job is absent, when the job sets no `TEST_FEATURES`, or
when the value is not one comma-separated list of `package/feature` items, so a rename or a
restructured job stops the caller rather than silently changing which graph it measures.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

JOB = "rust-test"
WORKFLOW = Path(".github/workflows/ci.yml")


FEATURE_LIST = re.compile(
    r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+(,[A-Za-z0-9_-]+/[A-Za-z0-9_-]+)*"
)


def test_features(document: dict) -> str:
    """Return the rust-test job's `env.TEST_FEATURES`, or exit naming what is wrong."""
    job = (document.get("jobs") or {}).get(JOB)
    if not isinstance(job, dict):
        raise SystemExit(f"{WORKFLOW} declares no job named {JOB}")
    value = (job.get("env") or {}).get("TEST_FEATURES")
    if value is None:
        raise SystemExit(f"{WORKFLOW} job {JOB} sets no `env.TEST_FEATURES`")
    value = str(value).strip()
    if not FEATURE_LIST.fullmatch(value):
        raise SystemExit(
            f"{WORKFLOW} job {JOB} sets `TEST_FEATURES` to {value!r}, which is not one "
            f"comma-separated list of `package/feature` items"
        )
    return value


SELF_TEST_CASES = [
    (
        "the shape ci.yml carries today",
        {"env": {"TEST_FEATURES": "a/x,b/y"}},
        "a/x,b/y",
    ),
    (
        "a shard command beside the env value does not change the answer",
        {
            "env": {"TEST_FEATURES": "a/x,b/y"},
            "steps": [{"run": "cargo nextest run --no-tests=fail -p a --features a/z"}],
        },
        "a/x,b/y",
    ),
]

SELF_TEST_REJECTS = [
    (
        "no env block",
        {"steps": [{"run": "cargo nextest run --workspace --features a/x"}]},
    ),
    ("an empty value", {"env": {"TEST_FEATURES": ""}}),
    (
        "a value holding a shell expansion",
        {"env": {"TEST_FEATURES": "a/x,${{ matrix.leg }}"}},
    ),
    ("a value with a space", {"env": {"TEST_FEATURES": "a/x, b/y"}}),
]


def self_test() -> None:
    """Check the reader against shapes a future ci.yml could take. Prints and exits."""
    failures = 0
    for name, job, expected in SELF_TEST_CASES:
        try:
            got = test_features({"jobs": {JOB: job}})
        except SystemExit as error:
            got = f"<rejected: {error}>"
        ok = got == expected
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'}  {name} -> {got}")
    for name, job in SELF_TEST_REJECTS:
        try:
            got = test_features({"jobs": {JOB: job}})
            ok = False
        except SystemExit:
            got, ok = "rejected", True
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'}  rejects: {name} -> {got}")
    if failures:
        raise SystemExit(f"{failures} self-test case(s) failed")
    print(
        f"read-workspace-test-features: {len(SELF_TEST_CASES) + len(SELF_TEST_REJECTS)} cases passed"
    )


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
        return
    workflow = Path(sys.argv[1]) if len(sys.argv) > 1 else WORKFLOW
    print(test_features(yaml.safe_load(workflow.read_text(encoding="utf-8"))))


if __name__ == "__main__":
    main()
