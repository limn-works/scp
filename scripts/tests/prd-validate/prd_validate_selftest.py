#!/usr/bin/env python3
"""Self-test for scripts/validate-prd.py.

CLAUDE.md tells every agent to run this validator before committing a PRD change
and states that CI enforces it. No workflow ran it: the only reference lived in
.github/workflows/prd-validate.yml.disabled, and GitHub never loads a file with
that suffix. Commit fffd5de56 renamed seven workflows to `.disabled` on
2026-03-15 under the heading "disable all Claude-powered GitHub workflows"; this
validator is a plain Python script that reaches no model and needs no secret,
and it was swept up because it shared a file with a Claude review step.

Before wiring the validator into ci.yml, this self-test proves it rejects each
violation class it claims to catch. A gate nobody has ever seen fail is a gate
nobody has tested. Each case plants one violation in a scratch copy of `.docs`
and asserts the validator exits non-zero and names the story.

Run: python3 scripts/tests/prd-validate/prd_validate_selftest.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
VALIDATOR = "scripts/validate-prd.py"

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


def drop_required_field(story, prd):
    story.pop("acceptanceCriteria", None)
    return "missing required field"


def invalid_status(story, prd):
    story["status"] = "shipped"
    return "invalid status"


def missing_source_file(story, prd):
    story["sources"] = [
        {"file": ".docs/specs/no-such-spec-file.md", "section": "## Nothing"}
    ]
    return "source file does not exist"


def missing_source_section(story, prd):
    for candidate in prd["stories"]:
        if candidate.get("sources"):
            candidate["sources"][0]["section"] = "## A Heading No Artifact Contains"
            return "source section not found"
    raise AssertionError("no story in this PRD carries a source to mutate")


def unknown_dependency(story, prd):
    story["blockedBy"] = ["SCP-NOSUCHSTORY-999"]
    return "blockedBy references non-existent story"


def unknown_gate(story, prd):
    story["gate"] = "gate-that-does-not-exist"
    return "references non-existent gate"


MUTATIONS = [
    ("a story missing a required field", drop_required_field),
    ("a status the standard does not define", invalid_status),
    ("a source pointing at a file that does not exist", missing_source_file),
    ("a source pointing at a heading that does not exist", missing_source_section),
    ("a dependency on a story ID that does not exist", unknown_dependency),
    ("a story assigned to a gate that does not exist", unknown_gate),
]


def run_validator(cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, VALIDATOR],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="prd-validate-selftest-"))
    try:
        shutil.copytree(REPO / ".docs", work / ".docs")
        shutil.copytree(REPO / "scripts", work / "scripts")

        print("the validator accepts the tree as it stands")
        clean = run_validator(work)
        check(
            "an unmutated tree passes",
            clean.returncode == 0,
            clean.stdout + clean.stderr,
        )
        # A validator that walked zero stories would also exit 0, which is the
        # shape of a gate that enforces nothing. Assert it walked the corpus.
        check(
            "and reports the story count it walked",
            "stories" in clean.stdout and "0 stories" not in clean.stdout,
            clean.stdout.strip(),
        )

        target = work / ".docs/prds/adr062-capability-injection.json"
        original = target.read_text()

        print("the validator rejects each violation it claims to catch")
        for name, mutate in MUTATIONS:
            prd = json.loads(original)
            expected = mutate(prd["stories"][0], prd)
            target.write_text(json.dumps(prd, indent=2))
            result = run_validator(work)
            check(
                f"{name} -> non-zero exit",
                result.returncode != 0,
                result.stdout + result.stderr,
            )
            check(
                f"  and the message says {expected!r}",
                expected in result.stdout,
                result.stdout.strip()[:400],
            )
            target.write_text(original)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print(f"\n{checks - len(failures)} of {checks} assertions passed")
    if failures:
        print("failed: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
