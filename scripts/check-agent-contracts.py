#!/usr/bin/env python3.12
"""Fail when an agent definition states no verdict criterion, or leaves its recipe unlabelled.

CRITERION
    Every file in `.claude/agents/` other than `README.md` carries a `## Verdict criterion`
    section holding two things: a line that starts `**Criterion:**` and states, in one
    sentence, what the agent must confirm before it reports a verdict; and a line that
    starts `**Indicators, not the criterion.**` and tells the agent that working the file's
    other sections does not satisfy that criterion.

    `.claude/agents/README.md` states both requirements under "Every agent definition is a
    contract", and `CLAUDE.md` states the rule they serve under "Agent execution rules":
    an agent that receives only a recipe satisfies the recipe and reports success, which is
    how `let _ = function_name;` came to satisfy a string-search test while calling nothing.
    Before this check landed, no agent definition carried the label and 21 of 29 carried no
    criterion, while `CLAUDE.md` said in the present tense that every definition already
    stated one.

USAGE
    python3.12 scripts/check-agent-contracts.py [--self-test]

    --self-test builds a scratch agent directory holding one compliant definition, one
    definition with no criterion section, one whose criterion line is a heading with no
    sentence under it, and one that states a criterion but never labels its recipe. It then
    asserts the checker reports exactly the three defective ones.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

SECTION = "## Verdict criterion"
CRITERION_PREFIX = "**Criterion:**"
LABEL_PREFIX = "**Indicators, not the criterion.**"
# A criterion shorter than this is a heading, not a sentence a reader can apply.
MIN_CRITERION_CHARS = 60


def check_text(text: str) -> list[str]:
    """Return the requirements this definition fails to meet."""
    problems: list[str] = []
    if SECTION not in text:
        problems.append(f"no `{SECTION}` section")
    criterion = ""
    for line in text.splitlines():
        if line.startswith(CRITERION_PREFIX):
            criterion = line[len(CRITERION_PREFIX) :].strip()
            break
    if not criterion:
        problems.append(f"no line starting `{CRITERION_PREFIX}`")
    elif len(criterion) < MIN_CRITERION_CHARS:
        problems.append(
            f"the `{CRITERION_PREFIX}` line holds {len(criterion)} characters, "
            f"fewer than the {MIN_CRITERION_CHARS} a criterion sentence takes"
        )
    if LABEL_PREFIX not in text:
        problems.append(f"no line starting `{LABEL_PREFIX}`")
    return problems


def scan(agents_dir: Path) -> list[tuple[Path, list[str]]]:
    """Return every agent definition that fails a requirement, with the reasons."""
    failures: list[tuple[Path, list[str]]] = []
    for path in sorted(agents_dir.glob("*.md")):
        if path.name == "README.md":
            continue
        problems = check_text(path.read_text(encoding="utf-8"))
        if problems:
            failures.append((path, problems))
    return failures


COMPLIANT = """---
name: good
---

## Verdict criterion

**Criterion:** Report the change complete only after every acceptance criterion has code
you read behind it, and report it incomplete as soon as one criterion has none.

**Indicators, not the criterion.** The sections below tell this agent where to look.

## What You Do

Read the code.
"""

NO_SECTION = """---
name: recipe-only
---

## What You Do

Check for stubs, check for `None`, check the matrix.
"""

EMPTY_CRITERION = """---
name: heading-only
---

## Verdict criterion

**Criterion:** Be thorough.

**Indicators, not the criterion.** The sections below tell this agent where to look.
"""

NO_LABEL = """---
name: unlabelled-recipe
---

## Verdict criterion

**Criterion:** Report the change secure only after you have followed every untrusted value
from its entry point to the place that consumes it.

## Review Dimensions

Injection, secrets, authorization.
"""


def self_test() -> int:
    """Prove the checker reports each planted defect and passes the compliant file."""
    with tempfile.TemporaryDirectory() as tmp:
        agents = Path(tmp)
        (agents / "README.md").write_text("An agent file must state its criterion.")
        (agents / "good.md").write_text(COMPLIANT)
        (agents / "no-section.md").write_text(NO_SECTION)
        (agents / "empty-criterion.md").write_text(EMPTY_CRITERION)
        (agents / "no-label.md").write_text(NO_LABEL)

        got = sorted(path.name for path, _ in scan(agents))
        want = ["empty-criterion.md", "no-label.md", "no-section.md"]
        if got != want:
            print(f"SELF-TEST FAILED: expected {want}, checker reported {got}")
            return 1
    print(
        "SELF-TEST PASSED: the checker reports a missing section, a criterion too short"
    )
    print("  to apply, and an unlabelled recipe, and passes a compliant definition.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    root = Path(__file__).resolve().parent.parent
    agents = root / ".claude" / "agents"
    failures = scan(agents)
    if not failures:
        count = len([p for p in agents.glob("*.md") if p.name != "README.md"])
        print(
            f"check-agent-contracts: all {count} agent definitions state a verdict criterion"
        )
        print("  and label their remaining sections as indicators.")
        return 0

    print(
        "check-agent-contracts: these agent definitions do not meet the contract that"
    )
    print(
        "`.claude/agents/README.md` states under 'Every agent definition is a contract'.\n"
    )
    for path, problems in failures:
        print(f"  {path.relative_to(root)}:")
        for problem in problems:
            print(f"    - {problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
