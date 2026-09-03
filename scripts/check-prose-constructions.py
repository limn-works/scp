#!/usr/bin/env python3.12
"""Require every forbidden-construction entry in the prose standard to state a criterion.

`.docs/standards/concrete-prose.md` makes a seven-question self-check mandatory
before a writer sends any sentence, and one of those questions asks whether the
sentence uses any of the forbidden constructions. A writer can answer that
question only for an entry that states what decides membership. An entry that
states a label and nothing else, or a label and one quoted example, gives the
writer no test, so the question answers no by default and the check reports
clean on a sentence the list intends to reject.

The commit titled "docs(claude): drop the examples for introductory patterns and
hedging" deleted the criterion text from two entries on the grounds that "both
names carry their meaning without an instance". Six of the eleven entries
reached `main` stating a label, a quoted example, or a fill-in template, and no
test a writer could apply. This check makes each of those six shapes fail the
build.

It asserts five properties of the list, and carries no per-entry allowlist:

  1. The lead-in line exists and names the entry count in words.
  2. The entries are numbered 1..N with no gap and no repeat.
  3. N equals the count the lead-in names.
  4. Every entry has the shape `**Name** - <criterion>`, where the criterion
     carries at least MIN_CRITERION_WORDS words that sit outside a multi-word
     quotation. Stripping multi-word quotations is what separates a criterion
     from an entry whose whole body is a quoted example.
  5. The self-check sentence names the same count as the lead-in, so a writer
     who adds a twelfth construction cannot leave the question asking about
     eleven.

Exit code 0 = clean. Exit code 1 = at least one violation.

Run from the repo root:

    python3.12 scripts/check-prose-constructions.py
    python3.12 scripts/check-prose-constructions.py --self-test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STANDARD = REPO_ROOT / ".docs" / "standards" / "concrete-prose.md"

# An entry whose body, once every multi-word quotation is removed, carries
# fewer words than this states an example or a label instead of a test.
MIN_CRITERION_WORDS = 6

NUMBER_WORDS = {
    "One": 1,
    "Two": 2,
    "Three": 3,
    "Four": 4,
    "Five": 5,
    "Six": 6,
    "Seven": 7,
    "Eight": 8,
    "Nine": 9,
    "Ten": 10,
    "Eleven": 11,
    "Twelve": 12,
    "Thirteen": 13,
    "Fourteen": 14,
    "Fifteen": 15,
}

LEAD_IN_RE = re.compile(r"^- \*\*([A-Z][a-z]+) forbidden constructions\.\*\*")
ENTRY_RE = re.compile(r"^ {2}(\d+)\. \*\*(.+?)\*\*(.*)$")
SELF_CHECK_RE = re.compile(r"^- \*\*Check every sentence before you send it\.\*\*")
SELF_CHECK_COUNT_RE = re.compile(r"any of the ([a-z]+) forbidden constructions")
# A quotation of two or more words. A single-word quotation, such as the "the"
# in the smuggled-definite-article entry, stays in the word count because the
# surrounding prose is doing the defining.
MULTI_WORD_QUOTE_RE = re.compile(r"\"[^\"]*\s[^\"]*\"")

EM_DASH_SEPARATOR = " — "


def criterion_word_count(body: str) -> int:
    """Count the words of `body` that sit outside a multi-word quotation."""
    stripped = MULTI_WORD_QUOTE_RE.sub(" ", body)
    return len([w for w in re.split(r"\s+", stripped) if any(c.isalpha() for c in w)])


def check_text(text: str, label: str) -> list[str]:
    """Return one diagnostic per violated property. An empty list means clean."""
    violations: list[str] = []
    lines = text.splitlines()

    lead_in_index = None
    declared_word = None
    for i, line in enumerate(lines):
        match = LEAD_IN_RE.match(line)
        if match:
            lead_in_index = i
            declared_word = match.group(1)
            break

    if lead_in_index is None:
        return [
            (
                f"{label}: no line matches "
                "`- **<Count> forbidden constructions.**`; the prose standard "
                "must keep that list and this check must keep finding it"
            )
        ]

    assert declared_word is not None
    declared_count = NUMBER_WORDS.get(declared_word)
    if declared_count is None:
        violations.append(
            f"{label}:{lead_in_index + 1}: the lead-in names the count "
            f'"{declared_word}", which is not a number word this check knows; '
            "add it to NUMBER_WORDS or write a word that is already there"
        )

    entries: list[tuple[int, int, str, str]] = []
    for i in range(lead_in_index + 1, len(lines)):
        line = lines[i]
        match = ENTRY_RE.match(line)
        if not match:
            if line.startswith("  "):
                violations.append(
                    f"{label}:{i + 1}: this indented line sits inside the "
                    "forbidden-construction list and does not match "
                    "`  <n>. **<Name>** - <criterion>`"
                )
                continue
            break
        entries.append((i + 1, int(match.group(1)), match.group(2), match.group(3)))

    if not entries:
        violations.append(f"{label}:{lead_in_index + 1}: the list has no entries")

    for position, (line_no, number, name, body) in enumerate(entries, start=1):
        if number != position:
            violations.append(
                f"{label}:{line_no}: entry {number} sits at position {position}; "
                "the list must run 1..N with no gap and no repeat"
            )
        if not body.startswith(EM_DASH_SEPARATOR):
            violations.append(
                f'{label}:{line_no}: entry {number}, "{name}", states a label and '
                "no criterion; write the name, an em dash, then what decides "
                "membership, then label any examples as indicators"
            )
            continue
        words = criterion_word_count(body[len(EM_DASH_SEPARATOR) :])
        if words < MIN_CRITERION_WORDS:
            violations.append(
                f'{label}:{line_no}: entry {number}, "{name}", carries {words} '
                f"words outside a multi-word quotation, below the "
                f"{MIN_CRITERION_WORDS} this check requires; a quoted example is "
                "an indicator, not the criterion, so state the criterion and "
                "label the example as an indicator"
            )

    if declared_count is not None and len(entries) != declared_count:
        violations.append(
            f"{label}:{lead_in_index + 1}: the lead-in names "
            f'"{declared_word}" constructions and the list holds {len(entries)}'
        )

    self_check_line = None
    self_check_word = None
    for i, line in enumerate(lines):
        if SELF_CHECK_RE.match(line):
            self_check_line = i + 1
            count_match = SELF_CHECK_COUNT_RE.search(line)
            if count_match:
                self_check_word = count_match.group(1)
            break

    if self_check_line is None:
        violations.append(
            f"{label}: no line matches "
            "`- **Check every sentence before you send it.**`; the per-sentence "
            "self-check is what makes the list binding"
        )
    elif self_check_word is None:
        violations.append(
            f"{label}:{self_check_line}: the self-check does not ask about the "
            "forbidden constructions; it must contain "
            '"any of the <count> forbidden constructions"'
        )
    elif declared_word is not None and self_check_word != declared_word.lower():
        violations.append(
            f"{label}:{self_check_line}: the self-check asks about "
            f'"{self_check_word}" forbidden constructions and the list declares '
            f'"{declared_word.lower()}"'
        )

    return violations


CLEAN_FIXTURE = (
    "- **Two forbidden constructions.** Delete it and write the claim.\n"
    "  1. **Comparative definition** — defining the subject by likening it to "
    'another thing: "a b c".\n'
    "  2. **Hedging** — a word that lowers the writer's commitment and names "
    "no evidence.\n"
    "- **Check every sentence before you send it.** Have I used any of the two "
    "forbidden constructions?\n"
)

HEDGING_ENTRY = (
    "  2. **Hedging** — a word that lowers the writer's commitment and names "
    "no evidence."
)


def self_test() -> int:
    """Fail unless the checker rejects each way the list can break."""
    cases: list[tuple[str, str]] = [
        ("bare label", CLEAN_FIXTURE.replace(HEDGING_ENTRY, "  2. **Hedging**.")),
        (
            "quoted example only",
            CLEAN_FIXTURE.replace(
                HEDGING_ENTRY,
                '  2. **Adjective reinforcement** — "sound and bounded".',
            ),
        ),
        (
            "count mismatch",
            CLEAN_FIXTURE.replace("- **Two forbidden", "- **Three forbidden"),
        ),
        (
            "self-check out of sync",
            CLEAN_FIXTURE.replace(
                "any of the two forbidden", "any of the eleven forbidden"
            ),
        ),
        (
            "numbering gap",
            CLEAN_FIXTURE.replace("  2. **Hedging**", "  3. **Hedging**"),
        ),
        (
            "list missing",
            CLEAN_FIXTURE.replace(
                "- **Two forbidden constructions.**", "- **Some rules.**"
            ),
        ),
        (
            "self-check missing",
            CLEAN_FIXTURE.replace(
                "- **Check every sentence before you send it.**",
                "- **Something else.**",
            ),
        ),
        (
            "unknown count word",
            CLEAN_FIXTURE.replace("- **Two forbidden", "- **Umpteen forbidden"),
        ),
    ]

    failures: list[str] = []

    clean = check_text(CLEAN_FIXTURE, "<clean fixture>")
    if clean:
        failures.append(f"the clean fixture must pass, and it reported: {clean}")

    for name, text in cases:
        if not check_text(text, f"<{name}>"):
            failures.append(f'the "{name}" fixture must fail, and it passed')

    if failures:
        print("Self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"OK: self-test passed; the checker rejects {len(cases)} broken lists.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    if not STANDARD.exists():
        print(f"{STANDARD} does not exist", file=sys.stderr)
        return 1

    violations = check_text(STANDARD.read_text(), str(STANDARD.relative_to(REPO_ROOT)))
    if violations:
        print(
            "Forbidden-construction entries that state no criterion "
            "(see scripts/check-prose-constructions.py header):",
            file=sys.stderr,
        )
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    print(
        f"OK: every forbidden-construction entry in "
        f"{STANDARD.relative_to(REPO_ROOT)} states a criterion."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
