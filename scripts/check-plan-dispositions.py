#!/usr/bin/env python3.12
"""Fail where one site name of the identity-substrate plan carries conflicting dispositions.

The plan at `/Users/alec/.claude/plans/identity-substrate-plan.md` gives every
site of a prescribed row's `Today` cell one of four dispositions, and §1's
Fields block states two tests over them.

**Test one — the disposition set.** A site name's dispositions across every row
that names it must be a subset of `{state, cite}`, or exactly `{mirror}`, or
exactly `{delete}`. `state` obliges the site to carry prose, `cite` obliges a
citation and a consequence sentence, `mirror` obliges an include directive and
no prose of its own, and `delete` obliges the text to leave. A site carrying
`mirror` beside `state` is bound by nothing, because a write that satisfies
either breaches the other.

**Test two — the site name's grain.** A site name that more than one row
carries names a position inside a section rather than a section, because a
disposition binds what a reader can find. A bare section name shared by two
rows makes every breach at that section unprovable either way. A `[delete]`
site of a withdrawal row is exempt, because that row's `Rule` cell states what
leaves the named artifact.

The input set is the plan's own enumeration, so the check closes by
construction and admits no new spelling.

Usage:
    python3.12 scripts/check-plan-dispositions.py
    python3.12 scripts/check-plan-dispositions.py --plan /path/to/plan.md
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_PLAN = Path.home() / ".claude" / "plans" / "identity-substrate-plan.md"

ROW = re.compile(r"^\| (I-\d{3}) \|")
DISPOSITION = re.compile(r"\[(state|cite|mirror|delete)\]")
# A site name names a section and nothing inside it when the whole name is a
# section reference: an artifact token, a `§N.M` or an `R<n>` reference, and no
# parenthesis, no trailing noun phrase.
SECTION_ONLY = re.compile(
    r"""^(?:
          \d{2}\s+§[\d.]+(?:\s+R\d+)?          # 09 §9.7.4.2 R9, 03 §3.10.10
        | ADR-\d+                               # ADR-063
        | ADR-\d+'s\s+executor-call\s+register
        | `[^`]+`                               # `.docs/standards/construction.md`
        )$""",
    re.X,
)


def parse(plan_text: str) -> dict[str, dict[str, set[str]]]:
    """Return {site name: {disposition: {row ids}}} over the plan's prescribed rows."""
    sites: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for line in plan_text.split("\n"):
        match = ROW.match(line)
        if match is None:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 7:
            continue
        row_id, today, prescribed = cells[0], cells[4], cells[5]
        if not prescribed.lower().startswith("yes"):
            continue
        for entry in (e.strip() for e in today.split(";")):
            found = DISPOSITION.search(entry)
            if found is None:
                continue
            name = DISPOSITION.sub("", entry).strip()
            sites[name][found.group(1)].add(row_id)
    return sites


def check(sites: dict[str, dict[str, set[str]]]) -> list[str]:
    failures: list[str] = []
    for name, by_disposition in sorted(sites.items()):
        kinds = set(by_disposition)
        permitted = kinds <= {"state", "cite"} or kinds == {"mirror"} or kinds == {"delete"}
        if not permitted:
            rows = sorted({r for ids in by_disposition.values() for r in ids})
            failures.append(
                f"`{name}` carries the disposition set {sorted(kinds)}, which is neither a "
                f"subset of {{state, cite}} nor exactly {{mirror}} nor exactly {{delete}}; "
                f"the rows that name it: {', '.join(rows)}"
            )
        # A `[delete]` site of a withdrawal row may name a whole artifact, because
        # that row's `Rule` cell states what leaves it. §1's Fields block says so.
        if kinds == {"delete"}:
            continue
        rows = {r for ids in by_disposition.values() for r in ids}
        if len(rows) > 1 and SECTION_ONLY.match(name):
            failures.append(
                f"`{name}` is carried by {len(rows)} rows ({', '.join(sorted(rows))}) and names "
                f"a section rather than a position inside one"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", default=str(DEFAULT_PLAN), help="the plan file to read")
    args = parser.parse_args()

    plan = Path(args.plan)
    if not plan.is_file():
        print(
            f"error: no plan at {plan}. The identity-substrate plan lives outside this "
            f"repository, so this check runs where that file is present and names it with "
            f"--plan elsewhere.",
            file=sys.stderr,
        )
        return 2

    sites = parse(plan.read_text(encoding="utf-8"))
    failures = check(sites)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"\n{len(failures)} disposition failures across {len(sites)} site names", file=sys.stderr)
        return 1

    print(f"site names: {len(sites)}")
    print("every site name's disposition set is permitted, and no shared name is a bare section")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
