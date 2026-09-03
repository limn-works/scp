#!/usr/bin/env python3.12
"""Fail when a document cites a spec section that its spec file does not contain.

CRITERION
    Every `§N.M` citation in a governing artifact names a heading that exists in
    `.docs/specs/N-*.md`, or the citing file declares the citation dead by writing the
    reference once followed by the literal marker `[no such section]`.

    `.docs/standards/concrete-prose.md` states the rule this check enforces: "Name the
    thing first, then give the identifier so the reader can find it." A number that
    resolves to nothing leaves the reader unable to decide whether the spec lost the
    section or the author invented it. `.docs/lessons/bad-prose-and-its-rewrite.md`
    records the citation that prompted this check: §18.11.13.2 of the addressability and
    deployment spec, which `main` does not carry. An unmerged branch proposes that
    section, so the agent who wrote the citation was reading a draft, and every reader
    who opened the merged spec afterwards found nothing there.

WHAT THE CHECK READS
    The files that tell an agent how to write and how to work: `.docs/standards/`,
    `.docs/lessons/`, `.claude/agents/`, and `CLAUDE.md`. A citation counts when its
    leading number names a spec file — `§18.11.3` names
    `.docs/specs/18-addressability-and-deployment.md`. A number that names no spec file
    is not an SCP spec citation, so the check skips it, and so are citations the line
    attributes to an outside document (RFC, ISO, BEP, an IETF draft).

WHAT THE CHECK DOES NOT READ, AND WHY
    `.docs/specs/`, `.docs/adrs/`, `.docs/prds/`, and the dated plans and planning
    sessions carried 56 dead citations on the day this check landed: §6.2.2B at 23 sites
    and §6.2.2A at 3, which name subsections that spec 6 never split out of §6.2.2,
    protocol-level discovery; §6.4 at 11 sites, which names a section spec 6 does not
    have; §5.14.13 at 8 sites, the broadcast hosting handshake that ADR-049,
    actor-per-context, withdrew on 2026-06-25; and §1.1 at 3 sites. Repointing §6.2.2B
    takes an author's decision about what spec 6 should say, and inventing a target is
    the defect this check exists to catch, so widening SCOPE_DIRS waits on that spec
    work rather than on an exemption list. Widen it by adding the directory here once
    its citations resolve — this check carries no per-site allowlist and gets none.

USAGE
    python3.12 scripts/check-doc-citations.py [--self-test]

    --self-test builds a scratch tree holding one resolving citation, one dead citation,
    one dead citation carrying the marker, one RFC citation, and one citation to a
    number that names no spec file. It then asserts the scanner reports exactly the
    unmarked dead one. Run it before the real scan: a scanner that reports nothing on a
    tree with a planted defect proves nothing about the tree it scans next.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

# A citation: § followed by a spec number, then one or more dotted parts.
CITATION = re.compile(r"§(\d+(?:\.[0-9A-Za-z]+)+)")
# A heading that opens a numbered section: "### 18.11.3 Feed Endpoint".
HEADING = re.compile(r"^#+\s+(\d+(?:\.[0-9A-Za-z]+)*)[.:]?\s")
# An outside document named just before the §, so the § belongs to that document.
FOREIGN = re.compile(
    r"(RFC\s*\d+|ISO\s*[\d\-:]+|BEP\s*\d+|draft-[a-z0-9\-]+)\s*$", re.IGNORECASE
)
MARKER = "[no such section]"

# Positive scope: the artifacts that govern work in this repository.
SCOPE_DIRS = (".docs/standards", ".docs/lessons", ".claude/agents")
SCOPE_FILES = ("CLAUDE.md",)


def spec_files(root: Path) -> dict[str, Path]:
    """Map a leading spec number to the spec file that carries it."""
    found: dict[str, Path] = {}
    for path in sorted((root / ".docs" / "specs").glob("*.md")):
        match = re.match(r"(\d+)-", path.name)
        if match:
            found[match.group(1).lstrip("0") or "0"] = path
    return found


def headings(path: Path) -> set[str]:
    """Collect every numbered heading a spec file defines."""
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = HEADING.match(line)
        if match:
            out.add(match.group(1).rstrip("."))
    return out


def scan_files(root: Path) -> list[Path]:
    """List every file the scope covers."""
    out: list[Path] = []
    for rel in SCOPE_DIRS:
        base = root / rel
        if base.is_dir():
            out.extend(sorted(p for p in base.rglob("*.md") if p.is_file()))
    for rel in SCOPE_FILES:
        path = root / rel
        if path.is_file():
            out.append(path)
    return out


def scan(root: Path) -> list[tuple[Path, int, str]]:
    """Return every dead citation the scope contains, as (file, line, reference)."""
    specs = spec_files(root)
    heading_cache: dict[str, set[str]] = {}
    failures: list[tuple[Path, int, str]] = []

    for path in scan_files(root):
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            for match in CITATION.finditer(line):
                ref = match.group(1).rstrip(".")
                top = ref.split(".")[0].lstrip("0") or "0"
                if top not in specs:
                    continue
                if FOREIGN.search(line[: match.start()]):
                    continue
                if top not in heading_cache:
                    heading_cache[top] = headings(specs[top])
                if ref in heading_cache[top]:
                    continue
                if f"§{ref} {MARKER}" in text:
                    continue
                failures.append((path, number, ref))
    return failures


SELF_TEST_SPEC = """# 18. Addressability and Deployment

## 18.11 HTTP Broadcast Projection

### 18.11.3 Feed Endpoint

Returns JSON.
"""

SELF_TEST_GOOD = """The feed endpoint of the addressability and deployment spec, §18.11.3, serves JSON.
MLS Welcome message (RFC 9420 §12.4.3.1) carries the group secrets.
Story SCP-046 lands in §99.1 of a spec this repository does not carry.
The passage cites §18.11.13.2 [no such section], which this scratch spec does not carry.
"""

SELF_TEST_BAD = """The addressability and deployment spec says, in §18.11.99, that a verifier reads JSON.
"""


def self_test() -> int:
    """Prove the scanner reports a planted dead citation and nothing else."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        specs = root / ".docs" / "specs"
        specs.mkdir(parents=True)
        (specs / "18-addressability-and-deployment.md").write_text(SELF_TEST_SPEC)
        lessons = root / ".docs" / "lessons"
        lessons.mkdir(parents=True)
        (lessons / "good.md").write_text(SELF_TEST_GOOD)
        (lessons / "bad.md").write_text(SELF_TEST_BAD)

        failures = scan(root)
        got = sorted((f.name, ref) for f, _, ref in failures)
        want = [("bad.md", "18.11.99")]
        if got != want:
            print(f"SELF-TEST FAILED: expected {want}, scanner reported {got}")
            return 1
    print("SELF-TEST PASSED: the scanner reports a planted dead citation and skips")
    print(
        "  a resolving citation, an RFC citation, a non-spec number, and a marked one."
    )
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    root = Path(__file__).resolve().parent.parent
    failures = scan(root)
    if not failures:
        print(
            "check-doc-citations: every spec citation in the governing artifacts resolves."
        )
        return 0

    print(
        "check-doc-citations: these citations name a section their spec file does not contain."
    )
    print(
        "Fix the number, or, when the file quotes a dead citation as evidence, write the"
    )
    print(f"reference once followed by the literal marker `{MARKER}`.\n")
    for path, line, ref in failures:
        print(f"  {path.relative_to(root)}:{line}: §{ref}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
