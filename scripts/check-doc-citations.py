#!/usr/bin/env python3.12
"""Fail when a document cites a spec section that its spec file does not contain.

CRITERION
    Every `§N.M` citation in a governing artifact names a heading that exists in
    `.docs/specs/N-*.md`, or the citation itself declares that it resolves
    to nothing by carrying the literal marker `[no such section]` directly after the
    reference, separated from it by one space. The marker exempts the one occurrence
    whose last character it follows, and exempts no other occurrence: not a second
    occurrence of the same reference further down the file, and not a second occurrence
    on the same line as the marker. A reader who reaches an unmarked occurrence sees no
    marker and goes looking for a section the spec does not carry, whatever a different
    occurrence elsewhere declares. A marker scoped to the line or to the file would let
    one marker launder every unmarked twin in its range, which is the per-site allowlist
    the section below refuses.

    `.docs/standards/concrete-prose.md` states both rules this check enforces: "Name the
    thing first, then give the identifier so the reader can find it", and write a dead
    reference "followed by `[no such section]` on the same line". A number that
    resolves to nothing leaves the reader unable to decide whether the spec lost the
    section or the author invented it. `.docs/lessons/bad-prose-and-its-rewrite.md`
    records the citation that prompted this check: §18.11.13.2 of the addressability and
    deployment spec, which `main` does not carry. An unmerged branch proposes that
    section, so the agent who wrote the citation was reading a draft, and every reader
    who opened the merged spec afterwards found nothing there.

WHAT THE CHECK READS
    The files that tell an agent how to write and how to work: `.docs/standards/`,
    `.docs/lessons/`, `.claude/agents/`, `AGENTS.md`, and the two build blueprints an
    agent reads before it writes a crate — `.docs/scaffold/` and `.docs/architecture.md`.
    It also reads the product specs in `.docs/specs/` and the decision records in
    `.docs/adrs/`, which is the widening the section below reserved.
    A citation counts when its leading number names a spec file — `§18.11.3` names
    `.docs/specs/18-addressability-and-deployment.md`. A number that names no spec file
    is not an SCP spec citation, so the check skips it, and so are citations the line
    attributes to an outside document (RFC, ISO, BEP, an IETF draft).

WHAT THE CHECK CANNOT DECIDE
    Whether the cited section says what the citing sentence claims it says. Spec 10,
    infrastructure and self-hosting, cited §16.4.1 of the test infrastructure spec for
    the contract of a `BlobStore` trait; §16.4.1 heads "StoredBlob" and its body stated
    that the in-memory relay defines no such trait. This check reported that pair green,
    because §16.4.1 is a heading that exists. A reader repairs that defect by opening the
    cited section, so do not read a green run as evidence that a citation points at the
    right section.

WHAT THE CHECK DOES NOT READ, AND WHY
    `.docs/prds/` and the dated plans and planning sessions. A PRD story names its
    sources through a `section` field that `scripts/validate-prd.py` already resolves
    against the spec file, so a second reader of the same field would re-check in weaker
    text-search form a property that check enforces on the parsed story. A dated plan
    records what an author believed on its date, so a citation that resolved then and
    does not resolve now is the record working rather than a defect.

    `.docs/specs/` and `.docs/adrs/` carried 56 dead citations on the day this check
    landed — §6.2.2B at 23 sites, §6.2.2A at 3, §6.4 at 11, §5.14.13 at 8, and §1.1 at
    3 — and this block reserved the widening until they resolved. Each surviving site
    now carries the `[no such section]` marker beside the reference, which is the
    declaration this check asks for and not an exemption: the marker tells a reader the
    number resolves to nothing, and it exempts only the occurrence it follows. This
    check carries no per-site allowlist and gets none.

BARE SCP CODES
    The same files fail on `SCP-` followed directly by digits, at a word boundary,
    unless those digits name a story in `.docs/prds/`. Two registries own an
    identifier that starts with `SCP-`: the PRD story ledger, whose IDs read `SCP-NNN`
    (`SCP-046`), and the SDK error registry in `crates/scp-ffi/common/src/error_codes.rs`,
    whose codes carry a band (`SCP-CAPSEL-8001`). A relay wire code from the error table
    of ADR-004, the SCP native relay protocol, is a bare number with a name (`4061`
    PUSH_PLATFORM_UNAVAILABLE). Prose that writes `SCP-4061` puts a wire code in the
    spelling of the SDK registry, so a reader searches `error_codes.rs` for a code that
    no registry holds. The check resolves the digits against the story ledger, so a
    story reference that names a real story passes, and every other `SCP-<digits>`
    fails, whether its author meant a wire code, dropped an SDK band, or invented a
    story.

USAGE
    python3.12 scripts/check-doc-citations.py [--self-test]

    --self-test builds a scratch tree holding one resolving citation, one dead citation,
    one dead citation carrying the marker, one RFC citation, one citation to a number
    that names no spec file, one file that marks a dead reference on its first line and
    repeats that same reference unmarked on a later line, and one file that marks a dead
    reference and repeats it unmarked on that same line. It then asserts the scanner
    reports exactly the three unmarked dead citations. The two repeats are the cases a
    widened marker passes: a file-wide marker passes the later-line repeat, and a
    line-wide marker passes the same-line repeat, so the self-test goes red if anyone
    widens the marker past the occurrence it follows. Run it before the real scan: a
    scanner that reports nothing on a tree with a planted defect proves nothing about
    the tree it scans next.

    The self-test also plants `SCP-4061` in one file and asserts that the bare-code
    scan reports it and passes `SCP-CAPSEL-8001` and the story reference `SCP-046`,
    which the scratch story ledger declares.
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
# `SCP-` followed directly by digits: a story ID, or a wire code in SDK spelling.
BARE_SCP = re.compile(r"\bSCP-\d+\b")
# A story ID as a PRD file declares it.
STORY_ID = re.compile(r'"id"\s*:\s*"(SCP-\d+)"')

# Positive scope: the artifacts that govern work in this repository.
SCOPE_DIRS = (
    ".docs/standards",
    ".docs/lessons",
    ".claude/agents",
    ".docs/scaffold",
    ".docs/specs",
    ".docs/adrs",
)
SCOPE_FILES = ("AGENTS.md", ".docs/architecture.md")


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


def story_ids(root: Path) -> set[str]:
    """Collect every story ID the PRD files declare."""
    out: set[str] = set()
    prds = root / ".docs" / "prds"
    if prds.is_dir():
        for path in sorted(prds.glob("*.json")):
            out.update(STORY_ID.findall(path.read_text(encoding="utf-8")))
    return out


def scan_bare_codes(root: Path) -> list[tuple[Path, int, str]]:
    """Return every `SCP-<digits>` that names no story, as (file, line, code)."""
    stories = story_ids(root)
    failures: list[tuple[Path, int, str]] = []
    for path in scan_files(root):
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            for match in BARE_SCP.finditer(line):
                if match.group(0) not in stories:
                    failures.append((path, number, match.group(0)))
    return failures


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
                if line[match.end() :].startswith(f" {MARKER}"):
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

SELF_TEST_PRD = """{"stories": [{"id": "SCP-046"}]}
"""

# A relay wire code in SDK spelling, beside a registered SDK code that must pass.
SELF_TEST_BARE_CODE = """A relay with no APNs sender answers SCP-4061.
A capability selection failure reports SCP-CAPSEL-8001.
"""

SELF_TEST_BAD = """The addressability and deployment spec says, in §18.11.99, that a verifier reads JSON.
"""

# One marked occurrence and one unmarked occurrence of the same reference in one file.
# A marker test scoped to the whole file passes this; a marker test scoped to the citing
# line reports the second line.
SELF_TEST_TWIN = """The passage cites §18.11.13.2 [no such section], which no merged spec carries.
A later paragraph repeats §18.11.13.2 and carries no marker of its own.
"""

# One marked occurrence and one unmarked occurrence on a single line. A marker test
# scoped to the citing line passes this; a marker test anchored to the occurrence the
# marker follows reports the second occurrence.
SELF_TEST_SAME_LINE = """The passage cites §18.11.13.2 [no such section], and the feed lives at §18.11.13.2.
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
        (lessons / "twin.md").write_text(SELF_TEST_TWIN)
        (lessons / "sameline.md").write_text(SELF_TEST_SAME_LINE)
        (lessons / "barecode.md").write_text(SELF_TEST_BARE_CODE)
        prds = root / ".docs" / "prds"
        prds.mkdir(parents=True)
        (prds / "main.json").write_text(SELF_TEST_PRD)

        failures = scan(root)
        got = sorted((f.name, line, ref) for f, line, ref in failures)
        want = [
            ("bad.md", 1, "18.11.99"),
            ("sameline.md", 1, "18.11.13.2"),
            ("twin.md", 2, "18.11.13.2"),
        ]
        if got != want:
            print(f"SELF-TEST FAILED: expected {want}, scanner reported {got}")
            return 1

        bare = sorted((f.name, line, code) for f, line, code in scan_bare_codes(root))
        want_bare = [("barecode.md", 1, "SCP-4061")]
        if bare != want_bare:
            print(f"SELF-TEST FAILED: expected bare codes {want_bare}, got {bare}")
            return 1
    print("SELF-TEST PASSED: the scanner reports all three planted dead citations,")
    print("  including the unmarked repeat of a reference the same file marks one line")
    print("  earlier and the unmarked repeat that shares a line with its own marker,")
    print(
        "  and skips a resolving citation, an RFC citation, a non-spec number, and the"
    )
    print("  occurrence the marker directly follows.")
    print("SELF-TEST PASSED: the bare-code scan reports SCP-4061 and passes")
    print("  SCP-CAPSEL-8001 and the ledger story SCP-046.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    root = Path(__file__).resolve().parent.parent
    failures = scan(root)
    bare = scan_bare_codes(root)
    if not failures and not bare:
        print(
            "check-doc-citations: every spec citation in the governing artifacts resolves,"
        )
        print("  and every bare SCP-<digits> names a story in .docs/prds/.")
        return 0

    if bare:
        print("check-doc-citations: these SCP-<digits> identifiers name no story.")
        print("Write a relay wire code as the bare number with its ADR-004 name")
        print("(`4061` PUSH_PLATFORM_UNAVAILABLE), or an SDK error code with its band")
        print("(`SCP-CAPSEL-8001`).\n")
        for path, line, code in bare:
            print(f"  {path.relative_to(root)}:{line}: {code}")
        if not failures:
            return 1
        print()

    print(
        "check-doc-citations: these citations name a section their spec file does not contain."
    )
    print(
        "Fix the number, or, when the file quotes a dead citation as evidence, write the"
    )
    print(f"marker `{MARKER}` after the reference on each line listed below.\n")
    for path, line, ref in failures:
        print(f"  {path.relative_to(root)}:{line}: §{ref}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
