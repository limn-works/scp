"""Write the Python and TypeScript code blocks of the live migration guides to files.

Run by scripts/check-examples-typecheck.sh as
`python3.12 guide_blocks.py OUT_DIR GUIDE...`. For each guide it reads the
`**Status:**` line. A guide whose status begins with the word `live` has every
fenced block whose info string's first word is `python`, `py`, `typescript` or
`ts`, in any letter case, written to
`OUT_DIR/py/` or `OUT_DIR/ts/` as one standalone module, so the gate type-checks
each block against the SDK source in this tree. Each written file opens with one
blank line per guide line above the block, so a line number in a type error is
the line number in the guide. A guide with any other status is reported on stdout
and none of its blocks is written.

A block is left out only when the line directly above its opening fence is the
marker `<!-- examples-typecheck: skip: REASON -->` with a non-empty REASON, for a
block that shows API the SDK no longer has, such as the "Before" half of a
breaking change. Every skipped block, and every block in a language this gate has
no type checker for, is printed with its guide, line and reason, so a reviewer
reads every block the gate did not check. A missing marker means the block is
checked.

A fence opens on a line whose first non-blank characters are three or more
backticks or three or more tildes, at any indentation, and closes on a line holding
only a run of the same character at least as long as the opener's run.

Exit 1 when a guide has no `**Status:**` line, a fence never closes, a line opens
with three or more backticks but carries a backtick in its info string, a marker has
no reason, or a marker does not sit directly above the opening fence of a Python
or TypeScript block. The gate then stops before it type-checks anything.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHECKED = {"python": "py", "py": "py", "typescript": "ts", "ts": "ts"}
FENCE = re.compile(r"^(?P<indent>[ \t]*)(?P<run>`{3,}|~{3,})(?P<info>.*)$")
MARKER_PREFIX = "<!-- examples-typecheck:"
MARKER = re.compile(r"^<!-- examples-typecheck: skip: (?P<reason>.*?) -->$")
STATUS = re.compile(r"^\*\*Status:\*\*\s*(?P<status>.*)$")


def opener(line: str) -> tuple[str, str, str] | None:
    """Return (indent, fence run, info string) when LINE opens a fence, else None.

    Raise ValueError for a line that starts with a backtick run of three or more but
    is not a fence, because its info string holds a backtick; such a line is
    neither prose nor a block the gate can classify.
    """
    match = FENCE.match(line)
    if match is None:
        return None
    run, info = match.group("run"), match.group("info").strip()
    if run[0] == "`" and "`" in info:
        raise ValueError("a backtick fence's info string may not hold a backtick")
    return match.group("indent"), run, info


def closes(line: str, run: str) -> bool:
    """Return True when LINE closes a fence opened by RUN."""
    stripped = line.strip()
    return len(stripped) >= len(run) and stripped == run[0] * len(stripped)


def module_name(guide: str, line: int) -> str:
    """Return a name that is a valid Python module and unique per guide and line."""
    stem = re.sub(r"\W", "_", Path(guide).stem)
    return f"guide_{stem}_L{line}"


def extract(guide: str, text: str, out: Path, errors: list[str]) -> None:
    lines = text.splitlines()
    status = next((m.group("status") for m in map(STATUS.match, lines) if m), None)
    if status is None:
        errors.append(
            f"{guide}: no '**Status:**' line, so the gate cannot tell whether the guide is live"
        )
        return
    if status.split(maxsplit=1)[:1] != ["live"]:
        print(
            f"examples-typecheck: GUIDE NOT LIVE {guide}: status '{status}'; no block checked"
        )
        return

    pending: tuple[int, str] | None = None  # (marker line, reason) awaiting a fence
    i = 0
    while i < len(lines):
        raw = lines[i]
        number = i + 1
        try:
            fence = opener(raw)
        except ValueError as error:
            errors.append(f"{guide}:{number}: {error}")
            return
        if raw.strip().startswith(MARKER_PREFIX):
            match = MARKER.match(raw.strip())
            if match is None or not match.group("reason").strip():
                errors.append(
                    f"{guide}:{number}: a marker must read '<!-- examples-typecheck: skip: REASON -->' "
                    "with a non-empty REASON"
                )
            else:
                pending = (number, match.group("reason").strip())
            i += 1
            if pending is not None and (
                i >= len(lines) or FENCE.match(lines[i]) is None
            ):
                errors.append(
                    f"{guide}:{pending[0]}: the skip marker is not directly above an opening fence"
                )
                pending = None
            continue
        if fence is None:
            i += 1
            continue
        indent, run, info = fence
        lang = info.split(maxsplit=1)[0].lower() if info else ""
        body: list[str] = []
        i += 1
        while i < len(lines) and not closes(lines[i], run):
            body.append(
                lines[i][len(indent) :]
                if lines[i][: len(indent)].strip() == ""
                else lines[i]
            )
            i += 1
        if i >= len(lines):
            errors.append(f"{guide}:{number}: the fence opened here never closes")
            return
        i += 1
        kind = CHECKED.get(lang)
        label = lang or "no language"
        if pending is not None:
            marker_line, reason = pending
            pending = None
            if kind is None:
                errors.append(
                    f"{guide}:{marker_line}: the skip marker sits above a {label} block, "
                    "which this gate never checks; delete the marker"
                )
            else:
                print(f"examples-typecheck: SKIP {guide}:{number} ({label}): {reason}")
            continue
        if kind is None:
            print(
                f"examples-typecheck: NOT CHECKED {guide}:{number} ({label}): this gate type-checks Python and TypeScript only"
            )
            continue
        target = out / kind / f"{module_name(guide, number)}.{kind}"
        target.write_text("\n" * number + "\n".join(body) + "\n", encoding="utf-8")
        print(f"examples-typecheck: CHECK {guide}:{number} ({label}) as {target.name}")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: guide_blocks.py OUT_DIR GUIDE...", file=sys.stderr)
        return 2
    out = Path(argv[1])
    for kind in ("py", "ts"):
        (out / kind).mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    for guide in argv[2:]:
        extract(guide, Path(guide).read_text(encoding="utf-8"), out, errors)
    for error in errors:
        print(f"examples-typecheck: FAIL: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
