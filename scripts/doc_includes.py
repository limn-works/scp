"""Shared scanner for the documentation transclusion markers.

An Owner section wraps a reproducible unit of its own text in a fragment marker:

    <!-- scp:fragment id="rent-arithmetic" -->
    One verified rent payment of `units` ... one declared period.
    <!-- scp:end id="rent-arithmetic" -->

A mirroring site carries the matching include directive and the Owner's bytes
between its two delimiters:

    <!-- scp:include id="rent-arithmetic" from=".docs/specs/09-security-model.md" -->
    One verified rent payment of `units` ... one declared period.
    <!-- scp:end id="rent-arithmetic" -->

`scripts/resolve-doc-includes.py` rewrites every include body from the fragment
its directive names. `scripts/check-doc-includes.py` re-runs that expansion into
a temporary tree and fails on a difference. This module holds the parsing both
of them read, so the resolver and the check never diverge on what a marker is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

FRAGMENT_OPEN = re.compile(r'^[ \t]*<!--[ \t]+scp:fragment[ \t]+id="([A-Za-z0-9._-]+)"[ \t]+-->[ \t]*$')
INCLUDE_OPEN = re.compile(
    r'^[ \t]*<!--[ \t]+scp:include[ \t]+id="([A-Za-z0-9._-]+)"[ \t]+from="([^"]+)"[ \t]+-->[ \t]*$'
)
MARKER_END = re.compile(r'^[ \t]*<!--[ \t]+scp:end[ \t]+id="([A-Za-z0-9._-]+)"[ \t]+-->[ \t]*$')
ANY_MARKER = re.compile(r"<!--\s*scp:(fragment|include|end)\b")

DOC_SUFFIXES = (".md", ".json")


@dataclass(frozen=True)
class Fragment:
    """One reproducible unit an Owner file delimits."""

    fragment_id: str
    path: Path
    open_line: int
    body: str


@dataclass(frozen=True)
class Include:
    """One include directive at a mirroring site."""

    fragment_id: str
    source: str
    path: Path
    open_line: int
    end_line: int
    body: str


class MarkerError(Exception):
    """A marker the scanner refuses to parse, with the file and line that carries it."""


def iter_doc_files(root: Path) -> list[Path]:
    """Every documentation file the scanner reads, in a stable order."""
    files: list[Path] = []
    for suffix in DOC_SUFFIXES:
        files.extend(p for p in root.rglob(f"*{suffix}") if p.is_file())
    return sorted(files)


@dataclass(frozen=True)
class _OpenMarker:
    """The delimiter the scanner has opened and not yet closed.

    The scanner holds one of these or holds `None`, so a reader that has checked for
    `None` reads `fragment_id` and `source` as the strings they are. Four parallel
    optional variables gave the same state four independent nullities, and a
    constructor call then took a `str | None` where the dataclass declares a `str`.
    """

    kind: str
    fragment_id: str
    source: str | None
    open_line: int


def scan_file(path: Path, text: str) -> tuple[list[Fragment], list[Include]]:
    """Read one file's fragment markers and include directives.

    Raises `MarkerError` where a delimiter opens without its matching end, where an
    end delimiter names an id no open delimiter opened, or where two markers nest.
    """
    lines = text.split("\n")
    fragments: list[Fragment] = []
    includes: list[Include] = []
    open_marker: _OpenMarker | None = None
    body: list[str] = []

    for index, line in enumerate(lines, start=1):
        fragment_match = FRAGMENT_OPEN.match(line)
        include_match = INCLUDE_OPEN.match(line)
        end_match = MARKER_END.match(line)

        if fragment_match is not None or include_match is not None:
            if open_marker is not None:
                raise MarkerError(
                    f"{path}:{index}: a marker opens while `{open_marker.fragment_id}` "
                    f"is still open at line {open_marker.open_line}"
                )
            if fragment_match is not None:
                open_marker = _OpenMarker("fragment", fragment_match.group(1), None, index)
            else:
                assert include_match is not None
                open_marker = _OpenMarker(
                    "include", include_match.group(1), include_match.group(2), index
                )
            body = []
            continue

        if end_match is not None:
            if open_marker is None:
                raise MarkerError(
                    f"{path}:{index}: `scp:end id=\"{end_match.group(1)}\"` closes a marker nothing opened"
                )
            if end_match.group(1) != open_marker.fragment_id:
                raise MarkerError(
                    f"{path}:{index}: `scp:end id=\"{end_match.group(1)}\"` closes "
                    f"`{open_marker.fragment_id}`, opened at line {open_marker.open_line}"
                )
            joined = "\n".join(body)
            if open_marker.kind == "fragment":
                fragments.append(
                    Fragment(open_marker.fragment_id, path, open_marker.open_line, joined)
                )
            else:
                source = open_marker.source
                assert source is not None
                includes.append(
                    Include(
                        open_marker.fragment_id,
                        source,
                        path,
                        open_marker.open_line,
                        index,
                        joined,
                    )
                )
            open_marker = None
            body = []
            continue

        if open_marker is not None:
            body.append(line)
        elif ANY_MARKER.search(line):
            raise MarkerError(
                f"{path}:{index}: a line carries an `scp:` marker the scanner does not parse: {line.strip()}"
            )

    if open_marker is not None:
        raise MarkerError(
            f"{path}:{open_marker.open_line}: `{open_marker.fragment_id}` opens "
            f"and no `scp:end` closes it"
        )

    return fragments, includes


def collect(root: Path) -> tuple[dict[str, Fragment], list[Include], list[str]]:
    """Read every fragment and every include under `root`.

    Returns the fragment table keyed by id, every include directive, and the errors
    the scan found: an unparsable marker, an unpaired delimiter, or one id two files
    define.
    """
    fragments: dict[str, Fragment] = {}
    includes: list[Include] = []
    errors: list[str] = []

    for path in iter_doc_files(root):
        text = path.read_text(encoding="utf-8")
        if "scp:fragment" not in text and "scp:include" not in text and "scp:end" not in text:
            continue
        try:
            file_fragments, file_includes = scan_file(path, text)
        except MarkerError as error:
            errors.append(str(error))
            continue
        for fragment in file_fragments:
            existing = fragments.get(fragment.fragment_id)
            if existing is not None:
                errors.append(
                    f"fragment id `{fragment.fragment_id}` is defined twice: "
                    f"{existing.path}:{existing.open_line} and {fragment.path}:{fragment.open_line}"
                )
                continue
            fragments[fragment.fragment_id] = fragment
        includes.extend(file_includes)

    return fragments, includes, errors


def expand(text: str, fragments: dict[str, Fragment], path: Path) -> tuple[str, list[str]]:
    """Rewrite every include body in `text` with the bytes its fragment holds."""
    errors: list[str] = []
    lines = text.split("\n")
    out: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        include_match = INCLUDE_OPEN.match(line)
        if include_match is None:
            out.append(line)
            index += 1
            continue
        fragment_id = include_match.group(1)
        end_index = index + 1
        while end_index < len(lines):
            end_match = MARKER_END.match(lines[end_index])
            if end_match is not None and end_match.group(1) == fragment_id:
                break
            end_index += 1
        if end_index >= len(lines):
            errors.append(f"{path}:{index + 1}: include `{fragment_id}` opens and no `scp:end` closes it")
            out.append(line)
            index += 1
            continue
        fragment = fragments.get(fragment_id)
        if fragment is None:
            errors.append(
                f"{path}:{index + 1}: include names fragment id `{fragment_id}`, which no file under `.docs/` defines"
            )
            out.extend(lines[index : end_index + 1])
            index = end_index + 1
            continue
        declared = include_match.group(2)
        owner = str(fragment.path)
        if not owner.endswith(declared.lstrip("./")):
            errors.append(
                f"{path}:{index + 1}: include names `from=\"{declared}\"` and fragment `{fragment_id}` "
                f"sits in {fragment.path}"
            )
        out.append(line)
        if fragment.body:
            out.extend(fragment.body.split("\n"))
        out.append(lines[end_index])
        index = end_index + 1
    return "\n".join(out), errors
