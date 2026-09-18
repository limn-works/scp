#!/usr/bin/env python3.12
"""Fail where a transcluding site's bytes differ from the fragment its directive names.

The check copies `.docs/` into a temporary tree, re-runs the resolver there, and
compares. It fails on five conditions, which are the five the identity-substrate
plan states for the `[mirror]` disposition:

1. a file differs after the expansion, so a site's bytes have drifted from its Owner;
2. a directive names a fragment id no file under `.docs/` defines;
3. two files define one fragment id;
4. a directive's two delimiters do not pair;
5. a site's include body carries a byte the fragment does not.

Condition 5 is condition 1 read from the site's side, and the check reports it in
the site's own terms so a writer reads which line drifted rather than which file.

`--self-test` plants each of the five conditions in a scratch tree and asserts that
the checker reports it, so a green real scan means the checker read the tree rather
than that it can no longer fail.

Usage:
    python3.12 scripts/check-doc-includes.py
    python3.12 scripts/check-doc-includes.py --self-test
"""

from __future__ import annotations

import argparse
import difflib
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from doc_includes import collect, expand  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = REPO_ROOT / ".docs"


def run_scan(root: Path) -> list[str]:
    """Return every failure the five conditions produce over the tree at `root`."""
    fragments, includes, failures = collect(root)
    failures = list(failures)

    for include in includes:
        path = include.path
        original = path.read_text(encoding="utf-8")
        resolved, expand_errors = expand(original, fragments, path)
        failures.extend(expand_errors)
        if resolved == original:
            continue
        fragment = fragments.get(include.fragment_id)
        if fragment is None:
            continue
        if include.body != fragment.body:
            diff = "\n".join(
                difflib.unified_diff(
                    fragment.body.split("\n"),
                    include.body.split("\n"),
                    fromfile=f"{fragment.path}:{fragment.open_line} (the Owner's fragment)",
                    tofile=f"{path}:{include.open_line} (the include body)",
                    lineterm="",
                )
            )
            failures.append(
                f"{path}:{include.open_line}: the include body for `{include.fragment_id}` "
                f"differs from the fragment {fragment.path}:{fragment.open_line} defines\n{diff}"
            )

    # Deduplicate while keeping the order the scan found them in.
    seen: set[str] = set()
    ordered: list[str] = []
    for failure in failures:
        if failure in seen:
            continue
        seen.add(failure)
        ordered.append(failure)
    return ordered


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def self_test() -> int:
    """Plant each of the five conditions and assert the checker reports it."""
    cases: list[tuple[str, dict[str, str], str]] = [
        (
            "a site's bytes drifted from its Owner",
            {
                "owner.md": (
                    "# Owner\n\n"
                    '<!-- scp:fragment id="probe-one" -->\n'
                    "The relay counts every PUBLISH and every `RENT`.\n"
                    '<!-- scp:end id="probe-one" -->\n'
                ),
                "site.md": (
                    "# Site\n\n"
                    '<!-- scp:include id="probe-one" from="owner.md" -->\n'
                    "The relay counts every PUBLISH.\n"
                    '<!-- scp:end id="probe-one" -->\n'
                ),
            },
            "differs from the fragment",
        ),
        (
            "a directive names a fragment id no file defines",
            {
                "site.md": (
                    '<!-- scp:include id="probe-absent" from="owner.md" -->\n'
                    "Some bytes.\n"
                    '<!-- scp:end id="probe-absent" -->\n'
                ),
            },
            "which no file under `.docs/` defines",
        ),
        (
            "two files define one fragment id",
            {
                "owner-a.md": '<!-- scp:fragment id="probe-two" -->\nA.\n<!-- scp:end id="probe-two" -->\n',
                "owner-b.md": '<!-- scp:fragment id="probe-two" -->\nB.\n<!-- scp:end id="probe-two" -->\n',
            },
            "is defined twice",
        ),
        (
            "a directive's two delimiters do not pair",
            {
                "owner.md": '<!-- scp:fragment id="probe-three" -->\nA.\n<!-- scp:end id="probe-three" -->\n',
                "site.md": '<!-- scp:include id="probe-three" from="owner.md" -->\nA.\n',
            },
            "and no `scp:end` closes it",
        ),
        (
            "a site's include body carries a byte the fragment does not",
            {
                "owner.md": (
                    '<!-- scp:fragment id="probe-four" -->\n'
                    "A relay charges no `scp:wit:` write.\n"
                    '<!-- scp:end id="probe-four" -->\n'
                ),
                "site.md": (
                    '<!-- scp:include id="probe-four" from="owner.md" -->\n'
                    "A relay charges no `scp:wit:` write, and the operator decides.\n"
                    '<!-- scp:end id="probe-four" -->\n'
                ),
            },
            "differs from the fragment",
        ),
    ]

    failed = False
    for name, files, expected in cases:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / ".docs"
            for relative, text in files.items():
                _write(root / relative, text)
            failures = run_scan(root)
            if not any(expected in failure for failure in failures):
                print(f"SELF-TEST FAILED: {name}: no failure carried {expected!r}", file=sys.stderr)
                for failure in failures:
                    print(f"  reported: {failure}", file=sys.stderr)
                failed = True
            else:
                print(f"self-test ok: {name}")

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw) / ".docs"
        _write(root / "owner.md", '<!-- scp:fragment id="probe-clean" -->\nA.\n<!-- scp:end id="probe-clean" -->\n')
        _write(
            root / "site.md",
            '<!-- scp:include id="probe-clean" from="owner.md" -->\nA.\n<!-- scp:end id="probe-clean" -->\n',
        )
        failures = run_scan(root)
        if failures:
            print("SELF-TEST FAILED: a conforming pair reported a failure", file=sys.stderr)
            for failure in failures:
                print(f"  reported: {failure}", file=sys.stderr)
            failed = True
        else:
            print("self-test ok: a conforming pair reports nothing")

    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="plant each condition and assert it is caught")
    parser.add_argument("--root", default=str(DOCS_ROOT), help="directory to scan")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    source = Path(args.root)
    with tempfile.TemporaryDirectory() as raw:
        mirror = Path(raw) / source.name
        shutil.copytree(source, mirror)
        failures = run_scan(mirror)
        # The scan reads the copy, so every path it names sits under the temporary
        # tree, which no reader of a CI log can open. Rewrite each one to the file the
        # writer edits before the failure leaves this function.
        failures = [failure.replace(str(mirror), str(source)) for failure in failures]

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"\n{len(failures)} transclusion failures", file=sys.stderr)
        return 1

    fragments, includes, _ = collect(source)
    print(f"fragments defined: {len(fragments)}")
    print(f"include directives: {len(includes)}")
    print("every include body equals the fragment its directive names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
