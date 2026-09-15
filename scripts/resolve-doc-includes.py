#!/usr/bin/env python3.12
"""Write each Owner fragment's bytes into every include directive that names it.

A writer runs this after it edits an Owner fragment. `scripts/check-doc-includes.py`
runs the same expansion into a temporary tree and fails where a file differs, which
is the shape `cargo fmt --check` already uses in this repository.

Usage:
    python3.12 scripts/resolve-doc-includes.py            # rewrite the tree in place
    python3.12 scripts/resolve-doc-includes.py --check     # report, write nothing
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from doc_includes import collect, expand  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = REPO_ROOT / ".docs"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report differences and write nothing")
    parser.add_argument("--root", default=str(DOCS_ROOT), help="directory to scan")
    args = parser.parse_args()

    root = Path(args.root)
    fragments, includes, errors = collect(root)

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    touched = sorted({include.path for include in includes})
    changed: list[Path] = []
    expand_errors: list[str] = []

    for path in touched:
        original = path.read_text(encoding="utf-8")
        resolved, path_errors = expand(original, fragments, path)
        expand_errors.extend(path_errors)
        if resolved != original:
            changed.append(path)
            if not args.check:
                path.write_text(resolved, encoding="utf-8")

    if expand_errors:
        for error in expand_errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"fragments defined: {len(fragments)}")
    print(f"include directives: {len(includes)} across {len(touched)} files")
    if args.check:
        if changed:
            for path in changed:
                print(f"stale: {path}")
            return 1
        print("every include body matches the fragment it names")
        return 0

    if changed:
        for path in changed:
            print(f"rewrote: {path}")
    else:
        print("every include body already matched the fragment it names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
