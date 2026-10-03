#!/usr/bin/env python3.12
"""Print the `cargo clippy` package and feature arguments for the paths a commit changes.

`scripts/hooks/pre-commit` pipes the paths its changed-path list holds, NUL-separated as
`git diff -z` prints them, into this script and passes the testing features it lints with
in `--features`. The script prints one cargo argument per line, and prints nothing when no
path needs a lint.

The script prints `--workspace` and every feature `--features` names when a changed path,
relative to the workspace root, is in `ROOT_WIDE`, when a changed path, relative to the
member directory that holds it, is in `MEMBER_WIDE`, or when a changed path's file name,
in any directory, is in `CLIPPY_CONFIG`. Each `ROOT_WIDE` path can change the lints or
the dependency resolution of a member whose files the commit did not touch:
- `Cargo.toml` can change the features and dependency versions every member resolves, and
  `Cargo.lock` can change the versions every member builds.
- `rust-toolchain.toml` (and its legacy name `rust-toolchain`) changes the compiler and
  therefore the lint set.
- `.cargo/config.toml` (and its legacy name `.cargo/config`) reaches every cargo command
  the hook runs from the root.
`MEMBER_WIDE` holds a member's `Cargo.toml`, `Cargo.lock`, and `build.rs`.
`CLIPPY_CONFIG` holds `clippy.toml` and `.clippy.toml`: clippy reads the one in the
member's directory, or else the one in the nearest parent directory that holds one, so one
in a directory that is no member, such as `crates/`, changes lint thresholds for members
below it.
These root files stay out of `ROOT_WIDE`: `rustfmt.toml` changes formatting, not lints,
and `deny.toml` is read by cargo-deny, not by clippy.

Otherwise the script selects each workspace member that holds a changed path, of any file
type, because a crate can read a non-Rust file in its directory with `include_str!`. A
commit that deletes or moves a file outside a member's directory does not select a member
that reads that file with `include_str!` or `include_bytes!`. The script then adds every
workspace member that depends on a selected member, directly or transitively, as
`Graph.affected` defines the walk, and prints `-p <name>` for each. It keeps only the
`--features` entries whose package is selected, because cargo rejects `<package>/<feature>`
for a package the command does not select.

`fuzz/` is a standalone workspace whose crates `fuzz/rust-toolchain.toml` builds on a
nightly compiler, so the hook does not lint it; the script names each such `.rs` path on
stderr.

The script reads the member graph from `cargo metadata --format-version 1 --no-deps`, or
from the file `--metadata` names. It exits nonzero when cargo metadata fails, so the hook
fails instead of linting nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import PurePosixPath

ROOT_WIDE = frozenset(
    {
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "rust-toolchain",
        ".cargo/config.toml",
        ".cargo/config",
    }
)
MEMBER_WIDE = frozenset({"Cargo.toml", "Cargo.lock", "build.rs"})
CLIPPY_CONFIG = frozenset({"clippy.toml", ".clippy.toml"})


def lints_everything(path: str) -> bool:
    """Return whether path, relative to the workspace root, needs a whole-workspace lint."""
    return path in ROOT_WIDE or PurePosixPath(path).name in CLIPPY_CONFIG


class ScopeError(Exception):
    """The script could not read the workspace member graph."""


def load_metadata(path: str | None) -> dict:
    if path is not None:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as err:
        stderr = getattr(err, "stderr", "") or ""
        raise ScopeError(f"cargo metadata failed: {err}\n{stderr}") from err
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as err:
        raise ScopeError(f"cargo metadata printed no JSON: {err}") from err


class Graph:
    """Workspace members, keyed by directory, with their reverse dependency edges."""

    def __init__(self, metadata: dict) -> None:
        root = PurePosixPath(metadata["workspace_root"])
        member_ids = set(metadata["workspace_members"])
        members = [p for p in metadata["packages"] if p["id"] in member_ids]
        if len(members) != len(member_ids):
            raise ScopeError(
                "cargo metadata lists a workspace member it gives no package for"
            )
        abs_dir_to_name = {
            str(PurePosixPath(p["manifest_path"]).parent): p["name"] for p in members
        }
        # {member directory relative to the workspace root: package name}
        self.dirs = {
            str(PurePosixPath(d).relative_to(root)): n
            for d, n in abs_dir_to_name.items()
        }
        # lib_dependents[x]: members whose library or build script compiles against x's library.
        # dev_dependents[x]: members whose test, bench, or example targets compile against it.
        self.lib_dependents: dict[str, set[str]] = {p["name"]: set() for p in members}
        self.dev_dependents: dict[str, set[str]] = {p["name"]: set() for p in members}
        for package in members:
            for dep in package["dependencies"]:
                dep_name = abs_dir_to_name.get(dep.get("path") or "")
                if dep_name is None or dep_name == package["name"]:
                    continue
                edges = (
                    self.dev_dependents
                    if dep.get("kind") == "dev"
                    else self.lib_dependents
                )
                edges[dep_name].add(package["name"])

    def affected(self, changed: set[str]) -> set[str]:
        """Return the changed members plus every member that depends on one of them.

        A member whose library depends on a changed member's library compiles different code,
        and so does every member that depends on that member's library, so the walk follows
        normal and build edges until the set stops growing. A dev-dependency edge reaches
        only the dependent's test, bench, and example targets, which no other member compiles
        against, so the walk adds each dev-dependent of the library set and stops there.
        """
        libs = set(changed)
        pending = list(changed)
        while pending:
            for dependent in self.lib_dependents[pending.pop()]:
                if dependent not in libs:
                    libs.add(dependent)
                    pending.append(dependent)
        affected = set(libs)
        for lib in libs:
            affected |= self.dev_dependents[lib]
        return affected


def owning_member(path: str, dirs: dict[str, str]) -> tuple[str, str] | None:
    """Return (member directory, package name) for the deepest member directory holding path."""
    parts = PurePosixPath(path).parts
    for depth in range(len(parts) - 1, -1, -1):
        candidate = str(PurePosixPath(*parts[:depth])) if depth else "."
        if candidate in dirs:
            return candidate, dirs[candidate]
    return None


def select(paths: list[str], metadata: dict, features: list[str]) -> list[str]:
    """Return the cargo arguments for the changed paths; an empty list means no lint."""
    if any(lints_everything(p) for p in paths):
        return workspace_args(features)
    graph = Graph(metadata)
    changed: set[str] = set()
    for path in paths:
        owner = owning_member(path, graph.dirs)
        if owner is None:
            if path.endswith(".rs"):
                print(
                    f"clippy scope: {path} is in no workspace member; not linted",
                    file=sys.stderr,
                )
            continue
        member_dir, name = owner
        relative = (
            PurePosixPath(path).relative_to(member_dir)
            if member_dir != "."
            else PurePosixPath(path)
        )
        if str(relative) in MEMBER_WIDE:
            return workspace_args(features)
        changed.add(name)
    selected = graph.affected(changed)
    if not selected:
        return []
    args: list[str] = []
    for name in sorted(selected):
        args += ["-p", name]
    kept = [f for f in features if f.split("/", 1)[0] in selected]
    if kept:
        args += ["--features", ",".join(kept)]
    return args


def workspace_args(features: list[str]) -> list[str]:
    args = ["--workspace"]
    if features:
        args += ["--features", ",".join(features)]
    return args


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print the cargo clippy arguments for the paths a commit changes."
    )
    parser.add_argument(
        "--features", default="", help="comma-separated <package>/<feature> list"
    )
    parser.add_argument(
        "--metadata", help="read this cargo metadata JSON file instead of running cargo"
    )
    args = parser.parse_args()
    paths = [os.fsdecode(p) for p in sys.stdin.buffer.read().split(b"\0") if p]
    features = [f for f in args.features.split(",") if f]
    for feature in features:
        if "/" not in feature:
            print(
                f"clippy scope: feature {feature!r} names no package", file=sys.stderr
            )
            return 2
    if not paths:
        return 0
    try:
        metadata = (
            {}
            if any(lints_everything(p) for p in paths)
            else load_metadata(args.metadata)
        )
        cargo_args = select(paths, metadata, features)
    except (ScopeError, OSError, KeyError, ValueError) as err:
        print(f"clippy scope: {err}", file=sys.stderr)
        return 1
    for arg in cargo_args:
        print(arg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
