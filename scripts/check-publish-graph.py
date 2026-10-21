#!/usr/bin/env python3
"""Fail when a crate the release publishes cannot be published.

`cargo publish -p X` resolves every normal and build dependency of X from
crates.io. A publishable crate (no `publish = false`) with such a dependency
on a `publish = false` crate therefore fails at release time, long after the
pull request that added the edge merged green. The same holds when
`.github/workflows/release.yml` publishes a crate before one it depends on,
or never publishes a crate a published crate depends on.

The check reads `cargo metadata --no-deps --offline` for the root workspace
and for the `fuzz/` workspace. The rules need only each workspace's members,
their `publish` setting and their declared path dependencies, all of which
come from the manifests, so the check resolves no registry crate and reads
nothing from the cargo home: it runs the same with an empty `CARGO_HOME` and
no network as it does on a warm machine. Whether fuzz/Cargo.lock records every
edge is fuzz-build's `cargo check --locked`, not this check. Over the members
of both workspaces it asserts:

  1. a publishable package has no normal or build dependency on a local
     package with `publish = false` (dev-dependencies are stripped from the
     published manifest, so they may reach one);
  2. release.yml publishes every publishable package of the root workspace
     exactly once, and names no other package in a `cargo publish -p` step;
  3. release.yml publishes each such package after every publishable local
     package it has a normal or build dependency on.

`--self-test` runs the rules over planted metadata, each case of which must
fail, plus a clean case that must pass, before the real check is trusted.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
WORKSPACES = (ROOT / "Cargo.toml", ROOT / "fuzz" / "Cargo.toml")
PUBLISH_STEP = re.compile(r"^\s*run:\s*cargo publish -p (\S+)", re.MULTILINE)
SHIPPED_KINDS = (None, "build")


class MetadataFailed(Exception):
    pass


def metadata(manifest: Path) -> dict:
    # --no-deps reads the manifests alone; --offline turns any registry access
    # a future cargo might attempt into an error here rather than a download.
    out = subprocess.run(
        [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--manifest-path",
            str(manifest),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise MetadataFailed(
            f"{manifest.relative_to(ROOT)}: `cargo metadata --no-deps --offline` failed:\n{out.stderr.strip()}"
        )
    return json.loads(out.stdout)


def local_packages(meta: dict) -> dict[str, dict]:
    """Every package built from a path in this checkout, by name.

    Under --no-deps that is every workspace member; a path dependency outside
    the workspace appears only in its dependent's `dependencies` list, which is
    why run() checks edges over the members of both workspaces together.
    """
    return {p["name"]: p for p in meta["packages"] if p.get("source") is None}


def publishable(package: dict) -> bool:
    # cargo reports `publish = false` as [] and an unrestricted crate as null.
    return package.get("publish") != []


def shipped_local_deps(package: dict, local: dict[str, dict]) -> list[str]:
    return sorted(
        {
            d["name"]
            for d in package["dependencies"]
            if d.get("kind") in SHIPPED_KINDS
            and d.get("path") is not None
            and d["name"] in local
        }
    )


def check_edges(local: dict[str, dict], label: str) -> list[str]:
    errors = []
    for name, package in sorted(local.items()):
        if not publishable(package):
            continue
        for dep in shipped_local_deps(package, local):
            if not publishable(local[dep]):
                errors.append(
                    f"{label}: publishable crate `{name}` has a normal or build dependency on "
                    f"`{dep}`, which sets `publish = false`; `cargo publish -p {name}` cannot "
                    f"resolve it"
                )
    return errors


def check_release(
    local: dict[str, dict], workspace_members: set[str], steps: list[str]
) -> list[str]:
    errors = []
    expected = {n for n in workspace_members if publishable(local[n])}
    seen: dict[str, int] = {}
    for index, name in enumerate(steps):
        if name in seen:
            errors.append(f"release.yml publishes `{name}` twice")
        seen.setdefault(name, index)
        if name not in expected:
            errors.append(
                f"release.yml publishes `{name}`, which is not a publishable workspace crate"
            )
    for name in sorted(expected - seen.keys()):
        errors.append(
            f"release.yml never publishes `{name}`, a publishable workspace crate"
        )
    for name in sorted(expected & seen.keys()):
        for dep in shipped_local_deps(local[name], local):
            if dep in seen and seen[dep] > seen[name]:
                errors.append(
                    f"release.yml publishes `{name}` before `{dep}`, which it depends on"
                )
    return errors


def run(metas: list[tuple[str, dict]], steps: list[str]) -> list[str]:
    # One name space over both workspaces: a fuzz member's path dependencies
    # are root members, which only the root workspace's metadata lists.
    combined: dict[str, dict] = {}
    for _, meta in metas:
        combined.update(local_packages(meta))
    errors = check_edges(combined, " + ".join(label for label, _ in metas))
    _, root = metas[0]
    local = local_packages(root)
    members = {
        p["name"] for p in root["packages"] if p["id"] in set(root["workspace_members"])
    }
    errors += check_release(local, members, steps)
    return errors


def _pkg(name: str, publish: bool, deps: list[tuple[str, str | None]]) -> dict:
    return {
        "id": name,
        "name": name,
        "source": None,
        "publish": None if publish else [],
        "dependencies": [{"name": d, "kind": k, "path": f"/x/{d}"} for d, k in deps],
    }


def _meta(*packages: dict) -> dict:
    return {
        "packages": list(packages),
        "workspace_members": [p["id"] for p in packages],
    }


def self_test() -> int:
    a_dev_on_private = _meta(_pkg("a", True, [("t", "dev")]), _pkg("t", False, []))
    cases = {
        # Must fail: the defect this gate exists for.
        "normal-dep-on-private": (
            _meta(_pkg("a", True, [("k", None)]), _pkg("k", False, [])),
            ["a"],
        ),
        "build-dep-on-private": (
            _meta(_pkg("a", True, [("k", "build")]), _pkg("k", False, [])),
            ["a"],
        ),
        "missing-step": (
            _meta(_pkg("a", True, [("k", None)]), _pkg("k", True, [])),
            ["a"],
        ),
        "wrong-order": (
            _meta(_pkg("a", True, [("k", None)]), _pkg("k", True, [])),
            ["a", "k"],
        ),
        "private-published": (a_dev_on_private, ["a", "t"]),
        "duplicate-step": (_meta(_pkg("a", True, [])), ["a", "a"]),
    }
    failed = False
    for name, (meta, steps) in cases.items():
        if not run([("planted", meta)], steps):
            print(f"self-test FAILED: case `{name}` passed but must fail")
            failed = True
    # --no-deps lists only a workspace's own members, so a second workspace's
    # member reaches a root crate only through the combined name space.
    cross = run(
        [
            ("root", _meta(_pkg("a", True, []), _pkg("k", False, []))),
            ("second", _meta(_pkg("f", True, [("k", None)]))),
        ],
        ["a"],
    )
    if not cross:
        print(
            "self-test FAILED: case `cross-workspace-dep-on-private` passed but must fail"
        )
        failed = True
    clean = run([("planted", a_dev_on_private)], ["a"])
    ordered = run(
        [("planted", _meta(_pkg("a", True, [("k", None)]), _pkg("k", True, [])))],
        ["k", "a"],
    )
    if clean or ordered:
        print(f"self-test FAILED: a clean case failed: {clean + ordered}")
        failed = True
    if failed:
        return 1
    print(
        f"check-publish-graph self-test: {len(cases) + 1} planted defects rejected, 2 clean cases accepted"
    )
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    try:
        metas = [(str(m.relative_to(ROOT)), metadata(m)) for m in WORKSPACES]
    except MetadataFailed as failed:
        print(f"error: {failed}")
        return 1
    steps = PUBLISH_STEP.findall(RELEASE.read_text())
    errors = run(metas, steps)
    for e in errors:
        print(f"error: {e}")
    if errors:
        return 1
    print(
        f"check-publish-graph: {len(steps)} publish steps; every published crate resolves from crates.io in release order"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
