#!/usr/bin/env python3.12
"""Prove end to end that a restored workspace-unit archive is reused only on equal content.

Runs in CI job `workspace-cache-exactness` on a runner that restored the
`workspace-debug` dependency cache. It builds two reader commands of job
rust-test-napi-production, packs their workspace units with
scripts/ci-workspace-cache.py, gives every tracked file a fresh-checkout mtime, and
then, for each plant below, deletes the units, restores the archive and rebuilds:

  none           no change: every workspace unit must be reused (the archive works).
  source-byte    one byte of a scp-ffi-common source file: every unit that compiled
                 the file, every other unit of a package whose library changed, and
                 every unit of a workspace package depending on that library must
                 rebuild; every other unit must be reused.
  include-byte   one byte of the JSON fixture scp-ffi-common's unit tests take through
                 `include_str!`: the lib-test unit alone rebuilds, and the fixture test
                 that compares the file to the struct fails, so the test observes the
                 new content.
  build-env      NAPI_TYPE_DEF_TMP_FOLDER, which scp-ffi-napi's build script declares
                 with `rerun-if-env-changed` and which napi-derive reads while it
                 expands scp-ffi-napi: every scp-ffi-napi unit rebuilds, and the folder
                 receives the type definitions, so the build observes the new value.

Each file plant has a must-fail control: after the restore, the planted file is given
the old mtime, as a mechanism trusting mtimes or commit times would leave it, and the
same assertion must report the stale reuse. The env plant's control builds without the
variable and must leave the folder empty. A control that passes fails this script,
because it means the assertion cannot see a stale unit.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CACHE = [sys.executable, str(ROOT / "scripts/ci-workspace-cache.py")]
TARGET = ROOT / "target"
OLD_MTIME = 946_684_800

# Two commands of job rust-test-napi-production, as job workspace-debug of
# .github/workflows/cache-warm.yml compiles them, so the restored dependency cache
# holds every dependency unit they need.
COMMANDS = [
    ["cargo", "test", "--no-run", "-p", "scp-ffi-napi", "--features", "server"],
    ["cargo", "test", "--no-run", "-p", "scp-ffi-common"],
]
SOURCE_FILE = "crates/scp-ffi/common/src/lib.rs"
INCLUDE_FILE = "crates/scp-ffi/common/tests/fixtures/node_start_config.json"
FIXTURE_TEST = ["cargo", "test", "-p", "scp-ffi-common", "--lib", "node_start_config"]

failures: list[str] = []


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    failures.append(msg)


def build(env_extra: dict[str, str] | None = None) -> list[dict]:
    """Run every command; return each compiler-artifact message of a workspace package."""
    env = dict(os.environ)
    env.update(env_extra or {})
    arts: list[dict] = []
    for cmd in COMMANDS:
        proc = subprocess.run(
            [*cmd, "--message-format=json"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            print(proc.stderr[-4000:])
            raise SystemExit(f"{' '.join(cmd)} failed")
        for line in proc.stdout.splitlines():
            if not line.startswith("{"):
                continue
            msg = json.loads(line)
            if msg.get("reason") == "compiler-artifact" and msg[
                "package_id"
            ].startswith("path+"):
                arts.append(msg)
    return arts


def unit_key(msg: dict) -> str:
    """Name one unit; the output file names carry cargo's metadata hash, so two feature sets differ."""
    t = msg["target"]
    files = ",".join(sorted(Path(f).name for f in msg["filenames"]))
    return f"{pkg_name(msg)}:{'/'.join(t['kind'])}:{t['name']}:{files}"


def pkg_name(msg: dict) -> str:
    # path+file:///.../crates/scp-ffi/common#scp-ffi-common@0.1.0
    return msg["package_id"].split("#", 1)[1].split("@", 1)[0]


def dep_info_inputs(msg: dict) -> set[str]:
    """Paths the unit's rustc dep-info lists, relative to the repository root."""
    inputs: set[str] = set()
    for fname in msg["filenames"]:
        p = Path(fname)
        stem = p.name
        for suffix in (".rlib", ".rmeta", ".so", ".dylib", ".a"):
            stem = stem.removesuffix(suffix)
        stem = stem.removeprefix("lib")
        d = p.parent / f"{stem}.d"
        if not d.is_file() and (p.parent / "deps").is_dir():
            d = p.parent / "deps" / f"{stem}.d"
        if not d.is_file():
            continue
        first = d.read_text().splitlines()[0]
        for raw in first.split(": ", 1)[1].replace("\\ ", "\0").split():
            path = Path(raw.replace("\0", " "))
            if not path.is_absolute():
                path = ROOT / path
            try:
                inputs.add(path.resolve().relative_to(ROOT).as_posix())
            except ValueError:
                pass
    return inputs


def reverse_deps() -> dict[str, set[str]]:
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--offline"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    names = {p["id"]: p["name"] for p in meta["packages"] if p["source"] is None}
    rdeps: dict[str, set[str]] = {n: set() for n in names.values()}
    for node in meta["resolve"]["nodes"]:
        if node["id"] not in names:
            continue
        for dep in node["deps"]:
            # A normal edge only: a dev-dependency reaches the dependent's test units alone.
            if dep["pkg"] in names and any(k["kind"] is None for k in dep["dep_kinds"]):
                rdeps[names[dep["pkg"]]].add(names[node["id"]])
    closed: dict[str, set[str]] = {}
    for n in rdeps:
        seen: set[str] = set()
        stack = [n]
        while stack:
            for r in rdeps[stack.pop()]:
                if r not in seen:
                    seen.add(r)
                    stack.append(r)
        closed[n] = seen
    return closed


def expected_rebuilt(
    baseline: list[dict], planted: str, rdeps: dict[str, set[str]]
) -> set[str]:
    direct = {unit_key(m) for m in baseline if planted in dep_info_inputs(m)}
    lib_pkgs = {
        pkg_name(m)
        for m in baseline
        if unit_key(m) in direct
        and not m["profile"]["test"]
        and "lib" in m["target"]["kind"]
    }
    widened = set(lib_pkgs)
    for pkg in lib_pkgs:
        widened |= rdeps.get(pkg, set())
    # A rebuilt library leaves its dependents' build-script compile units alone: those
    # link the build-dependencies, never the package's own dependencies.
    return direct | {
        unit_key(m)
        for m in baseline
        if pkg_name(m) in widened and "custom-build" not in m["target"]["kind"]
    }


def compare(label: str, arts: list[dict], expected: set[str]) -> list[str]:
    """Return every disagreement between the units cargo rebuilt and `expected`."""
    rebuilt = {unit_key(m) for m in arts if not m["fresh"]}
    seen = {unit_key(m) for m in arts}
    problems = []
    for u in sorted(expected - rebuilt):
        problems.append(
            f"{label}: {u} was reused from the archive, but an input of it changed"
        )
    for u in sorted(rebuilt - expected):
        problems.append(f"{label}: {u} was rebuilt, but no input of it changed")
    for u in sorted(expected - seen):
        problems.append(f"{label}: {u} expected in the build, absent")
    print(
        f"{label}: {len(rebuilt)} of {len(seen)} workspace units rebuilt, {len(expected)} expected"
    )
    return problems


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    return [p.decode() for p in out.split(b"\0") if p]


def fresh_checkout_mtimes() -> None:
    """Give every tracked file the time a new checkout gives it: now, after every unit."""
    for p in tracked():
        full = ROOT / p
        if full.is_file() and not full.is_symlink():
            os.utime(full)


def restore(archive: Path) -> None:
    subprocess.run([*CACHE, "clean", "--target", str(TARGET)], cwd=ROOT, check=True)
    fresh_checkout_mtimes()
    subprocess.run(
        [*CACHE, "restore", "--target", str(TARGET), "--archive", str(archive)],
        cwd=ROOT,
        check=True,
    )


def flip_byte(rel: str, old: bytes, new: bytes) -> bytes:
    """Replace the last `old` byte of `rel` with `new`; return the original content."""
    path = ROOT / rel
    original = path.read_bytes()
    idx = original.rfind(old)
    if idx < 0:
        raise SystemExit(f"{rel} holds no {old!r} to change")
    path.write_bytes(original[:idx] + new + original[idx + 1 :])
    return original


def main() -> int:
    rdeps = reverse_deps()
    baseline = build()
    print(f"baseline: {len(baseline)} workspace units")
    tmp = Path(tempfile.mkdtemp())
    archive = tmp / "units.tar.zst"
    subprocess.run(
        [*CACHE, "pack", "--target", str(TARGET), "--out", str(archive)],
        cwd=ROOT,
        check=True,
    )

    restore(archive)
    for p in compare("none", build(), set()):
        fail(p)

    # The source plant turns a space into a tab, which changes no behaviour, so only the
    # rebuild assertion sees it. The fixture plant drops the closing brace, so every test
    # reading the fixture fails if, and only if, the unit compiled the new bytes.
    plants = (
        ("source-byte", SOURCE_FILE, b" ", b"\t"),
        ("include-byte", INCLUDE_FILE, b"}", b" "),
    )
    for label, rel, old, new in plants:
        expected = expected_rebuilt(baseline, rel, rdeps)
        if not expected:
            fail(
                f"{label}: no unit lists {rel} as an input, so the plant tests nothing"
            )
            continue
        original = flip_byte(rel, old, new)
        try:
            restore(archive)
            problems = compare(label, build(), expected)
            for p in problems:
                fail(p)
            if label == "include-byte":
                proc = subprocess.run(
                    FIXTURE_TEST, cwd=ROOT, capture_output=True, text=True, check=False
                )
                if proc.returncode == 0:
                    fail(
                        "include-byte: the fixture test passed against the changed fixture, so it did not read the new bytes"
                    )
                else:
                    print(
                        "include-byte: the fixture test fails against the changed fixture, as it must"
                    )
            # Must-fail control: the mtime an mtime- or commit-time-based mechanism leaves.
            restore(archive)
            os.utime(ROOT / rel, (OLD_MTIME, OLD_MTIME))
            control = compare(f"{label} control", build(), expected)
            if not control:
                fail(
                    f"{label} control: the assertion did not see a unit reused across a changed {rel}"
                )
            else:
                print(
                    f"{label} control: the assertion reports the stale reuse, as it must"
                )
        finally:
            (ROOT / rel).write_bytes(original)

    expected_env = {
        unit_key(m)
        for m in baseline
        if pkg_name(m) == "scp-ffi-napi" and "custom-build" not in m["target"]["kind"]
    }
    folder = tmp / "typedefs"
    folder.mkdir()
    restore(archive)
    for p in compare("build-env control", build(), set()):
        fail(p)
    if any(folder.iterdir()):
        fail(
            "build-env control: the type-definition folder filled without the variable set"
        )
    restore(archive)
    for p in compare(
        "build-env", build({"NAPI_TYPE_DEF_TMP_FOLDER": str(folder)}), expected_env
    ):
        fail(p)
    if not any(folder.iterdir()):
        fail(
            "build-env: scp-ffi-napi was not expanded again under the new NAPI_TYPE_DEF_TMP_FOLDER"
        )
    else:
        print(
            "build-env: napi-derive wrote type definitions under the new value, as it must"
        )

    shutil.rmtree(tmp, ignore_errors=True)
    if failures:
        print(f"{len(failures)} exactness failures")
        return 1
    print("workspace-unit reuse is exact for every plant, and every control is caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
