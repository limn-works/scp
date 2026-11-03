#!/usr/bin/env python3.12
"""Fail when a workspace build script reruns although none of its inputs changed.

A build script that prints no `cargo:rerun-if-changed` or `cargo:rerun-if-env-changed`
line gets cargo's fallback: cargo reruns it whenever any file of its package is newer
than the last run. Editing a README, an AGENTS.md or a test file then reruns the script,
which rebuilds the package's library and every workspace package that depends on it.

Usage:
    check-build-script-rerun.py <cargo arguments>    e.g. build -p scp-ffi --features server
    check-build-script-rerun.py --self-test

The check runs `cargo <arguments>` once so every unit is fresh, writes a new file into
each workspace package whose build script ran, dated after every output, and runs the
same command again. No unit reads the new file, so every workspace unit must stay
fresh; a unit cargo compiles again names a build script that relies on the fallback.

`--self-test` runs the check on two one-crate workspaces: one whose build script prints
`cargo:rerun-if-changed=build.rs` (must pass) and one whose build script prints nothing
(must fail).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

PROBE = "build-script-rerun-probe.txt"


def cargo_json(args: list[str], cwd: Path, env: dict[str, str]) -> list[dict]:
    proc = subprocess.run(
        ["cargo", *args, "--message-format=json-render-diagnostics"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(f"`cargo {' '.join(args)}` failed in {cwd}")
    return [
        json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")
    ]


def package_dir(package_id: str) -> Path | None:
    """The directory of a path package, from ids such as `path+file:///x/scp-ffi#0.1.0`."""
    if not package_id.startswith("path+file://"):
        return None
    return Path(unquote(urlparse(package_id.removeprefix("path+").split("#")[0]).path))


def rebuilt_units(args: list[str], cwd: Path, env: dict[str, str]) -> list[str]:
    """Run the check; return each workspace unit cargo compiled again after the probe."""
    first = cargo_json(args, cwd, env)
    dirs = sorted(
        {
            d
            for m in first
            if m.get("reason") == "build-script-executed"
            and (d := package_dir(m["package_id"])) is not None
        }
    )
    if not dirs:
        raise SystemExit(f"`cargo {' '.join(args)}` ran no workspace build script")
    future = time.time() + 60
    probes = [d / PROBE for d in dirs]
    try:
        for probe in probes:
            probe.write_text("no unit reads this file\n")
            os.utime(probe, (future, future))
        second = cargo_json(args, cwd, env)
    finally:
        for probe in probes:
            probe.unlink(missing_ok=True)
    return [
        f"{m['target']['name']} ({'/'.join(m['target']['kind'])}) of {package_dir(m['package_id'])}"
        for m in second
        if m.get("reason") == "compiler-artifact"
        and not m.get("fresh", True)
        and package_dir(m["package_id"]) is not None
    ]


def check(args: list[str]) -> int:
    root = Path(__file__).resolve().parents[1]
    rebuilt = rebuilt_units(args, root, dict(os.environ))
    if rebuilt:
        print(
            "A new file that no unit reads made cargo compile these workspace units again, "
            "so a build script in their graph prints no rerun-if line and cargo reruns it "
            "whenever any file of its package changes. Print `cargo:rerun-if-changed` for "
            "each file the script reads (at least `build.rs`) and `cargo:rerun-if-env-changed` "
            "for each variable it reads:"
        )
        for unit in rebuilt:
            print(f"  {unit}")
        return 1
    print(f"`cargo {' '.join(args)}`: no build script reruns on an unrelated file")
    return 0


FIXTURE_MANIFEST = """[package]
name = "fixture"
version = "0.1.0"
edition = "2021"
build = "build.rs"

[workspace]
"""


def self_test() -> int:
    cases = {
        "declares": (
            'fn main() { println!("cargo:rerun-if-changed=build.rs"); }\n',
            False,
        ),
        "silent": ("fn main() {}\n", True),
    }
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, (script, must_fail) in cases.items():
            crate = Path(tmp) / name
            (crate / "src").mkdir(parents=True)
            (crate / "Cargo.toml").write_text(FIXTURE_MANIFEST)
            (crate / "build.rs").write_text(script)
            (crate / "src/lib.rs").write_text("pub fn f() {}\n")
            env = dict(os.environ, CARGO_TARGET_DIR=str(Path(tmp) / f"target-{name}"))
            rebuilt = rebuilt_units(["build"], crate, env)
            if bool(rebuilt) != must_fail:
                failures += 1
                print(
                    f"self-test {name}: expected {'a rebuild' if must_fail else 'no rebuild'}, "
                    f"got {rebuilt or 'none'}"
                )
            else:
                print(
                    f"self-test {name}: {'caught' if must_fail else 'passed'}, as it must"
                )
    return 1 if failures else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    sys.exit(check(sys.argv[1:]))
