#!/usr/bin/env python3.12
"""Pack and restore a cargo target directory's workspace-crate units, reused only on equal content.

Cargo decides whether a workspace crate's compiled unit is fresh from two kinds of
fact. Everything but file contents (rustc version, profile, features, flags, the
values of every env var a unit declared through `env!`/`option_env!` or a build
script's `rerun-if-env-changed`, dependency fingerprints) it compares by value. File
inputs it compares by modification time: a source, an `include_str!`/`include_bytes!`
target, or a build script's `rerun-if-changed` path newer than the unit makes the unit
stale. A fresh checkout gives every file the checkout time, so a restored unit would
always look stale; a checkout that set file times from history could make an edited
file look older than the unit, and cargo would reuse a stale build.

This script takes the time comparison out of history. `pack` runs after the writer's
build: it stores every workspace unit together with the git blob id of every tracked
file at build time (`manifest.json`), and it fails when any unit read a file that is
neither tracked, nor under the target directory, nor under the cargo home or the
toolchain, because content of such a file is in no key and no manifest. `restore`
extracts the units and sets every tracked file whose blob id equals the manifest's to
an mtime older than every unit, and every other tracked file (edited, added, or whose
path is new) to an mtime newer than every unit. Untracked files keep the time they
have, which is newer than every unit. Cargo then rebuilds exactly the units whose
file inputs changed, and their dependents, by its own rules.

Usage:
  ci-workspace-cache.py pack    --target DIR --out ARCHIVE [--workspace DIR]
  ci-workspace-cache.py restore --target DIR --archive ARCHIVE [--workspace DIR]
  ci-workspace-cache.py inputs  --target DIR [--workspace DIR]   (coverage check only)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Older than any unit any writer can have built; 2000-01-01T00:00:00Z.
OLD_MTIME = 946_684_800
UNIT_DIRS = ("deps", ".fingerprint", "build")
MANIFEST = "workspace-cache-manifest.json"
HASH16 = re.compile(r"-[0-9a-f]{16}(?:\.[A-Za-z0-9_.]+)?$")


def run(cmd: list[str], cwd: Path) -> bytes:
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True).stdout


def workspace_names(workspace: Path) -> set[str]:
    """Package and target names of every member, in both the `-` and `_` spelling."""
    meta = json.loads(
        run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
            workspace,
        )
    )
    names: set[str] = set()
    for pkg in meta["packages"]:
        names.add(pkg["name"])
        for tgt in pkg["targets"]:
            names.add(tgt["name"])
    return names | {n.replace("-", "_") for n in names}


def is_workspace_entry(name: str, names: set[str]) -> bool:
    if name.startswith("lib"):
        stripped = name[3:]
        if is_workspace_entry(stripped, names):
            return True
    m = HASH16.search(name)
    if not m:
        return False
    return name[: m.start()] in names


def profile_dirs(target: Path) -> list[Path]:
    """Every directory under the target dir that holds a `.fingerprint` (one per profile and triple)."""
    found = []
    for fp in target.glob(".fingerprint"):
        found.append(fp.parent)
    for depth in ("*", "*/*"):
        for fp in target.glob(f"{depth}/.fingerprint"):
            found.append(fp.parent)
    return sorted(set(found))


def workspace_files(target: Path, names: set[str]) -> list[Path]:
    """Files under each profile dir that rust-cache does not keep: workspace units and uplifted outputs."""
    out: list[Path] = []
    for prof in profile_dirs(target):
        for entry in prof.iterdir():
            if entry.name in UNIT_DIRS:
                for unit in entry.iterdir():
                    if is_workspace_entry(unit.name, names):
                        out.extend(walk(unit))
                if entry.name == "deps":
                    out.extend(sole_unhashed_outputs(prof, entry, names))
            elif entry.name == "incremental" or (
                entry.name.startswith(".cargo-") and entry.name.endswith("lock")
            ):
                continue
            else:
                out.extend(walk(entry))
    return out


def sole_unhashed_outputs(prof: Path, deps: Path, names: set[str]) -> list[Path]:
    """A workspace lib's cdylib or staticlib outputs in `deps`, kept only when one lib unit wrote them.

    Cargo names a cdylib or staticlib in `deps` without the metadata hash
    (`libscp_ffi.so`), so every feature set of the package writes the same path and the
    file holds whichever unit ran last. A lib unit's fingerprint does not cover that
    file's content. The file is packed only when the profile holds exactly one lib unit
    of that target, whose output it must be; with two or more, it stays out and cargo
    rebuilds the unit on restore because its output is missing.
    """
    lib_units: dict[str, int] = {}
    for unit in (prof / ".fingerprint").iterdir():
        if not is_workspace_entry(unit.name, names):
            continue
        for f in unit.iterdir():
            if f.name.startswith("lib-") and f.name.endswith(".json"):
                stem = f.name[len("lib-") : -len(".json")]
                lib_units[stem] = lib_units.get(stem, 0) + 1
    out: list[Path] = []
    for f in deps.iterdir():
        if HASH16.search(f.name) or not f.is_file() or f.suffix == ".o":
            continue
        stem = f.name.split(".", 1)[0]
        stem = stem[3:] if stem.startswith("lib") and stem[3:] in lib_units else stem
        if stem in names and lib_units.get(stem) == 1:
            out.append(f)
    return out


def walk(p: Path) -> list[Path]:
    if p.is_symlink() or p.is_file():
        return [p]
    if p.is_dir():
        res = []
        for root, _dirs, files in os.walk(p):
            res.extend(Path(root) / f for f in files)
        return res
    return []


def tracked_blobs(workspace: Path) -> dict[str, str]:
    """Path -> blob id of every tracked file as the working tree holds it now."""
    blobs: dict[str, str] = {}
    for rec in run(["git", "ls-files", "-s", "-z"], workspace).split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, sha, _stage = meta.split()
        blobs[path.decode()] = (
            sha.decode() if mode != b"160000" else "submodule:" + sha.decode()
        )
    modified = [
        p.decode()
        for p in run(
            ["git", "diff", "--name-only", "-z", "--no-renames"], workspace
        ).split(b"\0")
        if p
    ]
    for path in modified:
        full = workspace / path
        if full.is_file():
            blobs[path] = (
                run(["git", "hash-object", "--", path], workspace).decode().strip()
            )
        else:
            blobs[path] = "missing"
    return blobs


def environment_descriptor() -> dict[str, str]:
    """Inputs outside files and cargo's fingerprint that a workspace build script reads.

    crates/scp-ffi/build.rs asks python3.12 for its LIBDIR on macOS and declares no
    rerun directive, and a C compiler that crates/scp-ffi/napi-test-stubs/build.rs runs
    comes with the runner image, so the image and the interpreter are part of the key.
    """
    desc = {
        "image": f"{os.environ.get('ImageOS', '')}/{os.environ.get('ImageVersion', '')}",
        "rustc": subprocess.run(
            ["rustc", "-vV"], capture_output=True, text=True, check=True
        ).stdout,
    }
    try:
        desc["python_libdir"] = subprocess.run(
            [
                "python3.12",
                "-c",
                "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        desc["python_libdir"] = ""
    return desc


def dep_info_paths(dfile: Path) -> list[str]:
    """Every input path a rustc makefile dep-info file lists."""
    text = dfile.read_text(errors="replace")
    paths: list[str] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        _, sep, rest = line.partition(": ")
        if not sep:
            continue
        cur = ""
        i = 0
        while i < len(rest):
            ch = rest[i]
            if ch == "\\" and i + 1 < len(rest) and rest[i + 1] == " ":
                cur += " "
                i += 2
                continue
            if ch == " ":
                if cur:
                    paths.append(cur)
                cur = ""
            else:
                cur += ch
            i += 1
        if cur:
            paths.append(cur)
    return paths


def build_script_paths(output: Path, pkg_root_guess: Path | None) -> list[str]:
    paths = []
    for line in output.read_text(errors="replace").splitlines():
        for prefix in ("cargo:rerun-if-changed=", "cargo::rerun-if-changed="):
            if line.startswith(prefix):
                p = line[len(prefix) :]
                if pkg_root_guess is not None and not os.path.isabs(p):
                    p = str(pkg_root_guess / p)
                paths.append(p)
    return paths


def package_roots(workspace: Path) -> dict[str, Path]:
    meta = json.loads(
        run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
            workspace,
        )
    )
    return {p["name"]: Path(p["manifest_path"]).parent for p in meta["packages"]}


def package_mtime_build_runs(prof: Path, names: set[str]) -> list[str]:
    """Workspace build-script runs that cargo fingerprints by the package's newest file mtime.

    A build script that prints no `rerun-if-changed` or `rerun-if-env-changed` gets that
    fallback: cargo stores "<newest mtime> (<file>)" over every file of the package. The
    restore rewrites every tracked file's mtime, so the stored value never matches and
    every reader reruns the script and rebuilds the package and its dependents. That
    rebuild is safe but repeats on every reader, so the pack refuses it, and the build
    script declares the inputs it reads.
    """
    problems: list[str] = []
    fp = prof / ".fingerprint"
    if not fp.is_dir():
        return problems
    for unit in fp.iterdir():
        if not is_workspace_entry(unit.name, names):
            continue
        for f in unit.glob("run-build-script-*.json"):
            local = json.loads(f.read_text()).get("local", [])
            if any("Precalculated" in entry for entry in local):
                problems.append(
                    f"{f}: the build script of {unit.name} prints no rerun-if-changed or "
                    "rerun-if-env-changed, so cargo keys its run on the package's newest "
                    "file mtime; declare the inputs it reads"
                )
    return problems


def check_inputs(
    workspace: Path, target: Path, names: set[str], blobs: dict[str, str]
) -> list[str]:
    """Return every input path of a workspace unit that no manifest entry or key covers."""
    ws = workspace.resolve()
    tgt = target.resolve()
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    sysroot = Path(
        subprocess.run(
            ["rustc", "--print", "sysroot"], capture_output=True, text=True, check=True
        ).stdout.strip()
    ).resolve()
    roots = package_roots(workspace)
    problems: list[str] = []
    checked = 0
    for prof in profile_dirs(target):
        problems.extend(package_mtime_build_runs(prof, names))
        sources: list[tuple[Path, list[str]]] = []
        deps = prof / "deps"
        if deps.is_dir():
            for d in deps.glob("*.d"):
                if is_workspace_entry(d.name, names):
                    sources.append((d, dep_info_paths(d)))
        build = prof / "build"
        if build.is_dir():
            for unit in build.iterdir():
                if not is_workspace_entry(unit.name, names):
                    continue
                out = unit / "output"
                if out.is_file():
                    pkg = unit.name[: HASH16.search(unit.name).start()]
                    sources.append((out, build_script_paths(out, roots.get(pkg))))
        for src, paths in sources:
            for raw in paths:
                p = Path(raw)
                if not p.is_absolute():
                    p = ws / p
                try:
                    rp = p.resolve()
                except OSError:
                    rp = p
                checked += 1
                if (
                    rp.is_relative_to(tgt)
                    or rp.is_relative_to(cargo_home)
                    or rp.is_relative_to(sysroot)
                ):
                    continue
                if rp.is_relative_to(ws):
                    rel = rp.relative_to(ws).as_posix()
                    if rel in blobs:
                        continue
                    if rp.is_dir() and any(k.startswith(rel + "/") for k in blobs):
                        continue
                    if not rp.exists():
                        # Cargo treats a missing input as stale, so it rebuilds; nothing to cover.
                        continue
                problems.append(
                    f"{src}: input {raw} is not tracked by git, not under the target dir, cargo home or toolchain"
                )
    print(f"checked {checked} input paths of workspace units under {target}")
    return problems


def cmd_pack(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    target = Path(args.target).resolve()
    names = workspace_names(workspace)
    blobs = tracked_blobs(workspace)
    problems = check_inputs(workspace, target, names, blobs)
    if problems:
        for p in problems:
            print(f"::error::{p}")
        print(
            f"::error::{len(problems)} workspace-unit inputs are outside the manifest; not packing"
        )
        return 1
    files = workspace_files(target, names)
    if not files:
        print(f"::error::{target} holds no workspace unit, so there is nothing to pack")
        return 1
    built_at = max((f.lstat().st_mtime for f in files), default=time.time())
    manifest = {
        "version": 1,
        "built_at": built_at,
        "blobs": blobs,
        "environment": environment_descriptor(),
    }
    out = Path(args.out)
    (target / MANIFEST).write_text(json.dumps(manifest, sort_keys=True))
    rel = [MANIFEST] + [f.relative_to(target).as_posix() for f in files]
    listing = out.with_suffix(".list")
    listing.write_text("\0".join(rel) + "\0")
    subprocess.run(
        [
            "tar",
            "--zstd",
            "-cf",
            str(out),
            "-C",
            str(target),
            "--null",
            "-T",
            str(listing),
        ],
        check=True,
    )
    size = out.stat().st_size
    print(
        f"packed {len(files)} files of workspace units from {target} into {out}: {size / 1048576:.1f} MiB"
    )
    return 0


def cmd_inputs(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    target = Path(args.target).resolve()
    problems = check_inputs(
        workspace, target, workspace_names(workspace), tracked_blobs(workspace)
    )
    for p in problems:
        print(f"::error::{p}")
    return 1 if problems else 0


def cmd_clean(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    target = Path(args.target).resolve()
    files = workspace_files(target, workspace_names(workspace))
    for f in files:
        f.unlink(missing_ok=True)
    print(f"removed {len(files)} files of workspace units from {target}")
    return 0


def set_mtime(path: Path, t: float) -> None:
    os.utime(path, (t, t), follow_symlinks=False)


def cmd_restore(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    target = Path(args.target).resolve()
    target.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["tar", "--zstd", "-xf", args.archive, "-C", str(target)], check=True
    )
    manifest = json.loads((target / MANIFEST).read_text())
    env_now = environment_descriptor()
    if manifest["environment"] != env_now:
        diff = sorted(
            k for k in env_now if manifest["environment"].get(k) != env_now[k]
        )
        print(
            f"environment differs from the writer's ({', '.join(diff)}); removing the restored units"
        )
        names = workspace_names(workspace)
        for f in workspace_files(target, names):
            f.unlink(missing_ok=True)
        return 0
    old_blobs: dict[str, str] = manifest["blobs"]
    new_blobs = tracked_blobs(workspace)
    newer = max(time.time(), manifest["built_at"] + 2)
    changed_dirs: set[str] = set()
    unchanged = changed = 0
    for path, blob in new_blobs.items():
        full = workspace / path
        if not full.exists() and not full.is_symlink():
            continue
        if old_blobs.get(path) == blob:
            set_mtime(full, OLD_MTIME)
            unchanged += 1
        else:
            set_mtime(full, newer)
            changed += 1
            changed_dirs.add(os.path.dirname(path))
    for path in old_blobs.keys() - new_blobs.keys():
        changed_dirs.add(os.path.dirname(path))
    dirs: set[str] = set()
    for path in new_blobs:
        d = os.path.dirname(path)
        while d and d not in dirs:
            dirs.add(d)
            d = os.path.dirname(d)
    stale_dirs: set[str] = set()
    for d in changed_dirs:
        while d:
            stale_dirs.add(d)
            d = os.path.dirname(d)
    for d in dirs:
        full = workspace / d
        if full.is_dir():
            set_mtime(full, newer if d in stale_dirs else OLD_MTIME)
    print(
        f"restored workspace units into {target}: {unchanged} tracked files unchanged, {changed} changed or new"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("pack", "restore", "inputs", "clean"):
        p = sub.add_parser(name)
        p.add_argument("--workspace", default=".")
        p.add_argument("--target", required=True)
        if name == "pack":
            p.add_argument("--out", required=True)
        if name == "restore":
            p.add_argument("--archive", required=True)
    args = ap.parse_args()
    return {
        "pack": cmd_pack,
        "restore": cmd_restore,
        "inputs": cmd_inputs,
        "clean": cmd_clean,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
