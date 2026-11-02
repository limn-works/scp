#!/usr/bin/env python3.12
"""Every shipped package is compiled in a cargo invocation that resolves it alone.

CRITERION. A cargo invocation that compiles code (`cargo build`, `cargo rustc`,
`cargo install --path`, `cargo publish`, `cargo chef cook` without `--no-build`,
and the `cargo auditable build` and `cargo zigbuild` wrappers) in a shipping file
passes when both hold:

  1. it selects at most one SHIPPED package, a package named in
     `scripts/check-shipped-feature-graph.sh --print-artifacts`;
  2. for each shipped package it selects, the package's resolved graph under the
     invocation's own selection and feature flags equals the graph cargo resolves
     for that package selected alone under the same feature flags.

The shipping files are the SHIPPING_FILES array of
`scripts/check-shipped-feature-graph.sh` (the Dockerfile, which CI job
`docker-image` builds as shipped, and the build-matrix and release workflows),
read from that script's text so the two gates hold one list.

A resolved graph is the set of (package id, enabled features) pairs reachable from
the package over normal and build edges (`cargo tree -e normal,build --format
'{p}|{f}'`), for the invocation's `--target` when it names a literal triple and for
`x86_64-unknown-linux-gnu` otherwise (the Docker image's target, and the target a
`${{ matrix.target }}` leg resolves on ubuntu).

WHY. Cargo's resolver 2 unifies the features of every package one invocation
selects. The Dockerfile once built `-p scp-relay -p scp-node` in one invocation, so
the scp-relay binary it shipped carried `scp-transport/webpush`,
`scp-dht/production-dht`, and `scp-platform/{encrypting,sqlite,in-memory-storage}`,
features the scp-relay manifest does not ask for, while
`check-shipped-feature-graph.sh` resolved scp-relay alone and so gated a graph no
shipped build produced. Arm 1 rejects the joint selection by name. Arm 2 measures
the effect, so a selection arm 1 cannot see fails on what cargo resolves: no `-p`
at the workspace root, which selects every `default-members` package, or one
shipped package beside a non-shipped one that unifies features into it.

A workspace-root invocation that compiles no shipped artifact is declared in
DECLARED_NON_SHIPPING with the reason it ships nothing; a declaration that matches
no invocation fails, so a stale one cannot linger. `-p "$var"` inside
`for var in a b c; do` is one invocation per value. Any other shell variable or
workflow expression in a selection fails closed, because this reader cannot say
what it selects.

Exit 0 when every invocation passes, 1 otherwise. `--self-test` runs planted
cases, among them the joint `-p scp-relay -p scp-node` build, which must fail both
arms.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts/check-shipped-feature-graph.sh"
DEFAULT_TARGET = "x86_64-unknown-linux-gnu"
TRIPLE = re.compile(r"^[a-z0-9_]+(-[a-z0-9_.]+){2,3}$")
GH_EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
FOR_LOOP = re.compile(r"for\s+(\w+)\s+in\s+([^;\n]+?)\s*;\s*do")
SHELL_VAR = re.compile(r"^\$\{?(\w+)\}?$")

# (shipping file, the invocation as it reads with continuations joined): why it
# compiles no shipped artifact.
DECLARED_NON_SHIPPING: dict[tuple[str, str], str] = {
    (
        ".github/workflows/build-matrix.yml",
        "cargo build --release --target ${{ matrix.target }}",
    ): (
        "step 'Build all crates' is compile coverage across default-members; no "
        "upload reads its target/, and the shipped bridges come from the "
        "one-package-per-invocation loop into target-shipped"
    ),
}

# The token sequence after `cargo` that names a compiling subcommand.
COMPILING_VERBS: tuple[tuple[str, ...], ...] = (
    ("build",),
    ("rustc",),
    ("install",),
    ("publish",),
    ("chef", "cook"),
    ("auditable", "build"),
    ("zigbuild",),
)
SEPARATORS = {";", "&&", "||", "|", "&", "do", "then", "done", "fi"}
INSTALL_VALUE_FLAGS = {
    "--version",
    "--git",
    "--branch",
    "--tag",
    "--rev",
    "--root",
    "--index",
    "--registry",
    "--target",
    "--target-dir",
    "--features",
    "-F",
    "-j",
    "--jobs",
    "--profile",
    "--config",
    "-Z",
    "--bin",
    "--example",
}


@dataclass
class Invocation:
    file: str
    text: str
    packages: list[str]
    workspace: bool  # --workspace / --all, or no package selection at all
    feature_args: list[str]
    target: str
    unresolved: list[str] = field(default_factory=list)


def join_continued_lines(text: str) -> str:
    return re.sub(r"\\\n\s*", " ", text)


def loop_values(text: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for m in FOR_LOOP.finditer(text):
        values.setdefault(m.group(1), []).extend(m.group(2).split())
    return values


def installs_external_crate(args: list[str]) -> bool:
    """`cargo install <name>` without `--path` builds a registry or git crate."""
    k = 0
    external = False
    while k < len(args):
        a = args[k]
        if a == "--path" or a.startswith("--path="):
            return False
        if a in INSTALL_VALUE_FLAGS:
            k += 2
            continue
        if not a.startswith("-"):
            external = True
        k += 1
    return external


def expand_loop_variables(
    args: list[str], loops: dict[str, list[str]]
) -> list[list[str]]:
    """One argument list per value of each loop variable the arguments name.

    A loop body runs once per value, so `-p "$pkg"` inside
    `for pkg in a b; do ... done` is two invocations of one package each.
    """
    for k, a in enumerate(args):
        var = SHELL_VAR.match(a)
        if var and var.group(1) in loops:
            return [
                expanded
                for value in loops[var.group(1)]
                for expanded in expand_loop_variables(
                    [*args[:k], value, *args[k + 1 :]], loops
                )
            ]
    return [args]


def restore_exprs(text: str, exprs: list[str]) -> str:
    return re.sub(r"GHEXPR(\d+)", lambda m: exprs[int(m.group(1))], text)


def parse_invocations(file: str, text: str) -> list[Invocation]:
    text = join_continued_lines(text)
    loops = loop_values(text)
    found: list[Invocation] = []
    for raw in text.splitlines():
        if raw.lstrip().startswith("#") or "cargo" not in raw:
            continue
        # A workflow expression holds spaces; make it one token, restored for display.
        exprs = [m.group(0) for m in GH_EXPR.finditer(raw)]
        line = raw
        for n, expr in enumerate(exprs):
            line = line.replace(expr, f"GHEXPR{n}", 1)
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            tokens = line.split()
        i = 0
        while i < len(tokens):
            if tokens[i] != "cargo":
                i += 1
                continue
            end = i + 1
            while end < len(tokens) and tokens[end] not in SEPARATORS:
                end += 1
            args = tokens[i + 1 : end]
            i = end
            verb = next(
                (v for v in COMPILING_VERBS if tuple(args[: len(v)]) == v), None
            )
            if verb is None or (verb == ("chef", "cook") and "--no-build" in args):
                continue
            rest = args[len(verb) :]
            if verb == ("install",) and installs_external_crate(rest):
                continue
            shown = restore_exprs(" ".join(["cargo", *args]), exprs)
            for expanded in expand_loop_variables(rest, loops):
                found.append(build_invocation(file, shown, expanded, expanded != rest))
    return found


def build_invocation(
    file: str, shown: str, args: list[str], from_loop: bool
) -> Invocation:
    packages: list[str] = []
    unresolved: list[str] = []
    feature_args: list[str] = []
    workspace = False
    target = DEFAULT_TARGET
    k = 0
    while k < len(args):
        a = args[k]
        nxt = args[k + 1] if k + 1 < len(args) else ""
        value = None
        if a in ("-p", "--package"):
            value, k = nxt, k + 1
        elif a.startswith("--package="):
            value = a.split("=", 1)[1]
        elif a.startswith("-p") and len(a) > 2:
            value = a[2:]
        elif a == "--path" or a.startswith("--path="):
            unresolved.append(a if "=" in a else f"--path {nxt}")
            k += 0 if "=" in a else 1
        elif a in ("--workspace", "--all"):
            workspace = True
        elif a in ("--features", "-F"):
            feature_args += ["--features", nxt]
            k += 1
        elif a.startswith("--features="):
            feature_args += ["--features", a.split("=", 1)[1]]
        elif a.startswith("-F") and len(a) > 2:
            feature_args += ["--features", a[2:]]
        elif a in ("--all-features", "--no-default-features"):
            feature_args.append(a)
        elif a == "--target" or a.startswith("--target="):
            v = a.split("=", 1)[1] if "=" in a else nxt
            k += 0 if "=" in a else 1
            if TRIPLE.match(v):
                target = v
        elif a.startswith("$") or "GHEXPR" in a and not a.startswith("-"):
            # `$@`, `$ARGS`, `${{ ... }}` standing where a flag could be.
            unresolved.append(a)
        if value is not None:
            if "$" in value or "GHEXPR" in value:
                unresolved.append(value)
            else:
                packages.append(value)
        k += 1
    if any("$" in f or "GHEXPR" in f for f in feature_args):
        unresolved += [f for f in feature_args if "$" in f or "GHEXPR" in f]
    if not packages:
        workspace = True
    text = shown + (f"  [loop value {' '.join(packages)}]" if from_loop else "")
    return Invocation(file, text, packages, workspace, feature_args, target, unresolved)


def shipping_files() -> list[str]:
    """The SHIPPING_FILES array of check-shipped-feature-graph.sh, read from its text."""
    m = re.search(
        r"^SHIPPING_FILES=\(\n(.*?)^\)", GATE.read_text(), re.MULTILINE | re.DOTALL
    )
    names = re.findall(r'^\s*"([^"]+)"\s*$', m.group(1), re.MULTILINE) if m else []
    if not names:
        raise SystemExit(
            f"{GATE.name} carries no SHIPPING_FILES=( ... ) array naming a file"
        )
    return names


def shipped_packages() -> set[str]:
    out = subprocess.run(
        ["bash", str(GATE), "--print-artifacts"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    names = {line.split("|", 1)[0].strip() for line in out.splitlines() if line.strip()}
    if not names:
        raise SystemExit(f"{GATE.name} --print-artifacts printed no artifact")
    return names


def default_members() -> list[str]:
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    by_id = {p["id"]: p["name"] for p in meta["packages"]}
    members = [by_id[i] for i in meta.get("workspace_default_members", [])]
    if not members:
        raise SystemExit("cargo metadata reported no workspace default member")
    return members


TREE_LINE = re.compile(r"^(\d+)(.*?)\|([^|]*?)( \(\*\))?$")


def resolve(
    selection: list[str], feature_args: list[str], target: str
) -> dict[str, frozenset]:
    """Map each root package name to the (package id, features) pairs it reaches.

    `cargo tree` prints a node it already expanded anywhere in the output, under
    any root, as `(*)` with no children, so each root's set is the closure over
    the edges the whole output records, not the lines under that root.
    """
    cmd = [
        "cargo",
        "tree",
        "-q",
        "--offline",
        "-e",
        "normal,build",
        "--target",
        target,
        "--prefix",
        "depth",
        "--format",
        "{p}|{f}",
        *selection,
        *feature_args,
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"`{' '.join(cmd)}` failed:\n{proc.stderr.strip()}")
    children: dict[tuple, set[tuple]] = {}
    roots: list[tuple] = []
    stack: list[tuple] = []
    for line in proc.stdout.splitlines():
        m = TREE_LINE.match(line)
        if not m:
            continue
        depth = int(m.group(1))
        node = (
            m.group(2).strip(),
            ",".join(sorted(f for f in m.group(3).split(",") if f)),
        )
        del stack[depth:]
        if depth == 0:
            roots.append(node)
        elif len(stack) != depth:
            raise RuntimeError(
                f"`{' '.join(cmd)}` printed depth {depth} under depth {len(stack) - 1}"
            )
        else:
            children.setdefault(stack[-1], set()).add(node)
        children.setdefault(node, set())
        stack.append(node)
    if not roots:
        raise RuntimeError(f"`{' '.join(cmd)}` printed no root package")
    result: dict[str, frozenset] = {}
    for root in roots:
        seen = {root}
        todo = [root]
        while todo:
            for child in children[todo.pop()]:
                if child not in seen:
                    seen.add(child)
                    todo.append(child)
        result[root[0].split()[0]] = frozenset(seen)
    return result


def describe_diff(joint: frozenset, alone: frozenset) -> list[str]:
    def by_pkg(nodes: frozenset) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for pkg, feats in nodes:
            out.setdefault(re.sub(r" \(/.*\)$", "", pkg), set()).update(
                f for f in feats.split(",") if f
            )
        return out

    j, a = by_pkg(joint), by_pkg(alone)
    lines = []
    for pkg in sorted(set(j) | set(a)):
        if pkg not in a:
            lines.append(f"+ {pkg}: only in the invocation's graph")
        elif pkg not in j:
            lines.append(f"- {pkg}: only when resolved alone")
        elif j[pkg] != a[pkg]:
            added, removed = sorted(j[pkg] - a[pkg]), sorted(a[pkg] - j[pkg])
            lines.append(f"~ {pkg}: features +{added} -{removed}")
    return lines


def check(
    invocations: list[Invocation], shipped: set[str], members: list[str]
) -> list[str]:
    failures: list[str] = []
    used: set[tuple[str, str]] = set()
    cache: dict[tuple, dict[str, frozenset]] = {}

    def resolved(
        selection: list[str], features: list[str], target: str
    ) -> dict[str, frozenset]:
        key = (tuple(selection), tuple(features), target)
        if key not in cache:
            cache[key] = resolve(selection, features, target)
        return cache[key]

    for inv in invocations:
        where = f"{inv.file}: `{inv.text}`"
        if inv.unresolved:
            failures.append(
                f"{where} carries {inv.unresolved}, which this check cannot expand; "
                "name each package literally or loop over literal names"
            )
            continue
        if inv.workspace and not inv.packages:
            key = (inv.file, inv.text)
            if key in DECLARED_NON_SHIPPING:
                used.add(key)
                continue
            selected = members
            selection = (
                ["--workspace"]
                if "--workspace" in inv.text.split() or "--all" in inv.text.split()
                else []
            )
        else:
            selected = inv.packages
            selection = [arg for p in inv.packages for arg in ("-p", p)]
        hit = sorted(set(selected) & shipped)
        if len(hit) > 1:
            failures.append(
                f"{where} compiles {len(hit)} shipped packages in one invocation "
                f"({', '.join(hit)}); cargo unifies their features, so build each in its own invocation"
            )
        try:
            for pkg in hit:
                joint = resolved(selection, inv.feature_args, inv.target)
                alone = resolved(["-p", pkg], inv.feature_args, inv.target)
                if pkg not in joint or pkg not in alone:
                    failures.append(f"{where}: cargo tree printed no root for {pkg}")
                    continue
                diff = describe_diff(joint[pkg], alone[pkg])
                if diff:
                    failures.append(
                        f"{where} resolves {pkg} for {inv.target} differently from {pkg} alone:\n    "
                        + "\n    ".join(diff)
                    )
        except RuntimeError as err:
            failures.append(f"{where}: {err}")
    scanned = {inv.file for inv in invocations}
    for key, reason in DECLARED_NON_SHIPPING.items():
        if key[0] in scanned and key not in used:
            failures.append(
                f"DECLARED_NON_SHIPPING names `{key[1]}` in {key[0]} ({reason}), and no "
                "invocation there matches it; remove the stale declaration"
            )
    return failures


def run(
    files: list[tuple[str, str]], shipped: set[str], members: list[str]
) -> list[str]:
    invocations = [inv for name, text in files for inv in parse_invocations(name, text)]
    if not invocations:
        return [
            "the shipping files hold no compiling cargo invocation; the reader is broken"
        ]
    return check(invocations, shipped, members)


PLANTED: list[tuple[str, str, str, list[str]]] = [
    # (name, file, text, substrings the failures must carry; empty = must pass)
    (
        "the joint relay and node build fails both arms",
        "Dockerfile",
        "RUN cargo build --release --offline -p scp-relay -p scp-node\n",
        [
            "compiles 2 shipped packages",
            "resolves scp-relay for x86_64-unknown-linux-gnu differently",
            "scp-transport v0.1.0-beta.2: features +['webpush']",
        ],
    ),
    (
        "a joint cook split over a continuation fails",
        "Dockerfile",
        "RUN cargo chef cook --release --recipe-path r.json \\\n    -p scp-relay -p scp-node\n",
        ["compiles 2 shipped packages"],
    ),
    (
        "an undeclared workspace-root build fails",
        "planted.yml",
        "      run: cargo build --release\n",
        ["shipped packages in one invocation", "differently from scp-relay alone"],
    ),
    (
        "a selection hidden in an unknown variable fails closed",
        "planted.yml",
        '      run: cargo build --release -p "$PKG"\n',
        ["cannot expand"],
    ),
    (
        "one shipped package per invocation passes",
        "Dockerfile",
        "RUN cargo build --release -p scp-relay\nRUN cargo build --release -p scp-node\n",
        [],
    ),
    (
        "a for loop over literal names is one invocation per value and passes",
        "planted.yml",
        (
            "      run: |\n        for pkg in scp-relay scp-node; do\n"
            '          cargo build --release --target ${{ matrix.target }} -p "$pkg"\n        done\n'
        ),
        [],
    ),
    (
        "a --no-build cook compiles nothing and passes",
        "Dockerfile",
        "RUN cargo chef cook --release --recipe-path r.json --no-build\nRUN cargo build -p scp-relay\n",
        [],
    ),
    (
        "a declaration that matches no invocation fails",
        next(iter(DECLARED_NON_SHIPPING))[0],
        "      run: cargo build --release -p scp-relay\n",
        ["stale declaration"],
    ),
]


def self_test(shipped: set[str], members: list[str]) -> int:
    bad = 0
    for name, file, text, expected in PLANTED:
        failures = run([(file, text)], shipped, members)
        joined = "\n".join(failures)
        ok = (
            bool(failures) and all(e in joined for e in expected)
            if expected
            else not failures
        )
        print(f"{'PASS' if ok else 'FAIL'}: {name}")
        for f in failures:
            lines = f.splitlines()
            shown = lines[:8] + (
                [f"    ... {len(lines) - 8} more lines"] if len(lines) > 8 else []
            )
            print("    " + "\n    ".join(shown))
        bad += not ok
    return 1 if bad else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument(
        "--self-test", action="store_true", help="run the planted cases"
    )
    opts = parser.parse_args()
    shipped = shipped_packages()
    members = default_members()
    if opts.self_test:
        return self_test(shipped, members)
    files = [(name, (ROOT / name).read_text()) for name in shipping_files()]
    failures = run(files, shipped, members)
    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(
        "PASS: every compiling cargo invocation in "
        + ", ".join(name for name, _ in files)
        + " resolves each shipped package as cargo resolves it alone"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
