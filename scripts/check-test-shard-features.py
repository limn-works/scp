#!/usr/bin/env python3
"""Check that the package shards of `ci.yml`'s `rust-test` job run every workspace test once.

WHY IT EXISTS. Job rust-test used to run one `cargo nextest run --workspace` split with
`--partition count:k/4`. Nextest partitions the run, not the build, so each of the four
legs compiled all 160 test binaries and ran a quarter of the tests. The job now gives each
leg a set of packages (`-p`), so a leg compiles only the graph those packages need. Two
defects become possible that the partitioned form could not have:

1. A workspace member that no shard names runs none of its tests, and a member two shards
   name runs its tests twice. Every leg still passes.
2. Cargo resolves features across the packages one invocation selects. Under
   `--workspace`, every member's dependency declarations and the job's `TEST_FEATURES`
   list feed one resolution. Under `-p`, only the selected packages' declarations and the
   features the command names feed it. A package can therefore compile with fewer
   features in its shard than it did under `--workspace`, which removes every test and
   every code path behind `#[cfg(feature = ...)]` without any test failing.

THE CRITERION. The canonical resolution is `cargo tree --workspace --features
$TEST_FEATURES -e normal,build,dev` for target x86_64-unknown-linux-gnu, the target every
rust-test leg runs on, where `TEST_FEATURES` is the rust-test job's `env:` value. The check
fails when any of these holds:

- a workspace member, from `cargo metadata --no-deps`, is named by no shard command or by
  more than one, or a shard command names a package that is not a workspace member;
- a shard command is anything other than `cargo nextest run --no-tests=fail`, one or more
  `-p <package>`, and at most one `--features <list>`, because any other argument
  (`-E`, `--lib`, `--test`, `--partition`, `--exclude`) can drop tests from a package the
  shard names;
- a package a shard command selects resolves, in that shard, to a set of feature sets
  different from the canonical resolution's, because the package's own features decide
  which of its tests exist and what code they run;
- any package in a shard's resolved graph gets a feature the canonical resolution never
  gives it, or is a package the canonical resolution does not contain, because the shard
  would then test code the canonical run never built.

A dependency a shard does not select may still resolve with fewer features than in the
canonical resolution, when only another member's declaration requested them and no shard
command can name them (cargo accepts `--features dep/feature` only for a dependency of a
selected package). The check prints each such difference and does not fail on it: the
package's own tests run in the shard that selects it, with its canonical features.

`--suggest` prints, for each shard, the feature list that reproduces the canonical
resolution as far as cargo lets one command name features: it adds each missing
`package/feature` one at a time and keeps it when cargo accepts it and it adds no feature
or package the canonical resolution lacks. `--self-test` runs the checks on planted
failures without invoking cargo.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import yaml

JOB = "rust-test"
AXIS = "leg"
WORKFLOW = Path(".github/workflows/ci.yml")
TARGET = "x86_64-unknown-linux-gnu"
PUSH_LEG = "all"

FeatureGraph = dict[str, set[frozenset[str]]]


class CheckError(Exception):
    """A shard definition this check cannot read."""


def logical_lines(script: str) -> list[str]:
    """Return the script's lines with backslash continuations joined."""
    joined: list[str] = []
    pending = ""
    for raw in script.splitlines():
        stripped = raw.strip()
        if stripped.endswith("\\"):
            pending += stripped[:-1].rstrip() + " "
            continue
        joined.append(pending + stripped)
        pending = ""
    if pending:
        joined.append(pending.rstrip())
    return joined


def shard_of_condition(condition: object) -> str | None:
    """Return the shard a step `if:` of the form `matrix.leg == 'all' || matrix.leg == 'X'` names."""
    text = str(condition or "").strip()
    wrapped = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.DOTALL)
    text = (wrapped.group(1) if wrapped else text).strip()
    values = re.findall(rf"matrix\.{AXIS}\s*==\s*'([^']*)'", text)
    rest = re.sub(rf"matrix\.{AXIS}\s*==\s*'[^']*'", "", text).replace("||", "").strip()
    if rest or len(values) != 2 or PUSH_LEG not in values:
        return None
    return next(value for value in values if value != PUSH_LEG)


def parse_command(line: str) -> tuple[list[str], list[str]]:
    """Return (packages, features) of one shard command, or raise CheckError."""
    tokens = shlex.split(line)
    prefix = ["cargo", "nextest", "run", "--no-tests=fail"]
    if tokens[: len(prefix)] != prefix:
        raise CheckError(f"`{line}` does not start with `{' '.join(prefix)}`")
    packages: list[str] = []
    features: list[str] | None = None
    rest = tokens[len(prefix) :]
    index = 0
    while index < len(rest):
        token = rest[index]
        if token == "-p" and index + 1 < len(rest):
            packages.append(rest[index + 1])
            index += 2
        elif token == "--features" and index + 1 < len(rest) and features is None:
            features = [item for item in rest[index + 1].split(",") if item]
            index += 2
        else:
            raise CheckError(
                f"`{line}` passes `{token}`; a shard command takes only `-p <package>` and one "
                f"`--features <list>`, because any other argument can drop tests"
            )
    if not packages:
        raise CheckError(f"`{line}` selects no package with `-p`")
    return packages, features or []


def read_shards(document: dict) -> tuple[str, dict[str, tuple[list[str], list[str]]]]:
    """Return (TEST_FEATURES, {shard: (packages, features)}) out of a parsed workflow."""
    job = (document.get("jobs") or {}).get(JOB)
    if not isinstance(job, dict):
        raise CheckError(f"the workflow declares no job {JOB}")
    canonical = str((job.get("env") or {}).get("TEST_FEATURES") or "").strip()
    if not canonical:
        raise CheckError(f"job {JOB} sets no `env.TEST_FEATURES`")
    shards: dict[str, tuple[list[str], list[str]]] = {}
    for step in job.get("steps") or []:
        if not isinstance(step, dict) or "run" not in step:
            continue
        commands = [
            line
            for line in logical_lines(str(step["run"]))
            if line.startswith(("cargo nextest", "cargo test"))
        ]
        if not commands:
            continue
        shard = shard_of_condition(step.get("if"))
        if shard is None:
            raise CheckError(
                f"step {step.get('name')!r} runs `{commands[0]}` under `if: {step.get('if')}`, "
                f"which is not `matrix.{AXIS} == '{PUSH_LEG}' || matrix.{AXIS} == '<shard>'`"
            )
        if len(commands) != 1:
            raise CheckError(
                f"shard {shard} runs {len(commands)} test commands, not one"
            )
        if shard in shards:
            raise CheckError(f"two steps run shard {shard}")
        shards[shard] = parse_command(commands[0])
    if not shards:
        raise CheckError(f"job {JOB} runs no shard command")
    return canonical, shards


def coverage_failures(
    members: dict[str, list[str]], shards: dict[str, tuple[list[str], list[str]]]
) -> list[str]:
    """Report each member in no shard or in two, and each named package that is no member.

    `members` maps each workspace member to the test targets it declares, named in the
    report so a reader sees which tests run nowhere or twice.
    """
    failures: list[str] = []
    owners: dict[str, list[str]] = {}
    for shard, (packages, _) in shards.items():
        for package in packages:
            owners.setdefault(package, []).append(shard)
            if package not in members:
                failures.append(
                    f"shard {shard} names {package}, which is not a workspace member"
                )
    for member, targets in sorted(members.items()):
        named = owners.get(member, [])
        listed = ", ".join(targets) or "no test target"
        if not named:
            failures.append(
                f"workspace member {member} ({listed}) is in no shard, so its tests run nowhere"
            )
        elif len(named) > 1:
            failures.append(
                f"workspace member {member} ({listed}) is in shards {', '.join(named)}, so its "
                f"tests run {len(named)} times"
            )
    return failures


def feature_failures(
    canonical: FeatureGraph, shard_graph: FeatureGraph, selected: list[str]
) -> tuple[list[str], list[str]]:
    """Compare one shard's resolution with the canonical one. Returns (failures, notes).

    Graph keys are cargo tree `{p}` strings (`name vX.Y.Z (path)`); `selected` holds
    package names.
    """
    failures: list[str] = []
    notes: list[str] = []
    for package, variants in sorted(shard_graph.items()):
        name = package.split(" ", 1)[0]
        expected = canonical.get(package)
        if expected is None:
            failures.append(
                f"{package} resolves in the shard and not in the canonical run"
            )
            continue
        union = set().union(*expected)
        extra = set().union(*variants) - union
        if extra:
            failures.append(
                f"{package} gets {', '.join(sorted(extra))} in the shard and never in the canonical run"
            )
        if name in selected:
            if variants != expected:
                failures.append(
                    f"selected package {package} resolves to {fmt(variants)} in the shard and "
                    f"{fmt(expected)} in the canonical run"
                )
        elif variants != expected:
            missing = union - set().union(*variants)
            if missing:
                notes.append(f"{name} lacks {', '.join(sorted(missing))}")
    for name in selected:
        if not any(package.split(" ", 1)[0] == name for package in shard_graph):
            failures.append(
                f"selected package {name} is absent from the shard's resolved graph"
            )
    return failures, notes


def fmt(variants: set[frozenset[str]]) -> str:
    return " | ".join(sorted("{" + ",".join(sorted(v)) + "}" for v in variants))


def parse_tree(output: str) -> FeatureGraph:
    """Read `cargo tree --prefix none --format '{p}|{f}'` output into a FeatureGraph."""
    graph: FeatureGraph = {}
    for line in output.splitlines():
        # CI sets CARGO_TERM_COLOR=always; colored output would turn escape
        # codes into feature names, so refuse it instead of misreading it.
        if "\x1b" in line:
            raise ValueError(f"cargo tree output carries terminal escapes: {line!r}")
        line = line.strip().removesuffix(" (*)").strip()
        if "|" not in line:
            continue
        package, features = line.split("|", 1)
        graph.setdefault(package.strip(), set()).add(
            frozenset(item for item in features.split(",") if item)
        )
    return graph


def resolve(
    selection: list[str], features: list[str]
) -> tuple[FeatureGraph | None, str]:
    """Run cargo tree for one selection. Returns (graph, "") or (None, cargo's error)."""
    command = [
        "cargo",
        "tree",
        *selection,
        "--target",
        TARGET,
        "-e",
        "normal,build,dev",
    ]
    if features:
        command += ["--features", ",".join(features)]
    command += ["--prefix", "none", "--format", "{p}|{f}", "--color", "never"]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None, result.stderr.strip()
    return parse_tree(result.stdout), ""


def workspace_members() -> dict[str, list[str]]:
    """Return {member name: [test targets nextest runs]} from cargo metadata."""
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        check=True,
    )
    metadata = json.loads(result.stdout)
    members = set(metadata["workspace_members"])
    out: dict[str, list[str]] = {}
    for package in metadata["packages"]:
        if package["id"] not in members:
            continue
        out[package["name"]] = sorted(
            f"{kind}:{target['name']}"
            for target in package["targets"]
            for kind in target["kind"]
            if kind
            in ("lib", "rlib", "cdylib", "staticlib", "proc-macro", "bin", "test")
            and target.get("test", True)
        )
    return out


def selection_args(packages: list[str]) -> list[str]:
    return [arg for package in packages for arg in ("-p", package)]


def check(workflow: Path) -> int:
    document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    canonical_features, shards = read_shards(document)
    failures = coverage_failures(workspace_members(), shards)
    canonical, error = resolve(["--workspace"], canonical_features.split(","))
    if canonical is None:
        print(f"check-test-shard-features: the canonical resolution failed:\n{error}")
        return 1
    for shard, (packages, features) in shards.items():
        graph, error = resolve(selection_args(packages), features)
        if graph is None:
            failures.append(
                f"shard {shard}: cargo tree rejected the shard command:\n{error}"
            )
            continue
        found, notes = feature_failures(canonical, graph, packages)
        failures += [f"shard {shard}: {failure}" for failure in found]
        print(
            f"shard {shard}: {len(packages)} package(s), {len(graph)} resolved; "
            f"{len(notes)} unselected dependency(ies) resolve with fewer features than canonical"
            + (f": {'; '.join(notes)}" if notes else "")
        )
    for failure in failures:
        print(f"FAIL  {failure}")
    if failures:
        print(f"check-test-shard-features: {len(failures)} failure(s)")
        return 1
    print(
        f"check-test-shard-features: {len(shards)} shards cover every workspace member once, "
        f"and each selected package resolves to its canonical features"
    )
    return 0


def suggest(workflow: Path) -> int:
    document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    canonical_features, shards = read_shards(document)
    canonical, error = resolve(["--workspace"], canonical_features.split(","))
    if canonical is None:
        print(error)
        return 1
    for shard, (packages, _) in shards.items():
        selection = selection_args(packages)
        features = list(
            dict.fromkeys(
                f for f in canonical_features.split(",") if f.split("/")[0] in packages
            )
        )
        rejected: set[str] = set()
        while True:
            graph, error = resolve(selection, features)
            if graph is None:
                print(
                    f"shard {shard}: the canonical features naming its packages fail:\n{error}"
                )
                return 1
            candidates = []
            for package, variants in graph.items():
                name = package.split(" ", 1)[0]
                if sum(1 for other in graph if other.split(" ", 1)[0] == name) != 1:
                    continue
                missing = set().union(
                    *canonical.get(package, {frozenset()})
                ) - set().union(*variants)
                candidates += [f"{name}/{feature}" for feature in sorted(missing)]
            candidates = [
                c for c in candidates if c not in rejected and c not in features
            ]
            if not candidates:
                break
            for candidate in candidates:
                trial, _ = resolve(selection, [*features, candidate])
                # A candidate that cargo rejects, or that adds a feature or a package the
                # canonical resolution lacks, is dropped. A selected package's remaining
                # mismatch is what the candidates exist to close, so it does not count.
                if trial is None or any(
                    "canonical run" in failure
                    and not failure.startswith("selected package")
                    for failure in feature_failures(canonical, trial, packages)[0]
                ):
                    rejected.add(candidate)
                else:
                    features.append(candidate)
        print(f"{shard}: {','.join(features)}")
    return 0


SELF_TEST_WORKFLOW = """
jobs:
  rust-test:
    env:
      TEST_FEATURES: a/x,b/y
    steps:
      - uses: actions/checkout@v5
      - name: Run shard one
        if: matrix.leg == 'all' || matrix.leg == 'one'
        run: |
          cargo nextest run --no-tests=fail -p a -p b --features a/x,b/y
      - name: Run shard two
        if: matrix.leg == 'all' || matrix.leg == 'two'
        run: cargo nextest run --no-tests=fail -p c
"""


def self_test() -> int:
    failures = 0

    def expect(name: str, ok: bool, detail: object = "") -> None:
        nonlocal failures
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}{'' if ok else f' -> {detail}'}")

    base = yaml.safe_load(SELF_TEST_WORKFLOW)
    canonical, shards = read_shards(base)
    expect("reads TEST_FEATURES", canonical == "a/x,b/y", canonical)
    expect(
        "reads both shards",
        shards == {"one": (["a", "b"], ["a/x", "b/y"]), "two": (["c"], [])},
        shards,
    )

    members = {"a": ["lib:a"], "b": ["lib:b", "test:it"], "c": ["lib:c"]}
    expect("full coverage passes", not coverage_failures(members, shards))
    dropped = dict(shards, two=(["d"], []))
    found = coverage_failures({**members, "d": ["lib:d"]}, {"one": shards["one"]})
    expect(
        "a member in no shard is reported",
        any("member c" in f and "in no shard" in f for f in found),
        found,
    )
    found = coverage_failures(members, dict(shards, two=(["c", "b"], [])))
    expect(
        "a member in two shards is reported",
        any(
            "member b" in f and "shards one, two" in f and "test:it" in f for f in found
        ),
        found,
    )
    found = coverage_failures(members, dropped)
    expect(
        "a non-member package is reported", any("names d" in f for f in found), found
    )

    for label, run, needle in (
        (
            "a filter expression",
            "cargo nextest run --no-tests=fail -p c -E 'test(x)'",
            "`-E`",
        ),
        (
            "a partition",
            "cargo nextest run --no-tests=fail -p c --partition count:1/2",
            "--partition",
        ),
        ("a missing --no-tests=fail", "cargo nextest run -p c", "does not start"),
        (
            "a --lib target filter",
            "cargo nextest run --no-tests=fail -p c --lib",
            "--lib",
        ),
        (
            "a --workspace selection",
            "cargo nextest run --no-tests=fail --workspace",
            "--workspace",
        ),
    ):
        mutant = yaml.safe_load(SELF_TEST_WORKFLOW)
        mutant["jobs"]["rust-test"]["steps"][2]["run"] = run
        try:
            read_shards(mutant)
            expect(f"{label} is rejected", False, "accepted")
        except CheckError as error:
            expect(f"{label} is rejected", needle in str(error), error)

    mutant = yaml.safe_load(SELF_TEST_WORKFLOW)
    mutant["jobs"]["rust-test"]["steps"][2]["if"] = "matrix.leg == 'two'"
    try:
        read_shards(mutant)
        expect("a shard step the push leg skips is rejected", False, "accepted")
    except CheckError as error:
        expect(
            "a shard step the push leg skips is rejected", "is not" in str(error), error
        )

    mutant = yaml.safe_load(SELF_TEST_WORKFLOW)
    del mutant["jobs"]["rust-test"]["env"]
    try:
        read_shards(mutant)
        expect("a job without TEST_FEATURES is rejected", False, "accepted")
    except CheckError as error:
        expect(
            "a job without TEST_FEATURES is rejected",
            "TEST_FEATURES" in str(error),
            error,
        )

    a, b, dep = "a v0.1.0 (/w/a)", "b v0.1.0 (/w/b)", "dep v1.0.0"
    canon: FeatureGraph = {
        a: {frozenset({"x", "testing"})},
        b: {frozenset({"y"})},
        dep: {frozenset({"std", "net"})},
    }
    same = {key: set(value) for key, value in canon.items()}
    found, notes = feature_failures(canon, same, ["a", "b"])
    expect("an identical resolution passes", not found and not notes, (found, notes))

    fewer = dict(same, **{a: {frozenset({"x"})}})
    found, _ = feature_failures(canon, fewer, ["a", "b"])
    expect(
        "a selected package missing a canonical feature is reported",
        any("selected package a" in f for f in found),
        found,
    )
    extra = dict(same, **{dep: {frozenset({"std", "net", "test-util"})}})
    found, _ = feature_failures(canon, extra, ["a", "b"])
    expect(
        "a dependency feature the canonical run lacks is reported",
        any("test-util" in f and "never in the canonical run" in f for f in found),
        found,
    )
    new_package = dict(same, **{"rand v0.8.8": {frozenset({"std"})}})
    found, _ = feature_failures(canon, new_package, ["a", "b"])
    expect(
        "a package the canonical run lacks is reported",
        any("rand v0.8.8" in f and "not in the canonical run" in f for f in found),
        found,
    )
    deficit = dict(same, **{dep: {frozenset({"std"})}})
    found, notes = feature_failures(canon, deficit, ["a", "b"])
    expect(
        "an unselected dependency with fewer features is a note, not a failure",
        not found and notes == ["dep lacks net"],
        (found, notes),
    )
    found, _ = feature_failures(canon, {b: canon[b]}, ["a", "b"])
    expect(
        "a selected package absent from the shard graph is reported",
        any("selected package a is absent" in f for f in found),
        found,
    )
    two_variants: FeatureGraph = dict(
        canon, **{dep: {frozenset({"std"}), frozenset({"std", "net"})}}
    )
    found, _ = feature_failures(
        two_variants, dict(same, **{dep: {frozenset({"std", "net"})}}), ["dep"]
    )
    expect(
        "a selected package missing one of its canonical builds is reported",
        any("selected package dep" in f for f in found),
        found,
    )
    expect(
        "cargo tree output parses, with deduplicated repeats",
        parse_tree(
            "a v0.1.0 (/w/a)|x,testing\ndep v1.0.0|net,std\ndep v1.0.0|net,std (*)\n"
        )
        == {a: {frozenset({"x", "testing"})}, dep: {frozenset({"std", "net"})}},
    )
    try:
        parse_tree("dep v1.0.0|net,std \x1b[2m(*)\x1b[0m\n")
        colored = "parsed"
    except ValueError as error:
        colored = str(error)
    expect(
        "colored cargo tree output is refused, not read as feature names",
        "terminal escapes" in colored,
        colored,
    )
    if failures:
        print(f"check-test-shard-features self-test: {failures} case(s) failed")
        return 1
    print("check-test-shard-features self-test: every case passed")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args[:1] == ["--self-test"]:
        return self_test()
    mode = check
    if args[:1] == ["--suggest"]:
        mode = suggest
        args = args[1:]
    workflow = Path(args[0]) if args else WORKFLOW
    try:
        return mode(workflow)
    except CheckError as error:
        print(f"check-test-shard-features: {workflow}: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
