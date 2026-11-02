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
  would then test code the canonical run never built;
- the `default-filter` of `.config/nextest.toml` leaves out a set of test binaries other
  than UNRUN_BINARIES below. Nextest applies that filter to every shard command, so it
  drops tests the way `-E` would. The filter may only be `not binary_id(<pkg>::<bin>)` or
  `not (binary_id(...) | ...)`, each binary it names must be a test target of a workspace
  member, and no profile other than `default` may set a `default-filter`. Leaving a
  binary out of CI therefore takes an edit to this file, where the reason is written.

A dependency a shard does not select may still resolve with fewer features than in the
canonical resolution, when only another member's declaration requested them and no shard
command can name them (cargo accepts `--features dep/feature` only for a dependency of a
selected package). The check prints each such difference and does not fail on it: the
package's own tests run in the shard that selects it, with its canonical features.

Job rust-test-prose runs a few test targets of packages the shards select, for pull
requests that edit only prose those targets read. Each of its commands takes the shard
form plus target selectors (`--lib`, `--test <name>`), and the check fails when one takes
any other argument, names a `--test` target with more than one `-p`, names a target the
package lacks, or resolves a selected package to features other than the canonical
resolution's, so each target compiles the code its shard compiles.

`--legs` prints one line per shard, `<shard>` then a tab then the shard command's `-p` and
`--features` arguments, read out of the workflow without invoking cargo.
`.github/workflows/compile-timings.yml` builds each line's arguments under `--timings`, so
it times the graphs rust-test compiles. It exits non-zero on any workflow `read_shards`
rejects.

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

import tomllib
import yaml

JOB = "rust-test"
READER_JOB = "rust-test-prose"
AXIS = "leg"
WORKFLOW = Path(".github/workflows/ci.yml")
TARGET = "x86_64-unknown-linux-gnu"
PUSH_LEG = "all"
NEXTEST_CONFIG = Path(".config/nextest.toml")
BINARY_ID = re.compile(r"binary_id\(([A-Za-z0-9_-]+)::([A-Za-z0-9_]+)\)")

# Test binaries the default nextest filter leaves out, so that no shard and no other CI
# job runs them. CI still compiles each one: the shards build every test binary of the
# packages they select before nextest applies the filter, and job rust-clippy lints them
# under `--all-targets`.
#
# scp-testing::perf_baseline is the ADR-049 Decision 14 benchmark. Without
# `SCP_PERF_GATE=1` it measures, writes a git-ignored JSON file and asserts nothing, so a
# CI run spends tens of seconds and checks nothing. Decision 14 asks for a before-and-after
# comparison on one machine, which an operator runs by hand.
UNRUN_BINARIES = {("scp-testing", "perf_baseline")}

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
    packages, features, _ = parse_targeted(line, targets_allowed=False)
    return packages, features


def parse_targeted(
    line: str, targets_allowed: bool = True
) -> tuple[list[str], list[str], list[str]]:
    """Return (packages, features, targets) of one command; targets are `lib` or `test:<name>`."""
    tokens = shlex.split(line)
    prefix = ["cargo", "nextest", "run", "--no-tests=fail"]
    if tokens[: len(prefix)] != prefix:
        raise CheckError(f"`{line}` does not start with `{' '.join(prefix)}`")
    packages: list[str] = []
    features: list[str] | None = None
    targets: list[str] = []
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
        elif targets_allowed and token == "--lib" and "lib" not in targets:
            targets.append("lib")
            index += 1
        elif targets_allowed and token == "--test" and index + 1 < len(rest):
            targets.append(f"test:{rest[index + 1]}")
            index += 2
        elif targets_allowed:
            raise CheckError(
                f"`{line}` passes `{token}`; a {READER_JOB} command takes only `-p <package>`, "
                f"one `--features <list>`, `--lib` and `--test <name>`"
            )
        else:
            raise CheckError(
                f"`{line}` passes `{token}`; a shard command takes only `-p <package>` and one "
                f"`--features <list>`, because any other argument can drop tests"
            )
    if not packages:
        raise CheckError(f"`{line}` selects no package with `-p`")
    if targets_allowed and not targets:
        raise CheckError(f"`{line}` selects no target with `--lib` or `--test`")
    if any(t.startswith("test:") for t in targets) and len(packages) != 1:
        raise CheckError(
            f"`{line}` names a `--test` target with {len(packages)} packages; cargo runs it "
            f"from whichever package has it, so a `--test` command selects one package"
        )
    return packages, features or [], targets


def read_reader_commands(
    document: dict,
) -> list[tuple[list[str], list[str], list[str]]]:
    """Return (packages, features, targets) of each test command job rust-test-prose runs."""
    job = (document.get("jobs") or {}).get(READER_JOB)
    if not isinstance(job, dict):
        return []
    commands = []
    for step in job.get("steps") or []:
        if not isinstance(step, dict) or "run" not in step:
            continue
        for line in logical_lines(str(step["run"])):
            if line.startswith(("cargo nextest", "cargo test")):
                commands.append(parse_targeted(line))
    if not commands:
        raise CheckError(f"job {READER_JOB} runs no test command")
    return commands


def target_failures(
    members: dict[str, list[str]],
    commands: list[tuple[list[str], list[str], list[str]]],
) -> list[str]:
    """Each rust-test-prose target its selected packages do not define."""
    failures = []
    for packages, _, targets in commands:
        for package in packages:
            if package not in members:
                failures.append(
                    f"{READER_JOB} names {package}, which is not a workspace member"
                )
                continue
            for target in targets:
                kinds = {t.split(":", 1)[0] for t in members[package]}
                present = (
                    bool(kinds & {"lib", "rlib", "cdylib", "staticlib", "proc-macro"})
                    if target == "lib"
                    else target in members[package]
                )
                if not present:
                    failures.append(
                        f"{READER_JOB}: package {package} has no target {target}"
                    )
    return failures


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


def default_filter_exclusions(config_text: str | None) -> set[tuple[str, str]]:
    """Return the (package, binary) pairs the default nextest profile's filter leaves out."""
    if config_text is None:
        return set()
    profiles = tomllib.loads(config_text).get("profile") or {}
    for name, profile in profiles.items():
        if name != "default" and "default-filter" in (profile or {}):
            raise CheckError(
                f"{NEXTEST_CONFIG} profile {name} sets a default-filter; only profile default may"
            )
    expression = str(
        (profiles.get("default") or {}).get("default-filter") or ""
    ).strip()
    if not expression:
        return set()
    grouped = re.fullmatch(r"not\s*\((.*)\)", expression, re.DOTALL)
    single = re.fullmatch(r"not\s+(binary_id\([^()]*\))", expression)
    inner = grouped.group(1) if grouped else single.group(1) if single else None
    matches = [BINARY_ID.fullmatch(term.strip()) for term in (inner or "").split("|")]
    if inner is None or not all(matches):
        raise CheckError(
            f"{NEXTEST_CONFIG} default-filter `{expression}` is not `not binary_id(<package>::"
            f"<binary>)` or `not (binary_id(...) | ...)`, so this check cannot tell which tests "
            f"it drops from the shards"
        )
    return {(match.group(1), match.group(2)) for match in matches if match}


def filter_failures(
    exclusions: set[tuple[str, str]],
    members: dict[str, list[str]],
    declared: set[tuple[str, str]] = UNRUN_BINARIES,
) -> list[str]:
    """Report each binary the default filter drops that UNRUN_BINARIES does not declare,
    each declared binary the filter runs, and each named binary that is no test target."""
    failures: list[str] = []
    for package, binary in sorted(exclusions - declared):
        failures.append(
            f"the default nextest filter leaves {package}::{binary} out of every shard, and "
            f"UNRUN_BINARIES does not declare it"
        )
    for package, binary in sorted(declared - exclusions):
        failures.append(
            f"UNRUN_BINARIES declares {package}::{binary}, and the default nextest filter "
            f"does not leave it out"
        )
    for package, binary in sorted(exclusions):
        if f"test:{binary}" not in members.get(package, []):
            failures.append(
                f"the default nextest filter names {package}::{binary}, which is no test "
                f"target of a workspace member"
            )
    return failures


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


def leg_lines(document: dict) -> list[str]:
    """Return `<shard>\t<-p and --features arguments>` for each shard command."""
    _, shards = read_shards(document)
    return [
        f"{shard}\t"
        + " ".join(
            selection_args(packages)
            + (["--features", ",".join(features)] if features else [])
        )
        for shard, (packages, features) in shards.items()
    ]


def legs(workflow: Path) -> int:
    for line in leg_lines(yaml.safe_load(workflow.read_text(encoding="utf-8"))):
        print(line)
    return 0


def check(workflow: Path) -> int:
    document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    canonical_features, shards = read_shards(document)
    members = workspace_members()
    failures = coverage_failures(members, shards)
    config_text = (
        NEXTEST_CONFIG.read_text(encoding="utf-8") if NEXTEST_CONFIG.exists() else None
    )
    failures += filter_failures(default_filter_exclusions(config_text), members)
    readers = read_reader_commands(document)
    failures += target_failures(members, readers)
    canonical, error = resolve(["--workspace"], canonical_features.split(","))
    if canonical is None:
        print(f"check-test-shard-features: the canonical resolution failed:\n{error}")
        return 1
    for packages, features, _ in readers:
        graph, error = resolve(selection_args(packages), features)
        label = f"{READER_JOB} -p {' -p '.join(packages)}"
        if graph is None:
            failures.append(f"{label}: cargo tree rejected the command:\n{error}")
            continue
        found, _ = feature_failures(canonical, graph, packages)
        failures += [f"{label}: {failure}" for failure in found]
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
        f"each selected package of every shard and of {len(readers)} {READER_JOB} command(s) "
        f"resolves to its canonical features, and the default nextest "
        f"filter leaves out exactly {', '.join(sorted(f'{p}::{b}' for p, b in UNRUN_BINARIES))}"
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

    expect(
        "--legs prints each shard's -p and --features arguments",
        leg_lines(base) == ["one\t-p a -p b --features a/x,b/y", "two\t-p c"],
        leg_lines(base),
    )
    try:
        leg_lines(yaml.safe_load(SELF_TEST_WORKFLOW.replace("-p c", "-p c --lib")))
        refused = "printed"
    except CheckError as error:
        refused = str(error)
    expect(
        "--legs refuses a shard command it cannot reproduce",
        "--lib" in refused,
        refused,
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

    expect(
        "the default filter's exclusions are read",
        default_filter_exclusions(
            '[profile.default]\ndefault-filter = "not binary_id(c::slow)"\n'
        )
        == {("c", "slow")}
        and default_filter_exclusions(None) == set()
        and default_filter_exclusions(
            "[profile.default]\n"
            'default-filter = "not (binary_id(c::slow) | binary_id(a::big))"\n'
        )
        == {("c", "slow"), ("a", "big")},
    )
    for label, text, needle in (
        (
            "a test() default filter",
            '[profile.default]\ndefault-filter = "not test(slow)"\n',
            "is not",
        ),
        (
            "a default filter on another profile",
            '[profile.ci]\ndefault-filter = "all()"\n',
            "profile ci",
        ),
    ):
        try:
            default_filter_exclusions(text)
            expect(f"{label} is rejected", False, "accepted")
        except CheckError as error:
            expect(f"{label} is rejected", needle in str(error), error)
    with_slow = {**members, "c": ["lib:c", "test:slow"]}
    slow = {("c", "slow")}
    expect(
        "a declared exclusion passes",
        not filter_failures(slow, with_slow, slow),
        filter_failures(slow, with_slow, slow),
    )
    found = filter_failures(slow, with_slow, set())
    expect(
        "an undeclared exclusion is reported",
        any("does not declare" in f for f in found),
        found,
    )
    found = filter_failures(set(), with_slow, slow)
    expect(
        "a declared binary the filter runs is reported",
        any("does not leave it out" in f for f in found),
        found,
    )
    found = filter_failures({("c", "absent")}, with_slow, {("c", "absent")})
    expect(
        "an excluded binary that is no test target is reported",
        any("no test target" in f for f in found),
        found,
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
    reader = yaml.safe_load(
        SELF_TEST_WORKFLOW
        + f"""
  {READER_JOB}:
    steps:
      - run: |
          cargo nextest run --no-tests=fail -p b --features a/x --test it
          cargo nextest run --no-tests=fail -p a -p c --lib
"""
    )
    readers = read_reader_commands(reader)
    expect(
        f"reads each {READER_JOB} command with its targets",
        readers == [(["b"], ["a/x"], ["test:it"]), (["a", "c"], [], ["lib"])],
        readers,
    )
    expect(
        f"{READER_JOB} targets every package defines pass",
        not target_failures(members, readers),
    )
    found = target_failures(members, [(["c"], [], ["test:it"]), (["d"], [], ["lib"])])
    expect(
        f"a {READER_JOB} target the package lacks, and a non-member, are reported",
        any("c has no target test:it" in f for f in found)
        and any("names d" in f for f in found),
        found,
    )
    expect(
        f"a workflow without {READER_JOB} has no reader commands",
        read_reader_commands(base) == [],
    )
    for label, run, needle in (
        (
            "a filter expression",
            "cargo nextest run --no-tests=fail -p b --test it -E 'test(x)'",
            "`-E`",
        ),
        (
            "no target selector",
            "cargo nextest run --no-tests=fail -p b",
            "selects no target",
        ),
        (
            "a --test target with two packages",
            "cargo nextest run --no-tests=fail -p a -p b --test it",
            "one package",
        ),
        (
            "a --workspace selection",
            "cargo nextest run --no-tests=fail --workspace --lib",
            "--workspace",
        ),
    ):
        try:
            parse_targeted(run)
            refused = "accepted"
        except CheckError as error:
            refused = str(error)
        expect(
            f"a {READER_JOB} command with {label} is refused",
            needle in refused,
            refused,
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
    elif args[:1] == ["--legs"]:
        mode = legs
        args = args[1:]
    workflow = Path(args[0]) if args else WORKFLOW
    try:
        return mode(workflow)
    except CheckError as error:
        print(f"check-test-shard-features: {workflow}: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
