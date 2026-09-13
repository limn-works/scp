#!/usr/bin/env python3.12
"""Two checks over every cargo step in every workflow under `.github/workflows/`.

Both checks exist because the same defect landed twice in one week and a reader
cannot see either defect in a workflow file without holding the whole file in mind:
a step that looks correct on its own is wrong because of a step forty lines away.

CHECK 1 — every `Swatinem/rust-cache` step names its group and says whether it writes.

  The criterion: a step carries `with.shared-key` (a non-empty string), carries no
  `with.key`, and carries `with.save-if`; across every workflow file, each `shared-key`
  has exactly one step whose `save-if` is not the literal `false`, and that step's
  `save-if` names `refs/heads/main`.

  Why: `Swatinem/rust-cache` appends the job id to the key by default, so eighteen steps
  wrote eighteen copies of the same compiled dependencies against GitHub's 10 GB
  per-repository cap and evicted each other (`.docs/lessons/a-cache-that-never-
  restores-is-not-a-cache.md`). `shared-key` makes the jobs that write one target
  directory share one entry. `key` is dead beside `shared-key` — the action drops it
  when `shared-key` is set — so a reader who sees both believes the entries differ when
  they do not, and this check rejects the pair. A group with two writers lets whichever
  finishes first decide the entry's contents; a group with no writer never populates;
  a writer on any ref other than `main` writes an entry that only its own ref can read.
  The cap is per repository, not per workflow, so the count runs across every file.

CHECK 2 — every uniffi-bindgen step reads the library out of the directory its own
`cargo run` writes.

  The criterion: for every `run:` command of the form
  `cargo run [flags] --bin uniffi-bindgen -- generate … --library <path>`, the directory
  cargo writes for those flags — `target/<triple>/<profile>/` when `--target` is passed,
  `target/<profile>/` otherwise, where `<profile>` is `release` under `--release` and
  `debug` otherwise — is a prefix of `<path>`.

  Why: cargo shares no artifact between two target directories. When the `--library`
  path sits in a directory the `cargo run` does not write, one of two things is true:
  an earlier step built that directory and this `cargo run` compiles the same crate
  graph a second time into another one (six minutes on `macos-26`, measured on run
  34724307976), or no step built it and the path does not exist. The check reads only
  the `cargo run` command and the path, so it cannot tell the two apart and rejects
  both, because both are fixed the same way: pass the flags that name the directory
  the library sits in.

Exit 0 when every step passes, 1 otherwise. `--workflows-dir` points the checks at a
directory other than the repository's, which the cases under
`scripts/tests/workflow-compile-steps/` use.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

RUST_CACHE_ACTION = "Swatinem/rust-cache"
DEFAULT_BRANCH_REF = "refs/heads/main"

# `cargo run`, an optional `+toolchain`, then flags up to `--bin uniffi-bindgen`, then the
# rest of the command. Continuation lines are joined before this runs.
BINDGEN_RUN = re.compile(
    r"cargo(?:\s+\+\S+)?\s+run\s+(?P<flags>.*?)--bin\s+uniffi-bindgen\b(?P<rest>.*)"
)
TARGET_FLAG = re.compile(r"(?:^|\s)--target[=\s]+(?P<triple>\S+)")
PROFILE_FLAG = re.compile(r"(?:^|\s)--profile[=\s]+(?P<name>\S+)")
RELEASE_FLAG = re.compile(r"(?:^|\s)--release(?:\s|$)")
LIBRARY_FLAG = re.compile(r"(?:^|\s)--library[=\s]+(?P<path>\S+)")


def profile_directory(flags: str) -> str:
    if RELEASE_FLAG.search(flags):
        return "release"
    profile = PROFILE_FLAG.search(flags)
    if profile is None:
        return "debug"
    name = profile.group("name")
    return "debug" if name == "dev" else name


def written_directory(flags: str) -> str:
    """The directory `cargo run <flags>` writes its artifacts into, relative to the cwd."""
    target = TARGET_FLAG.search(flags)
    profile = profile_directory(flags)
    if target is None:
        return f"target/{profile}/"
    return f"target/{target.group('triple')}/{profile}/"


def join_continuations(script: str) -> str:
    return script.replace("\\\n", " ")


def is_false(value: object) -> bool:
    return value is False or (
        isinstance(value, str) and value.strip().lower() == "false"
    )


def load_jobs(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    if not isinstance(document, dict):
        return {}
    jobs = document.get("jobs")
    return jobs if isinstance(jobs, dict) else {}


def check_workflows(workflows_dir: Path) -> list[str]:
    failures: list[str] = []
    producers: dict[str, list[str]] = defaultdict(list)
    cache_steps = 0
    bindgen_steps = 0

    for path in sorted(workflows_dir.glob("*.yml")) + sorted(
        workflows_dir.glob("*.yaml")
    ):
        rel = path.name
        for job_id, job in load_jobs(path).items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                where = f"{rel}: job {job_id}, step {index + 1}"
                uses = step.get("uses")
                if isinstance(uses, str) and uses.startswith(RUST_CACHE_ACTION):
                    cache_steps += 1
                    failures.extend(check_cache_step(where, step, producers))
                run = step.get("run")
                if isinstance(run, str):
                    found, step_failures = check_bindgen_run(where, run)
                    bindgen_steps += found
                    failures.extend(step_failures)

    for group, writers in sorted(producers.items()):
        if len(writers) > 1:
            failures.append(
                f"cache group {group!r} has {len(writers)} steps whose save-if is not "
                f"false, and a group has exactly one writer: {', '.join(writers)}"
            )
        elif not writers:
            failures.append(
                f"cache group {group!r} has no step whose save-if is not false, so no "
                f"run ever writes it and every member misses"
            )

    print(
        f"OK: {cache_steps} rust-cache step(s) in {len(producers)} group(s), each group "
        f"with one writer on {DEFAULT_BRANCH_REF}"
        if not failures
        else f"{len(failures)} failure(s) across {cache_steps} rust-cache step(s) and "
        f"{bindgen_steps} uniffi-bindgen step(s)"
    )
    if not failures:
        print(
            f"OK: {bindgen_steps} uniffi-bindgen step(s), each reading the library out of "
            f"the directory its own `cargo run` writes"
        )
    return failures


def check_cache_step(
    where: str, step: dict, producers: dict[str, list[str]]
) -> list[str]:
    failures: list[str] = []
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        with_block = {}
    shared_key = with_block.get("shared-key")
    if not isinstance(shared_key, str) or not shared_key.strip():
        failures.append(
            f"{where}: rust-cache step names no `shared-key`, so it writes its own entry "
            f"under the job id against the repository's 10 GB cache cap"
        )
        return failures
    if "key" in with_block:
        failures.append(
            f"{where}: rust-cache step names both `key` and `shared-key`; the action drops "
            f"`key` when `shared-key` is set, so remove `key`"
        )
    if "save-if" not in with_block:
        failures.append(
            f"{where}: rust-cache step in group {shared_key!r} names no `save-if`, so it "
            f"writes on every ref and the first job to finish decides the entry"
        )
        return failures
    save_if = with_block["save-if"]
    if is_false(save_if):
        producers.setdefault(shared_key, [])
        return failures
    producers[shared_key].append(where)
    if not (isinstance(save_if, str) and DEFAULT_BRANCH_REF in save_if):
        failures.append(
            f"{where}: the writer of cache group {shared_key!r} has save-if {save_if!r}, "
            f"which does not name {DEFAULT_BRANCH_REF}; an entry written on any other "
            f"ref is readable by that ref alone"
        )
    return failures


def check_bindgen_run(where: str, script: str) -> tuple[int, list[str]]:
    failures: list[str] = []
    found = 0
    for line in join_continuations(script).splitlines():
        match = BINDGEN_RUN.search(line)
        if match is None:
            continue
        found += 1
        flags = match.group("flags")
        rest = match.group("rest")
        library = LIBRARY_FLAG.search(rest)
        if library is None:
            failures.append(
                f"{where}: `cargo run --bin uniffi-bindgen` passes no `--library`, so this "
                f"check cannot tell which directory it reads"
            )
            continue
        writes = written_directory(flags)
        path = library.group("path")
        if not path.startswith(writes):
            failures.append(
                f"{where}: `cargo run` with flags {flags.strip()!r} writes {writes} and "
                f"the `--library` it reads is {path}; pass the `--release`/`--target` "
                f"flags that name the library's directory, or the crate graph compiles "
                f"twice (or the path does not exist)"
            )
    return found, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--workflows-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / ".github" / "workflows",
        help="directory holding the workflow files to check",
    )
    args = parser.parse_args()
    if not args.workflows_dir.is_dir():
        print(f"FAIL: {args.workflows_dir} is not a directory", file=sys.stderr)
        return 1
    failures = check_workflows(args.workflows_dir)
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
