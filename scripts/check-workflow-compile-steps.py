#!/usr/bin/env python3.12
"""Four checks over the cargo steps and push runs of every workflow under `.github/workflows/`.

The first two exist because the same defect landed twice in one week and a reader
cannot see either defect in a workflow file without holding the whole file in mind:
a step that looks correct on its own is wrong because of a step forty lines away.

CHECK 1 — every `./.github/actions/rust-cache` step names its group and says whether it writes.

  The criterion: a step carries `with.shared-key` (a non-empty string), carries no
  `with.key`, and carries `with.save-if`; across every workflow file, each `shared-key`
  has exactly one step whose `save-if` is not the literal `false`, and that step's
  `save-if` passes gated_to_main: one `${{ }}` expression with no top-level `||`, one of
  whose top-level `&&` terms is exactly `github.ref == 'refs/heads/main'`.
  scripts/tests/ci-gate/ci_gate_selftest.py's main-only-writers check judges every other
  Actions-cache writer by the same function.

  Why: `Swatinem/rust-cache` appends the job id to the key by default, so eighteen steps
  wrote eighteen copies of the same compiled dependencies against GitHub's 10 GB
  per-repository cap and evicted each other (`.docs/lessons/a-cache-that-never-
  restores-is-not-a-cache.md`). `shared-key` makes the jobs that write one target
  directory under one compile mode share one entry; the mode is an axis because cargo
  hashes it into each artifact's metadata suffix, so a check-mode `cargo clippy` restores
  nothing out of an entry a build-mode `cargo nextest` wrote into the same directory.
  This check reads the group's shape — named, one writer, on `main`; CHECK 3 reads
  what each member compiles. `key` is dead beside `shared-key` — the action drops it
  when `shared-key` is set — so a reader who sees both believes the entries differ when
  they do not, and this check rejects the pair. A group with two writers lets whichever
  finishes first decide the entry's contents; a group with no writer never populates;
  a writer on any ref other than `main` writes an entry that only its own ref can read.
  The cap is per repository, not per workflow, so the count runs across every file.
  A `shared-key` holding `${{ matrix.<axis> }}` counts as one group per value of that
  axis, the keys GitHub expands it to on the job's legs, so a templated writer and a
  literal writer of one expanded key count as two writers of that group.

CHECK 2 — every uniffi-bindgen step reads the library out of the directory its own
`cargo run` writes.

  The criterion: for every `run:` command of the form
  `cargo run [flags] --bin uniffi-bindgen -- generate … --library <path>`, the directory
  cargo writes for those flags — `target/<triple>/<profile>/` when `--target` is passed,
  `target/<profile>/` otherwise, where `<profile>` is `release` under `--release`, the
  profile's own name under `--profile <name>` (`debug` for `dev` and `test`, `release`
  for `bench`), and `debug` otherwise —
  is a prefix of `<path>`.

  Why: cargo shares no artifact between two target directories. When the `--library`
  path sits in a directory the `cargo run` does not write, one of two things is true:
  an earlier step built that directory and this `cargo run` compiles the same crate
  graph a second time into another one (six minutes on `macos-26`, measured on run
  34724307976), or no step built it and the path does not exist. The check reads only
  the `cargo run` command and the path, so it cannot tell the two apart and rejects
  both, because both are fixed the same way: pass the flags that name the directory
  the library sits in.

CHECK 3 — every reader of a cache group compiles only what a writer of a group it
restores compiles.

  The criterion: for each job leg that restores a group and does not write it, every
  compile command its steps run, after the normalization below, is a command that some
  leg writing one of the groups that leg restores also runs; and the reader and each
  writer of the group run on one OS family, pass one `workspaces` input, and set the
  same CARGO*/CC*/CFLAGS*/CXX*/CMAKE*/RUST* environment, the variables rust-cache hashes
  into the key. A leg writes when its rust-cache step's `save-if` and its job's and
  step's `if:` can hold on a run of `refs/heads/main` that a push or a schedule starts,
  and the workflow file triggers on one of those events. A writer's rust-cache step
  reads no earlier step's output in its `if:` or `save-if`: such an output (a
  bridge-artifact cache hit, for one) can skip the save on every push, so an evicted or
  rekeyed entry would stay unwritten while the check counted it written. A group with a
  reader that runs on a pull request, a merge-queue run or a push has a writer that
  writes on a push to `main`, not only on a schedule. A compile-only script a writer
  runs in place of a gate script (SCRIPT_TWINS) holds the same compiling cargo
  commands as that gate, and stands in for it in the comparison.

  Why: rust-cache saves only when the restored key was not an exact match, so a reader
  that compiles a feature set or a compile mode the writer did not compile rebuilds
  those dependency units from source on every run and never saves them. Merge-queue run
  41499098021 measured it: rust-doctest recompiled 223 crates, WASM / test 228,
  rust-test-prose 104, rust-doc 102, each a reader whose writer built a different
  feature set. A feature set reaches every dependency through feature unification, so
  the check compares whole commands, not packages.

  Indicators, not the criterion — how the check reads a command: a command is
  `cargo`/`cross` with a compiling subcommand, `cargo nextest run|list|archive`,
  `cargo fuzz`, `maturin develop|build`, `wasm-pack build|test`, `bun|npm run <script>`
  resolved through the package.json in its working directory, or a shell script the
  step runs whose text names a compiler. A command's signature is its program, its
  compile class (`nextest run` and `test` are one class, `run` and `build` another),
  its working directory, its compile environment, and its flags as a set, with `-p`
  and `--features` values as sets and the flags DROPPED_FLAGS and DROPPED_VALUE_FLAGS
  list (test filters, output, lockfile policy) removed. A shell variable the script
  does not assign, a `cd` to a computed directory, or a cargo subcommand neither list
  classes fails the check rather than passing unread.

  Known gap: a script in a language other than shell (Python, TypeScript) builds its
  argv in code this check does not evaluate, so it is read as compiling nothing, and a
  reader that compiles through one is not compared.

CHECK 4 — a push to `main` runs only cache writers, and they only set up and compile.

  The criterion: in every workflow a push to `main` starts that also runs on merge-queue
  runs or writes a cache on that push, every job the push can run writes a cache, or a
  job that writes one needs it, or it is a companion PUSH_COMPANIONS names whose `if:`
  equals its needed partner's; and no step of those jobs runs a test, a lint or a
  gate.

  Why: the merge-queue run already ran every test, lint and gate on the tree a push to
  `main` lands, so the push run re-proves nothing and spends runner time to write the
  caches every later run restores. A job that runs on that push only to assert holds
  the push run's wall time (push run 41521637198), and a cache writer that runs a test
  or a gate makes that gate's verdict on `main` depend on a job no ruleset reads.

  Indicators, not the criterion — how the check reads a step: an action passes when it
  is on PUSH_ACTIONS (checkout, tool setup, cache, upload, path filter, image build); a
  shell command passes when its program is on PUSH_PLAIN_PROGRAMS, prints only its
  version, is `cargo build|check|doc|fetch|metadata`, `cargo clippy` with nothing after
  `--`, `cargo test` or `cargo nextest run` with `--no-run` (or `cargo test` ending
  `-- --list`), `maturin build|develop`, `wasm-pack build` or `wasm-pack test` ending
  `-- --list`, a package script whose own commands pass, Gradle tasks GRADLE_TASK
  matches, or a script PUSH_SCRIPTS names. Anything else fails.

  Known gap: an assertion written inline with programs PUSH_PLAIN_PROGRAMS allows (a
  `test -f` that exits 1, a `jq -e`) passes, because those programs also serve setup.

Exit 0 when every step passes, 1 otherwise. `--workflows-dir` points the checks at a
directory other than the repository's, which the cases under
`scripts/tests/workflow-compile-steps/` use.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import shlex
import sys
from collections import defaultdict
from pathlib import Path

import yaml

RUST_CACHE_ACTION = "./.github/actions/rust-cache"
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
    return {"dev": "debug", "test": "debug", "bench": "release"}.get(name, name)


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


# The one form of a ref test that holds a cache save to `main`.
MAIN_REF_TEST = re.compile(r"github\.ref\s*==\s*'refs/heads/main'", re.IGNORECASE)
WRAPPED_EXPRESSION = re.compile(r"\$\{\{(.*)\}\}", re.DOTALL)


def expression_body(value: object, bare: bool = False) -> str | None:
    """The expression a workflow field holds, or None when it holds a literal.

    A field holds an expression when one `${{ }}` spans its whole text. An `if:` field
    (`bare`) also holds one when its text carries no `${{` at all, because GitHub reads
    a bare `if:` as an expression.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    wrapped = WRAPPED_EXPRESSION.fullmatch(text)
    if wrapped and "${{" not in wrapped.group(1):
        return wrapped.group(1).strip()
    if bare and "${{" not in text:
        return text
    return None


def split_top(body: str, operator: str) -> list[str] | None:
    """Split an expression at each `operator` outside parentheses and quoted strings.

    None when the parentheses or quotes do not balance.
    """
    parts: list[str] = []
    depth, start, index, quoted = 0, 0, 0, False
    while index < len(body):
        char = body[index]
        if quoted:
            if char == "'":
                if body.startswith("''", index):
                    index += 2
                    continue
                quoted = False
        elif char == "'":
            quoted = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0 and body.startswith(operator, index):
            parts.append(body[start:index])
            index += len(operator)
            start = index
            continue
        index += 1
    if quoted or depth:
        return None
    return parts + [body[start:]]


def strip_parentheses(term: str) -> str:
    """Remove each pair of parentheses that encloses the whole term."""
    term = term.strip()
    while term.startswith("(") and term.endswith(")") and split_top(term[1:-1], "\0"):
        term = term[1:-1].strip()
    return term


def gated_to_main(value: object, bare: bool = False) -> bool:
    """Whether a condition can hold only on a run of `refs/heads/main`.

    The criterion: the field holds an expression (expression_body) with no top-level
    `||`, and one of its top-level `&&` terms, with enclosing parentheses removed, is
    exactly `github.ref == 'refs/heads/main'`. Such a term is a conjunct of the whole
    condition, so the condition is false wherever it is false, whatever the other
    terms read. Every other shape fails, including a correct condition written another
    way: the rule reads a shape, so it never evaluates an expression.

    Residual: GitHub compares strings without regard to case, so the term also holds
    on a branch named `MAIN` or `Main`.
    """
    body = expression_body(value, bare)
    if body is None:
        return False
    body = strip_parentheses(body)
    alternatives = split_top(body, "||")
    terms = split_top(body, "&&")
    if alternatives is None or len(alternatives) != 1 or terms is None:
        return False
    return any(MAIN_REF_TEST.fullmatch(strip_parentheses(term)) for term in terms)


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
                    failures.extend(check_cache_step(where, step, job, producers))
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


MATRIX_REFERENCE = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")


def expand_matrix_key(where: str, key: str, job: dict) -> tuple[list[str], list[str]]:
    """The keys a `shared-key` takes on the job's matrix legs, and any failure.

    Each `${{ matrix.<axis> }}` in the key is replaced by every value of that axis's
    list in `strategy.matrix`, so a templated key counts as one group per value, as
    GitHub expands it at runtime. An axis with no list of scalars there (absent, or
    defined only through `include`) is reported, and so is a matrix carrying
    `include` or `exclude`, because either one can add or remove legs, and this
    check could not say which groups the step writes.
    """
    keys = [key]
    matrix = (job.get("strategy") or {}).get("matrix")
    for axis in dict.fromkeys(MATRIX_REFERENCE.findall(key)):
        expanders = [
            k
            for k in ("include", "exclude")
            if isinstance(matrix, dict) and k in matrix
        ]
        if expanders:
            message = (
                f"{where}: rust-cache `shared-key` {key!r} names matrix axis {axis!r} "
                f"of a `strategy.matrix` carrying {' and '.join(expanders)}, so this "
                f"check cannot say which groups the step writes"
            )
            return [], [message]
        values = matrix.get(axis) if isinstance(matrix, dict) else None
        if not (
            isinstance(values, list)
            and values
            and all(isinstance(v, (str, int, float, bool)) for v in values)
        ):
            message = (
                f"{where}: rust-cache `shared-key` {key!r} names matrix axis {axis!r}, "
                f"which the job's `strategy.matrix` gives no list of values, so this "
                f"check cannot say which groups the step writes"
            )
            return [], [message]
        pattern = re.compile(r"\$\{\{\s*matrix\." + re.escape(axis) + r"\s*\}\}")
        keys = [pattern.sub(lambda _m, v=str(v): v, k) for k in keys for v in values]
    return list(dict.fromkeys(keys)), []


def check_cache_step(
    where: str, step: dict, job: dict, producers: dict[str, list[str]]
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
    keys, key_failures = expand_matrix_key(where, shared_key, job)
    failures.extend(key_failures)
    if is_false(save_if):
        for key in keys:
            producers.setdefault(key, [])
        return failures
    for key in keys:
        producers[key].append(where)
    if not gated_to_main(save_if):
        failures.append(
            f"{where}: the writer of cache group {shared_key!r} has save-if {save_if!r}, "
            f"which does not name {DEFAULT_BRANCH_REF} as a top-level `&&` term of one "
            f"`${{{{ }}}}` expression with no top-level `||` (gated_to_main); an entry "
            f"written on any other ref is readable by that ref alone"
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


# ── CHECK 3 ───────────────────────────────────────────────────────────────────────────
#
# What rust-cache hashes from the environment of the step that restores: every variable
# whose name starts with one of these prefixes (Swatinem/rust-cache v2, `src/config.ts`).
CACHE_ENV_PREFIXES = ("CARGO", "CC", "CFLAGS", "CXX", "CMAKE", "RUST")


# A step's own `env:` entry that changes what a command in it compiles: the variables
# rust-cache hashes, and the `<LIB>_FLAGS` variables a `-sys` crate's build script reads
# (job rust-test-optional-features sets `LIBSQLITE3_FLAGS`).
def is_compile_env(name: str) -> bool:
    return name.startswith(CACHE_ENV_PREFIXES) or name.endswith("_FLAGS")


# cargo subcommands that compile nothing into the target directory a group caches.
CARGO_NON_COMPILING = frozenset(
    {
        "tree",
        "metadata",
        "fetch",
        "fmt",
        "deny",
        "version",
        "install",
        "uninstall",
        "update",
        "generate-lockfile",
        "locate-project",
        "pkgid",
        "search",
        "owner",
        "login",
        "logout",
        "yank",
        "vendor",
        "help",
        "clean",
        "verify-project",
        "read-manifest",
        "add",
        "remove",
        "init",
        "new",
        "cyclonedx",
    }
)
# cargo subcommands, by the compile class each runs. `nextest run` builds what
# `cargo test --no-run` builds; `run` and `rustc` build what `cargo build` builds.
CARGO_CLASS = {
    "build": "build",
    "b": "build",
    "run": "build",
    "r": "build",
    "rustc": "build",
    "test": "test",
    "t": "test",
    "bench": "bench",
    "check": "check",
    "c": "check",
    "fix": "check",
    "clippy": "clippy",
    "doc": "doc",
    "d": "doc",
    "rustdoc": "doc",
    "publish": "package",
    "package": "package",
}
NEXTEST_COMPILING = frozenset({"run", "r", "archive", "list", "l"})
NEXTEST_NON_COMPILING = frozenset({"show-config", "self", "store", "help"})
FUZZ_COMPILING = frozenset({"run", "build", "check", "coverage", "tmin", "cmin"})

# Flags that change nothing a command compiles: run-time selection, output, and
# lockfile policy. Every other flag stays in the signature as written, so a flag this
# list does not name can only make two signatures differ, never make them match.
DROPPED_FLAGS = frozenset(
    {
        "--no-run",
        "--locked",
        "--frozen",
        "--offline",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "--no-fail-fast",
        "--fail-fast",
        "--document-private-items",
        "--no-deps",
        "--timings",
        "--keep-going",
        "--ignore-rust-version",
        "--nocapture",
        "--no-capture",
        "--skip-auditwheel",
        "--strip",
        # A test harness flag: after `--`, `cargo test --doc -- --list` and `wasm-pack test
        # -- --list` print each test's name and run none, and the compile is unchanged.
        "--list",
    }
)
DROPPED_VALUE_FLAGS = frozenset(
    {
        "-E",
        "--filterset",
        "--filter-expr",
        "--test-threads",
        "-j",
        "--jobs",
        "--message-format",
        "--color",
        "--run-ignored",
        "--retries",
        "--partition",
        "--no-tests",
        "--out",
        "-o",
        "--out-dir",
        "-d",
        "--out-name",
        "-i",
        "--interpreter",
        "--compatibility",
        "--archive-file",
        "--success-output",
        "--failure-output",
        "--status-level",
        "--final-status-level",
    }
)
# Flags whose value is the next token when no `=` joins them.
VALUE_FLAGS = DROPPED_VALUE_FLAGS | frozenset(
    {
        "-p",
        "--package",
        "--exclude",
        "-F",
        "--features",
        "--target",
        "--profile",
        "--cargo-profile",
        "--target-dir",
        "--manifest-path",
        "-m",
        "--bin",
        "--test",
        "--example",
        "--bench",
        "--fuzz-dir",
        "--sanitizer",
        "-s",
        "--config",
        "-Z",
        "--scope",
        "--mode",
    }
)
# Flags that hold a set: their order and repetition change nothing.
SET_FLAGS = {
    "-p": "-p",
    "--package": "-p",
    "--exclude": "--exclude",
    "-F": "--features",
    "--features": "--features",
}

# Words that a shell line can start with before the command it runs.
SHELL_PREFIX_WORDS = frozenset(
    {
        "if",
        "then",
        "else",
        "elif",
        "while",
        "until",
        "do",
        "!",
        "{",
        "}",
        "time",
        "exec",
        "command",
    }
)
SHELL_SKIP_WORDS = frozenset(
    {
        "fi",
        "done",
        "esac",
        "case",
        "for",
        "in",
        ";;",
        "source",
        ".",
        "return",
        "exit",
        "function",
        "local",
        "set",
        "shift",
        "trap",
        "echo",
        "printf",
        "true",
        "false",
        "test",
        "[",
        "[[",
        "]]",
        "]",
    }
)
PACKAGE_RUNNERS = frozenset({"bun", "npm", "pnpm", "yarn"})
FILE_RUNNERS = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "bun",
        "node",
        "python",
        "python3",
        "python3.12",
        "deno",
        "ruby",
        "perl",
    }
)
# Text in a file a step runs that marks it as able to compile Rust.
COMPILER_MENTION = re.compile(r"\b(cargo|wasm-pack|maturin|rustc|cross)\b")
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
SHELL_VARIABLE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:[^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


class Unknown:
    """The value of a workflow expression this check cannot evaluate."""

    def __repr__(self) -> str:
        return "unknown"


UNKNOWN = Unknown()


def _tokens(expression: str) -> list[str]:
    pattern = re.compile(
        r"\s*(?:(==|!=|&&|\|\||<=|>=|<|>|!|\(|\)|,)|('(?:[^']|'')*')|([A-Za-z_][\w.\-*]*)|(\d+(?:\.\d+)?))"
    )
    tokens, position = [], 0
    expression = expression.strip()
    while position < len(expression):
        match = pattern.match(expression, position)
        if match is None or match.end() == position:
            return []
        tokens.append(match.group(0).strip())
        position = match.end()
    return tokens


def evaluate(expression: object, context: dict[str, object]) -> object:
    """Evaluate a GitHub `if:` or `save-if:` expression on three values.

    `context` maps names such as `matrix.leg` or `github.ref` to their values; any other
    name, and any function call, evaluates to UNKNOWN. A comparison involving UNKNOWN is
    UNKNOWN, `&&` and `||` follow Kleene logic, and an expression this evaluator cannot
    parse is UNKNOWN.
    """
    if isinstance(expression, bool):
        return expression
    if expression is None:
        return True
    text = str(expression).strip()
    whole = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.DOTALL)
    if whole:
        text = whole.group(1)
    elif "${{" in text:
        return UNKNOWN
    tokens = _tokens(text)
    if not tokens:
        return UNKNOWN
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def truthy(value: object) -> object:
        if value is UNKNOWN:
            return UNKNOWN
        return bool(value) and value != ""

    def primary() -> object:
        token = take()
        if token == "(":
            value = disjunction()
            if peek() == ")":
                take()
            return value
        if token == "!":
            value = truthy(primary())
            return UNKNOWN if value is UNKNOWN else not value
        if token.startswith("'"):
            return token[1:-1].replace("''", "'")
        if re.fullmatch(r"\d+(?:\.\d+)?", token):
            return token
        if token in ("true", "false"):
            return token == "true"
        if peek() == "(":
            depth = 0
            while position < len(tokens):
                inner = take()
                depth += inner == "("
                depth -= inner == ")"
                if depth == 0:
                    break
            return UNKNOWN
        return context.get(token, UNKNOWN)

    def comparison() -> object:
        left = primary()
        while peek() in ("==", "!=", "<", ">", "<=", ">="):
            operator = take()
            right = primary()
            if left is UNKNOWN or right is UNKNOWN or operator not in ("==", "!="):
                left = UNKNOWN
                continue
            equal = str(left).lower() == str(right).lower()
            left = equal if operator == "==" else not equal
        return left

    def conjunction() -> object:
        left = comparison()
        while peek() == "&&":
            take()
            right = comparison()
            lt, rt = truthy(left), truthy(right)
            if lt is False or rt is False:
                left = False
            elif lt is UNKNOWN or rt is UNKNOWN:
                left = UNKNOWN
            else:
                left = right
        return left

    def disjunction() -> object:
        left = conjunction()
        while peek() == "||":
            take()
            right = conjunction()
            lt, rt = truthy(left), truthy(right)
            if lt is True:
                continue
            if rt is True:
                left = right
            elif lt is UNKNOWN or rt is UNKNOWN:
                left = UNKNOWN
            else:
                left = right
        return left

    try:
        value = disjunction()
    except IndexError:
        return UNKNOWN
    if position != len(tokens):
        return UNKNOWN
    return truthy(value)


def may_run(expression: object, context: dict[str, object]) -> bool:
    return evaluate(expression, context) is not False


def matrix_legs(job: dict) -> tuple[list[dict[str, object]], str | None]:
    """Every leg of the job's matrix, as GitHub expands it, or the reason it cannot.

    An axis given as a `${{ fromJSON(…) }}` expression contributes every value of every
    JSON list quoted inside it, so a matrix that names one list on a push and another on
    other events counts the legs of both.
    """
    matrix = (job.get("strategy") or {}).get("matrix")
    if matrix is None:
        return [{}], None
    if not isinstance(matrix, dict):
        return [], "its `strategy.matrix` is an expression, not a mapping"
    axes: dict[str, list[object]] = {}
    for axis, values in matrix.items():
        if axis in ("include", "exclude"):
            continue
        if isinstance(values, list) and all(
            isinstance(v, (str, int, float, bool)) for v in values
        ):
            axes[axis] = values
            continue
        if isinstance(values, str):
            found: list[object] = []
            for literal in re.findall(r"'(\[.*?\])'", values, re.DOTALL):
                try:
                    parsed = json.loads(literal)
                except json.JSONDecodeError:
                    return [], f"matrix axis {axis!r} quotes a list that is not JSON"
                found.extend(v for v in parsed if v not in found)
            if found:
                axes[axis] = found
                continue
        return [], f"matrix axis {axis!r} has no list of values this check can read"
    legs: list[dict[str, object]] = [{}]
    for axis, values in axes.items():
        legs = [dict(leg, **{axis: value}) for leg in legs for value in values]
    if not axes:
        legs = []
    for excluded in matrix.get("exclude") or []:
        if isinstance(excluded, dict):
            legs = [
                leg
                for leg in legs
                if not all(str(leg.get(k)) == str(v) for k, v in excluded.items())
            ]
    for included in matrix.get("include") or []:
        if not isinstance(included, dict):
            continue
        matched = False
        for leg in legs:
            if all(str(leg.get(k)) == str(v) for k, v in included.items() if k in axes):
                matched = True
                for key, value in included.items():
                    if key not in axes:
                        leg.setdefault(key, value)
        if not matched:
            legs.append(dict(included))
    return legs or [{}], None


def substitute_matrix(text: str, leg: dict[str, object]) -> str:
    def replace(match: re.Match[str]) -> str:
        inner = match.group(1).strip()
        name = re.fullmatch(r"matrix\.([\w-]+)", inner)
        if name and name.group(1) in leg:
            return str(leg[name.group(1)])
        # Left unresolved, the expression stays one shell word: `${{ a.b }}` would
        # otherwise split into `${{`, `a.b` and `}}`.
        return "${{" + re.sub(r"\s+", "", inner) + "}}"

    return EXPRESSION.sub(replace, text)


def strip_heredocs(script: str) -> str:
    kept: list[str] = []
    terminator: str | None = None
    for line in script.splitlines():
        if terminator is not None:
            if line.strip() == terminator:
                terminator = None
            continue
        kept.append(line)
        heredoc = HEREDOC.search(line)
        if heredoc:
            terminator = heredoc.group(2)
    return "\n".join(kept)


class Extraction:
    """The compile signatures a job leg's steps produce, and what blocked reading one."""

    def __init__(self) -> None:
        self.signatures: set[str] = set()
        self.unreadable: list[str] = []


def split_segments(line: str) -> list[list[str]] | None:
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token and set(token) <= set(";&|()<>"):
            if token in ("(", ")"):
                segments.append([token])
                segments.append([])
            elif token in (">", "<", ">>", ">&", "<&", "2>", "&>"):
                segments[-1].append(token)
            else:
                segments.append([])
            continue
        segments[-1].append(token)
    return [segment for segment in segments if segment]


def normalize_path(cwd: str, path: str) -> str:
    return (
        posixpath.normpath(posixpath.join(cwd, path))
        if not path.startswith("/")
        else path
    )


def resolve_variables(token: str, variables: dict[str, str]) -> tuple[str, list[str]]:
    unresolved: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name in variables:
            return "{" + name + "=" + variables[name] + "}"
        unresolved.append(name)
        return match.group(0)

    protected = EXPRESSION.sub(lambda m: m.group(0).replace("$", "\x00"), token)
    resolved = SHELL_VARIABLE.sub(replace, protected).replace("\x00", "$")
    return resolved, unresolved


def normalize_flags(words: list[str], nextest: bool) -> tuple[list[str], list[str]]:
    """The signature tokens of a cargo-style argument list, and its positional words."""
    kept: list[str] = []
    sets: dict[str, set[str]] = defaultdict(set)
    positionals: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        index += 1
        if word == "--":
            break
        if not word.startswith("-") or word == "-":
            positionals.append(word)
            continue
        name, joined, value = word.partition("=")
        if (
            not joined
            and name in VALUE_FLAGS
            and not name.startswith("--no-tests")
            and index < len(words)
        ):
            value = words[index]
            index += 1
        if name.startswith("-F") and name != "-F" and not name.startswith("--"):
            name, value = "-F", name[2:]
        if name.startswith("-p") and name != "-p" and not name.startswith("--"):
            name, value = "-p", name[2:]
        if name in DROPPED_FLAGS or name in DROPPED_VALUE_FLAGS:
            continue
        if nextest and name == "--profile":
            continue
        if name == "--cargo-profile":
            name = "--profile"
        if name == "--all":
            name = "--workspace"
        if name in SET_FLAGS:
            for item in re.split(r"[,\s]+", value):
                if item:
                    sets[SET_FLAGS[name]].add(item)
            continue
        kept.append(f"{name}={value}" if value else name)
    for flag in sorted(sets):
        kept.append(f"{flag}={','.join(sorted(sets[flag]))}")
    return sorted(set(kept)), positionals


class ScriptReader:
    """Reads the commands of one `run:` script, or a package script, into signatures."""

    def __init__(self, repo_root: Path, extraction: Extraction, where: str) -> None:
        self.repo_root = repo_root
        self.extraction = extraction
        self.where = where

    def read(self, script: str, cwd: str, env: dict[str, str], depth: int = 0) -> None:
        variables: dict[str, str] = {}
        stack: list[str] = []
        for line in join_continuations(strip_heredocs(script)).splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            segments = split_segments(line)
            if segments is None:
                if COMPILER_MENTION.search(line):
                    self.extraction.unreadable.append(
                        f"{self.where}: cannot split the shell line {line.strip()!r}"
                    )
                continue
            for segment in segments:
                if segment == ["("]:
                    stack.append(cwd)
                    continue
                if segment == [")"]:
                    cwd = stack.pop() if stack else cwd
                    continue
                cwd = self.command(segment, cwd, env, variables, depth)

    def command(
        self,
        words: list[str],
        cwd: str,
        env: dict[str, str],
        variables: dict[str, str],
        depth: int,
    ) -> str:
        while words and words[0] in SHELL_PREFIX_WORDS:
            words = words[1:]
        if words and words[0] == "export":
            words = words[1:]
        prefix_env: dict[str, str] = {}
        while words and ASSIGNMENT.match(words[0]):
            name, value = ASSIGNMENT.match(words[0]).groups()
            if len(words) == 1:
                variables[name] = value
                return cwd
            if is_compile_env(name):
                prefix_env[name] = value
            words = words[1:]
        if not words or words[0] in SHELL_SKIP_WORDS:
            return cwd
        program = posixpath.basename(words[0])
        if program == "cd":
            target = words[1] if len(words) > 1 else "~"
            if "$" in target:
                return "<unknown>"
            return normalize_path(cwd, target)
        command_env = dict(env, **prefix_env)
        if program in ("cargo", "cross"):
            self.cargo(program, words[1:], cwd, command_env, variables)
        elif program == "maturin":
            self.tool(
                "maturin",
                words[1:],
                cwd,
                command_env,
                variables,
                compiling={"develop", "build", "publish"},
            )
        elif program == "wasm-pack":
            self.tool(
                "wasm-pack",
                words[1:],
                cwd,
                command_env,
                variables,
                compiling={"build", "test", "pack", "publish"},
                paths=True,
            )
        elif program in PACKAGE_RUNNERS and len(words) > 2 and words[1] == "run":
            self.package_script(words[2], cwd, command_env, depth)
        elif (
            program in FILE_RUNNERS and len(words) > 1 and not words[1].startswith("-")
        ):
            self.file(words[1], words[2:], cwd, command_env, variables)
        elif "/" in words[0] or words[0].endswith(".sh"):
            self.file(words[0], words[1:], cwd, command_env, variables)
        return cwd

    def record(
        self, parts: list[str], cwd: str, env: dict[str, str], variables: dict[str, str]
    ) -> None:
        resolved: list[str] = []
        for part in parts:
            text, unresolved = resolve_variables(part, variables)
            if unresolved:
                self.extraction.unreadable.append(
                    f"{self.where}: `{' '.join(parts)}` names shell variable(s) "
                    f"{', '.join(sorted(set(unresolved)))} that no assignment earlier in "
                    f"its script sets, so this check cannot say what it compiles"
                )
                return
            resolved.append(text)
        if cwd == "<unknown>":
            self.extraction.unreadable.append(
                f"{self.where}: `{' '.join(parts)}` runs after a `cd` to a computed "
                f"directory, so this check cannot say what it compiles"
            )
            return
        environment = " ".join(f"{k}={v}" for k, v in sorted(env.items()))
        signature = " ".join(resolved) + f" [in {cwd}]"
        if environment:
            signature += f" [env {environment}]"
        self.extraction.signatures.add(signature)

    def cargo(
        self,
        program: str,
        words: list[str],
        cwd: str,
        env: dict[str, str],
        variables: dict[str, str],
    ) -> None:
        toolchain = ""
        if words and words[0].startswith("+"):
            toolchain, words = words[0], words[1:]
        leading: list[str] = []
        while words and words[0].startswith("-"):
            if words[0] in ("--version", "-V", "--help", "-h", "--list"):
                return
            leading.append(words[0])
            words = words[1:]
        if not words:
            return
        subcommand, rest = words[0], words[1:]
        if subcommand in CARGO_NON_COMPILING:
            return
        nextest = subcommand == "nextest"
        if nextest:
            action = rest[0] if rest else ""
            if action in NEXTEST_NON_COMPILING or not rest:
                return
            if action not in NEXTEST_COMPILING:
                self.extraction.unreadable.append(
                    f"{self.where}: `cargo nextest {action}` is a nextest command this "
                    f"check does not class as compiling or not"
                )
                return
            klass, rest = "test", rest[1:]
        elif subcommand == "fuzz":
            action = rest[0] if rest else ""
            if action not in FUZZ_COMPILING:
                return
            klass, rest = f"fuzz-{action if action != 'run' else 'build'}", rest[1:]
            if action == "run":
                klass = "fuzz-build"
        elif subcommand in CARGO_CLASS:
            klass = CARGO_CLASS[subcommand]
        else:
            self.extraction.unreadable.append(
                f"{self.where}: `cargo {subcommand}` is a cargo subcommand this check does "
                f"not class as compiling or not"
            )
            return
        flags, _positionals = normalize_flags(leading + rest, nextest)
        parts = [program] + ([toolchain] if toolchain else []) + [klass] + flags
        self.record(parts, cwd, env, variables)

    def tool(
        self,
        program: str,
        words: list[str],
        cwd: str,
        env: dict[str, str],
        variables: dict[str, str],
        compiling: set[str],
        paths: bool = False,
    ) -> None:
        if not words or words[0] not in compiling:
            return
        subcommand, rest = words[0], words[1:]
        extra: list[str] = []
        if "--" in rest:
            split = rest.index("--")
            rest, extra = rest[:split], rest[split + 1 :]
        flags, positionals = normalize_flags(rest, nextest=False)
        extra_flags, _ = normalize_flags(extra, nextest=False)
        located = [normalize_path(cwd, p) for p in positionals] if paths else []
        parts = (
            [program, subcommand]
            + located
            + flags
            + (["--"] + extra_flags if extra_flags else [])
        )
        self.record(parts, cwd, env, variables)

    def package_script(
        self, name: str, cwd: str, env: dict[str, str], depth: int
    ) -> None:
        manifest = self.repo_root / cwd / "package.json"
        if depth > 8:
            self.extraction.unreadable.append(
                f"{self.where}: package script {name!r} in {cwd} nests more than eight deep"
            )
            return
        try:
            scripts = (
                json.loads(manifest.read_text(encoding="utf-8")).get("scripts") or {}
            )
        except (OSError, json.JSONDecodeError):
            self.extraction.unreadable.append(
                f"{self.where}: `run {name}` in {cwd} names a package script, and "
                f"{cwd}/package.json does not exist or is not JSON"
            )
            return
        text = scripts.get(name)
        if not isinstance(text, str):
            self.extraction.unreadable.append(
                f"{self.where}: {cwd}/package.json defines no script {name!r}"
            )
            return
        self.read(text, cwd, env, depth + 1)

    def file(
        self,
        path: str,
        args: list[str],
        cwd: str,
        env: dict[str, str],
        variables: dict[str, str],
    ) -> None:
        if "$" in path:
            text, unresolved = resolve_variables(path, variables)
            if unresolved or "$" in text:
                if COMPILER_MENTION.search(path):
                    self.extraction.unreadable.append(
                        f"{self.where}: runs the computed path {path!r}"
                    )
                return
        located = normalize_path(cwd, path)
        target = self.repo_root / located
        if not target.is_file():
            return
        try:
            text = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        if not COMPILER_MENTION.search(text):
            return
        # A script in another language builds its argv in code this check does not
        # evaluate (a list constant may be a parse prefix and never run), so only a shell
        # script counts; the module docstring names the gap.
        first = text.splitlines()[0] if text else ""
        if not (
            located.endswith(".sh")
            or (first.startswith("#!") and first.rstrip().endswith(("sh", "bash")))
        ):
            return
        self.record(["run-file", located] + args, cwd, env, variables)


def leg_label(job_id: str, leg: dict[str, object]) -> str:
    if not leg:
        return job_id
    return job_id + " (" + ", ".join(f"{k}={v}" for k, v in leg.items()) + ")"


class Pair:
    """One job leg that restores one cache group."""

    def __init__(
        self,
        workflow: str,
        job_id: str,
        leg: dict[str, object],
        write_events: set[str],
        events: set[str],
        runner: str,
        workspaces: str,
        env: dict[str, str],
        extraction: Extraction,
    ) -> None:
        self.label = f"{workflow}: {leg_label(job_id, leg)}"
        self.write_events = write_events
        self.writes = bool(write_events)
        self.events = events
        self.runner = runner
        self.workspaces = workspaces
        self.env = env
        self.extraction = extraction


def runner_family(runs_on: object, leg: dict[str, object]) -> str:
    text = substitute_matrix(str(runs_on), leg).lower()
    for family in ("ubuntu", "macos", "windows"):
        if family in text:
            return family
    return text


def main_events(document: dict) -> list[str]:
    """The events of a workflow that run on the default branch without a person."""
    triggers = document.get("on", document.get(True))
    if isinstance(triggers, str):
        triggers = {triggers: None}
    elif isinstance(triggers, list):
        triggers = {name: None for name in triggers}
    elif not isinstance(triggers, dict):
        return []
    events: list[str] = []
    if "push" in triggers:
        push = triggers["push"] if isinstance(triggers["push"], dict) else {}
        branches = push.get("branches")
        # A `push` filter naming tags and no branch filter starts no branch push.
        tags_only = (
            branches is None
            and "branches-ignore" not in push
            and ("tags" in push or "tags-ignore" in push)
        )
        if not tags_only and (
            branches is None or DEFAULT_BRANCH_REF.rsplit("/", 1)[1] in branches
        ):
            events.append("push")
    if "schedule" in triggers:
        events.append("schedule")
    return events


def trigger_events(document: dict) -> set[str]:
    """Every event name a workflow's `on:` lists."""
    triggers = document.get("on", document.get(True))
    if isinstance(triggers, str):
        return {triggers}
    if isinstance(triggers, (list, dict)):
        return {str(name) for name in triggers}
    return set()


# Events on which a reader runs against a tree someone is waiting on. A group such a reader
# restores needs a writer on every push to `main`: a schedule writer leaves an evicted or
# rekeyed entry missing until the schedule next fires.
PUSH_WRITER_EVENTS = frozenset({"push", "pull_request", "merge_group"})

# A shell script a step runs is read as one opaque `run-file <path>` signature. A gate
# script whose compiles a writer must reproduce maps here to the compile-only script a
# writer runs in its place; check_script_twins requires both scripts to hold the same
# compiling cargo command templates, so the twin compiles what the gate compiles.
SCRIPT_TWINS = {
    "scripts/check-examples-compile.sh": "scripts/compile-examples.sh",
}
# Shell scripts a reader runs that compile nothing into the target directory its cache
# group restores, each with the reason.
SCRIPTS_COMPILING_ELSEWHERE = {
    "scripts/tests/examples-compile/run-tests.sh": (
        "each case runs cargo inside a workspace it creates under `mktemp -d`, whose own "
        "`target/` no cache group holds"
    ),
}
CARGO_TEMPLATE = re.compile(
    r"\bcargo\s+(?:\+\S+\s+)?(?P<sub>[a-z][a-z-]*)(?P<rest>[^;|&<>\n]*)"
)


def cargo_templates(text: str) -> set[str]:
    """The compiling cargo commands a shell script's text holds, up to `--`, as written."""
    templates: set[str] = set()
    for line in join_continuations(text).splitlines():
        if line.lstrip().startswith("#"):
            continue
        for match in CARGO_TEMPLATE.finditer(line):
            subcommand = match.group("sub")
            words = match.group("rest").split(" -- ")[0].split()
            if subcommand != "nextest" and subcommand not in CARGO_CLASS:
                continue
            if subcommand in ("package", "publish") and "--list" in words:
                continue
            templates.add(" ".join([CARGO_CLASS.get(subcommand, subcommand)] + words))
    return templates


def check_script_twins(repo_root: Path) -> list[str]:
    failures: list[str] = []
    for gate, twin in sorted(SCRIPT_TWINS.items()):
        texts = {}
        for path in (gate, twin):
            try:
                texts[path] = (repo_root / path).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                failures.append(f"script twin {path} does not exist or is not text")
        if len(texts) != 2:
            continue
        gate_templates = cargo_templates(texts[gate])
        twin_templates = cargo_templates(texts[twin])
        if not gate_templates:
            failures.append(
                f"{gate} holds no compiling cargo command this check can read"
            )
        if gate_templates != twin_templates:
            failures.append(
                f"{twin} stands in for {gate} in every cache-group writer, and the two run "
                f"different compiling cargo commands (only in {gate}: "
                f"{sorted(gate_templates - twin_templates)}; only in {twin}: "
                f"{sorted(twin_templates - gate_templates)}), so a writer running the twin "
                f"does not compile what a reader running the gate compiles"
            )
    return failures


def run_file_path(signature: str) -> str | None:
    words = signature.split()
    return words[1] if len(words) > 1 and words[0] == "run-file" else None


def twin_signatures(signatures: set[str]) -> set[str]:
    """Each signature, plus the gate signature that each twin script's signature covers."""
    covered = set(signatures)
    for signature in signatures:
        path = run_file_path(signature)
        for gate, twin in SCRIPT_TWINS.items():
            if path == twin:
                words = signature.split(" ")
                covered.add(" ".join([words[0], gate] + words[2:]))
    return covered


def check_group_coverage(workflows_dir: Path, repo_root: Path) -> list[str]:
    failures: list[str] = check_script_twins(repo_root)
    members: dict[str, list[Pair]] = defaultdict(list)
    restored_by: dict[str, set[str]] = defaultdict(set)
    for path in sorted(workflows_dir.glob("*.yml")) + sorted(
        workflows_dir.glob("*.yaml")
    ):
        with path.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        if not isinstance(document, dict):
            continue
        workflow_env = (
            document.get("env") if isinstance(document.get("env"), dict) else {}
        )
        # A step saves only on a run of the default branch, and only push and schedule
        # start one without a person, so a workflow neither triggers writes nothing.
        writer_events = main_events(document)
        events = trigger_events(document)
        for job_id, job in (document.get("jobs") or {}).items():
            if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
                continue
            steps = [s for s in job["steps"] if isinstance(s, dict)]
            if not any(
                str(s.get("uses", "")).startswith(RUST_CACHE_ACTION) for s in steps
            ):
                continue
            legs, reason = matrix_legs(job)
            if reason:
                failures.append(
                    f"{path.name}: job {job_id} restores a cargo cache and {reason}, so "
                    f"this check cannot say which legs restore which group"
                )
                continue
            job_env = job.get("env") if isinstance(job.get("env"), dict) else {}
            defaults = ((job.get("defaults") or {}).get("run") or {}).get(
                "working-directory"
            )
            for leg in legs:
                context = {f"matrix.{k}": v for k, v in leg.items()}
                writer_contexts = [
                    (
                        event,
                        dict(
                            context,
                            **{
                                "github.ref": DEFAULT_BRANCH_REF,
                                "github.event_name": event,
                            },
                        ),
                    )
                    for event in writer_events
                ]
                where = f"{path.name}: {leg_label(job_id, leg)}"
                extraction = Extraction()
                reader = ScriptReader(repo_root, extraction, where)
                restores: list[tuple[str, set[str], str, dict[str, str]]] = []
                for step in steps:
                    if not may_run(step.get("if"), context):
                        continue
                    step_env = (
                        step.get("env") if isinstance(step.get("env"), dict) else {}
                    )
                    if str(step.get("uses", "")).startswith(RUST_CACHE_ACTION):
                        block = (
                            step.get("with")
                            if isinstance(step.get("with"), dict)
                            else {}
                        )
                        key = block.get("shared-key")
                        if not isinstance(key, str) or not key.strip():
                            continue
                        write_events = (
                            set()
                            if is_false(block.get("save-if"))
                            else {
                                event
                                for event, writer_context in writer_contexts
                                if may_run(job.get("if"), writer_context)
                                and may_run(step.get("if"), writer_context)
                                and may_run(block.get("save-if"), writer_context)
                            }
                        )
                        writes = bool(write_events)
                        gate = " ".join(
                            str(value)
                            for value in (step.get("if"), block.get("save-if"))
                            if value is not None
                        )
                        if writes and re.search(r"(?i)\bsteps\s*\.", gate):
                            failures.append(
                                f"{where}: the rust-cache step writing group "
                                f"{substitute_matrix(key, leg).strip()!r} waits on an "
                                f"earlier step's output (`{gate}`), which can skip the save "
                                f"on every push to {DEFAULT_BRANCH_REF}, so an evicted or "
                                f"rekeyed entry stays unwritten; write the group from a "
                                f"step that every such push runs"
                            )
                        env = {
                            name: substitute_matrix(str(value), leg)
                            for source in (workflow_env, job_env, step_env)
                            for name, value in source.items()
                            if name.startswith(CACHE_ENV_PREFIXES)
                        }
                        restores.append(
                            (
                                substitute_matrix(key, leg).strip(),
                                write_events,
                                substitute_matrix(
                                    str(block.get("workspaces", ". -> target")), leg
                                ).strip(),
                                env,
                            )
                        )
                        continue
                    run = step.get("run")
                    if not isinstance(run, str):
                        continue
                    cwd = posixpath.normpath(
                        str(step.get("working-directory") or defaults or ".")
                    )
                    compile_env = {
                        name: substitute_matrix(str(value), leg)
                        for source in (job_env, step_env)
                        for name, value in source.items()
                        if is_compile_env(name)
                    }
                    reader.read(substitute_matrix(run, leg), cwd, compile_env)
                for key, write_events, workspaces, env in restores:
                    pair = Pair(
                        path.name,
                        job_id,
                        leg,
                        write_events,
                        events,
                        runner_family(job.get("runs-on"), leg),
                        workspaces,
                        env,
                        extraction,
                    )
                    members[key].append(pair)
                    restored_by[pair.label].add(key)

    def same_key(a: Pair, b: Pair) -> bool:
        return a.runner == b.runner and a.workspaces == b.workspaces and a.env == b.env

    compared = 0
    for group, pairs in sorted(members.items()):
        writers = [p for p in pairs if p.writes]
        readers = [p for p in pairs if not p.writes]
        if not readers:
            continue
        if not writers:
            failures.append(
                f"cache group {group!r}: no leg writes it on a run of {DEFAULT_BRANCH_REF} "
                f"that a push or a schedule starts, so its readers "
                f"({', '.join(p.label for p in readers)}) restore nothing"
            )
            continue
        waiting = [r for r in readers if r.events & PUSH_WRITER_EVENTS]
        if waiting:
            writers = [w for w in writers if "push" in w.write_events]
            if not writers:
                failures.append(
                    f"cache group {group!r}: its readers "
                    f"({', '.join(r.label for r in waiting)}) run on pull requests, "
                    f"merge-queue runs or pushes, and no leg writes it on a push to "
                    f"{DEFAULT_BRANCH_REF}, so an evicted or rekeyed entry stays missing "
                    f"until a schedule next writes it"
                )
                continue
        for pair in writers + readers:
            for problem in pair.extraction.unreadable:
                failures.append(f"cache group {group!r}: {problem}")
        for reader in readers:
            compared += 1
            # rust-cache keys an entry on the runner OS, the workspaces and the
            # CARGO*/RUST* environment, so only a writer that agrees on all three saves
            # the entry this reader restores.
            matching = [w for w in writers if same_key(reader, w)]
            if not matching:
                for writer in writers:
                    differences = []
                    if reader.runner != writer.runner:
                        differences.append(
                            f"runs on {reader.runner} and the writer on {writer.runner}"
                        )
                    if reader.workspaces != writer.workspaces:
                        differences.append(
                            f"restores workspaces {reader.workspaces!r} and the writer saves "
                            f"{writer.workspaces!r}"
                        )
                    if reader.env != writer.env:
                        differing = sorted(
                            name
                            for name in set(reader.env) | set(writer.env)
                            if reader.env.get(name) != writer.env.get(name)
                        )
                        differences.append(
                            f"and the writer restore under different values of "
                            f"{', '.join(differing)}"
                        )
                    failures.append(
                        f"cache group {group!r}: {reader.label} {'; '.join(differences)} "
                        f"(writer {writer.label}), and rust-cache hashes each of those into "
                        f"the key, so the reader restores nothing the writer saves"
                    )
                continue
            covered: set[str] = set()
            for restored in restored_by[reader.label]:
                for writer in members[restored]:
                    if not writer.writes or not same_key(reader, writer):
                        continue
                    if reader.events & PUSH_WRITER_EVENTS and (
                        "push" not in writer.write_events
                    ):
                        continue
                    covered |= twin_signatures(writer.extraction.signatures)
            compared_signatures = {
                s
                for s in reader.extraction.signatures
                if run_file_path(s) not in SCRIPTS_COMPILING_ELSEWHERE
            }
            for signature in sorted(compared_signatures - covered):
                failures.append(
                    f"cache group {group!r}: {reader.label} compiles `{signature}`, and no "
                    f"writer of a group it restores compiles that feature set in that mode "
                    f"({', '.join(w.label for w in matching)}), so on a full-match restore "
                    f"it compiles those dependencies from source on every run and never "
                    f"saves them"
                )
    if not failures:
        print(
            f"OK: {compared} cache-group reader(s), each compiling only what its group's "
            f"writer compiles"
        )
    return failures


# CHECK 4 tables. Each names what a job that a push to `main` runs may do; anything else
# fails the check, so a new tool or script lands here only with a reason.

# Actions that set up a tool, fetch sources, restore or save a cache, upload a build output,
# select jobs, or build an image.
PUSH_ACTIONS = (
    "actions/checkout@",
    "actions/cache@",
    "actions/cache/restore@",
    "actions/cache/save@",
    "actions/upload-artifact@",
    "gradle/actions/setup-gradle@",
    "gradle/actions/wrapper-validation@",
    "taiki-e/install-action@",
    "dorny/paths-filter@",
    "docker/setup-buildx-action@",
    "docker/login-action@",
    "docker/build-push-action@",
    "./.github/actions/rust-toolchain",
    "./.github/actions/rust-cache",
    "./.github/actions/cargo-fetch",
    "./.github/actions/android-sdk",
    "./.github/actions/toolcache-setup",
    "./.github/actions/pinned-tool",
)
# Programs a push step may run with any arguments: shell builtins, and utilities that
# read, hash, print, copy or delete files or install packages. None of them runs a
# repository test or check script.
PUSH_PLAIN_PROGRAMS = frozenset(
    {
        "echo",
        "printf",
        "df",
        "tail",
        "head",
        "tr",
        "cut",
        "sed",
        "awk",
        "cat",
        "touch",
        "mkdir",
        "rm",
        "cp",
        "mv",
        "ls",
        "shasum",
        "sha256sum",
        "find",
        "[",
        "[[",
        "test",
        "exit",
        "export",
        "source",
        ".",
        "set",
        "cd",
        "true",
        "false",
        ":",
        "continue",
        "break",
        "return",
        "shift",
        "local",
        "pip",
        "pip3",
        "jq",
        "sdkmanager",
        "yes",
        "dpkg-query",
        "tsup",
    }
)
# Programs a push step may run only to print their version, which some steps hash into a
# bridge artifact's cache key.
VERSION_ARGUMENTS = frozenset({"--version", "-version", "-V", "-VV"})
# Repository scripts a push step may run, each a build or a generator that asserts nothing
# about the tree beyond its own outputs existing.
PUSH_SCRIPTS = {
    "scripts/compile-examples.sh": "compiles every example target, asserting nothing",
    "scripts/generate-uniffi-kotlin.sh": "builds the UniFFI library and generates Kotlin",
    "bindings/swift/build-xcframework.sh": "builds the XCFramework and its Swift bindings",
    "bindings/typescript-wasm/scripts/build-wasm.ts": "runs `wasm-pack build`",
    "bindings/typescript-wasm/scripts/copy-wasm-asset.ts": "copies the built `.wasm`",
}
# Gradle tasks a push step may run: compiles, packaging, installs, and dependency
# resolution. A verification task (test, check, lint, detekt, ktlint) matches none.
GRADLE_TASK = re.compile(
    r"(?:^|:)(?:compile\w*|assemble\w*|\w*[Cc]lasses|jar|installDist|warmDependencyCache)$"
)
PYTHON_PROGRAMS = frozenset({"python", "python3", "python3.12"})
# A job a push runs that writes no cache and that no writer needs, mapped to the needed
# job whose `if:` it must carry word for word. check-draft carries `changes`'s `if:` so
# that `changes` starts with the run (ci_gate_selftest.py holds the two equal), so it
# runs wherever `changes` runs; its one step prints a line.
PUSH_COMPANIONS = {"check-draft": "changes"}
REDIRECT = re.compile(r"^\d*(?:<<<|<<|<|>>|>|>&|<&|&>|&>>)$")


def strip_redirects(words: list[str]) -> list[str]:
    """A command's words without its redirections and their targets."""
    kept: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        following = words[index + 1] if index + 1 < len(words) else ""
        if word.isdigit() and REDIRECT.match(following):
            index += 1
            continue
        if REDIRECT.match(word):
            index += 2
            continue
        kept.append(word)
        index += 1
    return kept


def push_command_problem(
    words: list[str], cwd: str, repo_root: Path, depth: int
) -> str | None:
    """Why one shell command may not run on a push, or None when it may."""
    words = strip_redirects(words)
    if not words:
        return None
    program = posixpath.basename(words[0])
    args = words[1:]
    if program in PUSH_PLAIN_PROGRAMS:
        return None
    if args and all(arg in VERSION_ARGUMENTS for arg in args):
        return None
    if program == "sudo" and args:
        return push_command_problem(args, cwd, repo_root, depth)
    if program == "command" and args and args[0] in ("-v", "-V"):
        return None
    if program == "git" and args and args[0] == "ls-files":
        return None
    if program == "xcrun" and "--show-sdk-version" in args:
        return None
    if program in PYTHON_PROGRAMS:
        if args[:2] in (["-m", "venv"], ["-m", "pip"]) or args[:1] == ["-c"]:
            return None
        return f"`{' '.join(words)}` runs Python that is not a venv, pip or inline `-c`"
    if program in ("cargo", "cross"):
        rest = args[1:] if args and args[0].startswith("+") else args
        subcommand = rest[0] if rest else ""
        after = rest[rest.index("--") + 1 :] if "--" in rest else []
        if subcommand in (
            "build",
            "b",
            "check",
            "c",
            "doc",
            "d",
            "fetch",
            "metadata",
            "rustc",
        ):
            return None
        if subcommand == "clippy" and not after:
            return None
        if subcommand in ("test", "t") and ("--no-run" in rest or after == ["--list"]):
            return None
        if subcommand == "nextest" and rest[1:2] == ["run"] and "--no-run" in rest:
            return None
        return (
            f"`{' '.join(words)}` is a cargo command that runs tests or lints rather than "
            f"only compiling (`cargo test` needs `--no-run` or `-- --list`, `cargo clippy` "
            f"takes nothing after `--`)"
        )
    if program == "maturin" and args and args[0] in ("develop", "build"):
        return None
    if program == "wasm-pack" and args:
        after = args[args.index("--") + 1 :] if "--" in args else []
        if args[0] == "build" or (args[0] == "test" and after == ["--list"]):
            return None
        return (
            f"`{' '.join(words)}` runs wasm tests (`wasm-pack test` needs `-- --list`)"
        )
    if program == "bun" and args[:1] == ["install"]:
        return None
    if program in PACKAGE_RUNNERS and len(args) >= 2 and args[0] == "run":
        return push_package_script_problem(args[1], cwd, repo_root, depth)
    if program in ("gradlew", "gradle"):
        tasks = []
        index = 0
        while index < len(args):
            arg = args[index]
            index += 1
            if arg in ("-p", "--project-dir", "--init-script", "-I"):
                index += 1
                continue
            if arg.startswith("-"):
                continue
            tasks.append(arg)
        bad = [task for task in tasks if not GRADLE_TASK.search(task)]
        if not tasks or bad:
            return (
                f"`{' '.join(words)}` runs Gradle task(s) "
                f"{', '.join(bad) or '(none named)'} that are not compile, assemble, "
                f"install or dependency-resolution tasks"
            )
        return None
    script = words[0]
    if program in FILE_RUNNERS and args and not args[0].startswith("-"):
        script = args[0]
    located = normalize_path(cwd, script)
    if located in PUSH_SCRIPTS:
        return None
    return (
        f"`{' '.join(words)}` runs `{program}`, which this check does not know as a setup "
        f"or compile command; a push to {DEFAULT_BRANCH_REF} runs only cache writers"
    )


def push_package_script_problem(
    name: str, cwd: str, repo_root: Path, depth: int
) -> str | None:
    try:
        scripts = (
            json.loads(
                (repo_root / cwd / "package.json").read_text(encoding="utf-8")
            ).get("scripts")
            or {}
        )
    except (OSError, json.JSONDecodeError):
        return (
            f"`run {name}` in {cwd} names a package script no package.json there holds"
        )
    text = scripts.get(name)
    if not isinstance(text, str) or depth > 8:
        return f"{cwd}/package.json defines no script {name!r} this check can read"
    problems = push_script_problems(text, cwd, repo_root, depth + 1)
    return "; ".join(problems) if problems else None


def push_script_problems(
    script: str, cwd: str, repo_root: Path, depth: int = 0
) -> list[str]:
    """Every command in a `run:` script that a push may not run."""
    problems: list[str] = []
    for line in join_continuations(strip_heredocs(script)).splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        segments = split_segments(line)
        if segments is None:
            problems.append(f"cannot split the shell line {line.strip()!r}")
            continue
        for words in segments:
            while words and (
                words[0]
                in ("if", "then", "else", "elif", "while", "until", "do", "!", "{", "}")
                or ASSIGNMENT.match(words[0])
            ):
                words = words[1:]
            if not words or words[0] in ("fi", "done", "esac", "(", ")"):
                continue
            if words[0] in ("for", "case") or set(words[0]) <= set("<>&0123456789"):
                continue
            if words[0] == "cd" and len(words) > 1 and "$" not in words[1]:
                cwd = normalize_path(cwd, words[1])
                continue
            problem = push_command_problem(words, cwd, repo_root, depth)
            if problem:
                problems.append(problem)
    return problems


def step_writes_cache(step: dict, context: dict[str, object]) -> bool:
    """Whether a step saves a cache entry on a run with this context."""
    uses = str(step.get("uses", ""))
    block = step.get("with") if isinstance(step.get("with"), dict) else {}

    def holds(name: str) -> bool:
        return evaluate(block.get(name, False), context) is True

    if uses.startswith(RUST_CACHE_ACTION):
        return not is_false(block.get("save-if")) and may_run(
            block.get("save-if"), context
        )
    if uses.startswith(("actions/cache@", "actions/cache/save@")):
        return True
    if uses.startswith("gradle/actions/setup-gradle@"):
        return not (holds("cache-disabled") or holds("cache-read-only"))
    if uses.startswith("oven-sh/setup-bun@"):
        return not holds("no-cache")
    if uses.startswith("docker/build-push-action@"):
        return bool(block.get("cache-to"))
    if uses.startswith("actions/setup-"):
        return bool(block.get("cache"))
    return False


def check_push_runs(workflows_dir: Path, repo_root: Path) -> list[str]:
    failures: list[str] = []
    checked = 0
    for path in sorted(workflows_dir.glob("*.yml")) + sorted(
        workflows_dir.glob("*.yaml")
    ):
        with path.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        if not isinstance(document, dict) or "push" not in main_events(document):
            continue
        jobs = {
            job_id: job
            for job_id, job in (document.get("jobs") or {}).items()
            if isinstance(job, dict)
        }
        context: dict[str, object] = {
            "github.event_name": "push",
            "github.ref": DEFAULT_BRANCH_REF,
        }
        push_jobs = {
            job_id: job
            for job_id, job in jobs.items()
            if may_run(job.get("if"), context)
        }
        writers = set()
        for job_id, job in push_jobs.items():
            legs, _ = matrix_legs(job)
            for leg in legs or [{}]:
                leg_context = dict(
                    context, **{f"matrix.{k}": v for k, v in leg.items()}
                )
                for step in job.get("steps") or []:
                    if (
                        isinstance(step, dict)
                        and may_run(step.get("if"), leg_context)
                        and step_writes_cache(step, leg_context)
                    ):
                        writers.add(job_id)
        if "merge_group" not in trigger_events(document) and not writers:
            continue
        needed: set[str] = set()
        pending = list(writers)
        while pending:
            needs = jobs.get(pending.pop(), {}).get("needs") or []
            for name in [needs] if isinstance(needs, str) else needs:
                if name not in needed:
                    needed.add(name)
                    pending.append(name)
        for job_id, job in push_jobs.items():
            checked += 1
            where = f"{path.name}: job {job_id}"
            companion = PUSH_COMPANIONS.get(job_id)
            if companion is not None and (
                companion not in needed | writers
                or jobs.get(companion, {}).get("if") != job.get("if")
            ):
                failures.append(
                    f"{where} runs on a push as the companion of job {companion}, so "
                    f"its `if:` must equal that job's and a cache-writing job must need "
                    f"{companion}"
                )
            elif companion is None and job_id not in writers and job_id not in needed:
                failures.append(
                    f"{where} can run on a push to {DEFAULT_BRANCH_REF}, writes no cache, "
                    f"and no cache-writing job needs it; the merge-queue run already ran "
                    f"it on the tree that push lands, so add "
                    f"`github.event_name != 'push'` to its `if:`"
                )
            defaults = ((job.get("defaults") or {}).get("run") or {}).get(
                "working-directory"
            )
            for step in job.get("steps") or []:
                if not isinstance(step, dict) or not may_run(step.get("if"), context):
                    continue
                uses = step.get("uses")
                if isinstance(uses, str):
                    if not uses.startswith(PUSH_ACTIONS):
                        failures.append(
                            f"{where} uses {uses} on a push, an action this check does not "
                            f"know as setup, cache, upload or build"
                        )
                    continue
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                cwd = posixpath.normpath(
                    str(step.get("working-directory") or defaults or ".")
                )
                for problem in push_script_problems(run, cwd, repo_root):
                    failures.append(
                        f"{where}, step {step.get('name', run.splitlines()[0])!r}: {problem}"
                    )
    if not failures:
        print(
            f"OK: {checked} job(s) a push to {DEFAULT_BRANCH_REF} can run, each writing a "
            f"cache or needed by one that does, and each only setting up and compiling"
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--workflows-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / ".github" / "workflows",
        help="directory holding the workflow files to check",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="directory that `run:` paths, working directories and package.json files "
        "resolve against",
    )
    args = parser.parse_args()
    if not args.workflows_dir.is_dir():
        print(f"FAIL: {args.workflows_dir} is not a directory", file=sys.stderr)
        return 1
    failures = check_workflows(args.workflows_dir)
    failures += check_group_coverage(args.workflows_dir, args.repo_root)
    failures += check_push_runs(args.workflows_dir, args.repo_root)
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
