#!/usr/bin/env python3.12
"""Gate the release pipeline's three fail-closed properties.

The release workflow publishes to registries that refuse to overwrite a
published coordinate, so a defect it carries costs a version bump across every
SDK rather than a re-run. This gate states three criteria and derives both sides
of each from the repository, so neither side can drift alone.

Criterion 1 — the Swift Package mirror carries the grant LICENSING.md assigns
to the Swift binding.
    LICENSING.md assigns each component a license file. The mirror-publishing
    job (release.yml, job `publish-spm`) writes exactly one file as the
    mirror's LICENSE, and that file MUST be the one LICENSING.md names for the
    bindings. The repository root's LICENSE is a pointer that names three other
    files, none of which the mirror contains, so copying it publishes three
    dangling references and no grant.

Criterion 2 — the credential-free build gate compiles every Kotlin module the
credential-bearing publish job publishes.
    Job `publish-maven` of release.yml assembles both modules and then
    publishes them, and it starts at the same time as the crates.io, PyPI, and
    npm publish jobs, which all declare the same `needs`. A Kotlin compile
    error that first surfaces inside `publish-maven` therefore surfaces after
    those three registries have already taken uploads. Every module-qualified
    Gradle task that `publish-maven` runs before its first publish task MUST
    also run in job `kotlin-aar` of build-matrix.yml, which holds no
    credentials and which every publish job depends on.

Criterion 3 — the published JVM coordinate carries a native library for every
JVM platform the release builds one for.
    `works.limn:scp-kt` is a plain JVM coordinate. Its UniFFI-generated loader
    calls JNA's `Native.load("scp_ffi_uniffi", ...)`, and a consumer who
    installed no SCP library reaches JNA's last search step, which reads the
    classpath at `<Platform.RESOURCE_PREFIX>/<mapSharedLibraryName(name)>`. Job
    `publish-maven` of release.yml MUST therefore stage one library per resource
    prefix into the module's JAR resources, and MUST run the
    `--verify-staged-natives` mode of this script over that directory, both
    before its first publish task. Job `kotlin-jvm-natives` of build-matrix.yml
    declares the platform set: each `matrix.include` row gives a `jna-prefix` and
    the `lib-file` JNA asks for under it.

Run the static gate:  python3.12 scripts/check-release-pipeline.py
Run the release-time verifier over a staged tree:
    python3.12 scripts/check-release-pipeline.py --verify-staged-natives DIR
Exit 0 when every criterion holds, 1 otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
BUILD_MATRIX_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "build-matrix.yml"
LICENSING = REPO_ROOT / "LICENSING.md"
KOTLIN_ROOT = REPO_ROOT / "bindings" / "kotlin"
KOTLIN_SETTINGS = KOTLIN_ROOT / "settings.gradle.kts"
UNIFFI_MANIFEST = REPO_ROOT / "crates" / "scp-ffi" / "uniffi" / "Cargo.toml"

# The job that assembles and pushes the limn-works/scp-swift mirror.
SPM_JOB = "publish-spm"
# The job that publishes works.limn:scp-kt and works.limn:scp-kt-android.
MAVEN_JOB = "publish-maven"
# The credential-free build-matrix job that produces the Kotlin release inputs.
KOTLIN_BUILD_JOB = "kotlin-aar"
# The credential-free build-matrix job that cross-compiles the desktop JVM
# libraries and declares which JNA resource prefix each one belongs under.
JVM_NATIVES_JOB = "kotlin-jvm-natives"
# The Gradle module whose JAR carries those libraries, and its resource root as
# a repository-relative POSIX path (what a workflow step writes).
JVM_MODULE = "scp-kt"
JVM_RESOURCES = f"bindings/kotlin/{JVM_MODULE}/src/main/resources"
# The Gradle plugin id a module applies to become a published Maven coordinate.
MAVEN_PUBLISH_PLUGIN = "com.vanniktech.maven.publish"

# JNA composes `Platform.RESOURCE_PREFIX` as `<os>-<arch>` and asks the
# classloader for `<prefix>/<NativeLibrary.mapSharedLibraryName(name)>`. This
# table is the second half of that pair, keyed by the `<os>` half of the prefix,
# read from com.sun.jna.Platform and com.sun.jna.NativeLibrary in JNA 5.18.1 —
# the version bindings/kotlin/scp-kt/build.gradle.kts declares. A prefix whose
# `<os>` half is absent here fails the gate rather than passing unchecked.
JNA_LIBRARY_NAME_BY_OS = {
    "linux": "lib{crate}.so",
    "darwin": "lib{crate}.dylib",
    "win32": "{crate}.dll",
}

# `cp [-flags] ../<source> LICENSE`, run inside the mirror working directory.
COPY_TO_MIRROR_LICENSE = re.compile(
    r"^\s*cp\s+(?:-[A-Za-z]+\s+)*\.\./(\S+)\s+LICENSE\s*$",
    re.MULTILINE,
)
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
# A Gradle task written as :<module>:<task>.
MODULE_TASK = re.compile(r"^:([A-Za-z0-9_.-]+):([A-Za-z0-9_]+)$")
GRADLE_INCLUDE = re.compile(r'^\s*include\("([^"]+)"\)', re.MULTILINE)
GRADLEW_COMMAND = re.compile(r"(?:^|\s|&&\s*|\|\|\s*|;\s*)(\./gradlew\s.*)$")
# `[lib]\nname = "scp_ffi_uniffi"` in the UniFFI crate's manifest.
CARGO_LIB_NAME = re.compile(
    r"^\[lib\]\s*$.*?^\s*name\s*=\s*\"([^\"]+)\"",
    re.MULTILINE | re.DOTALL,
)
# This script invoked in its release-time verifier mode, with its target
# directory as the captured argument.
VERIFY_STAGED_NATIVES = re.compile(
    r"scripts/check-release-pipeline\.py\s+--verify-staged-natives\s+(\S+)"
)


class GateError(Exception):
    """A condition that leaves the gate unable to decide, so it fails closed."""


# ---------------------------------------------------------------------------
# Workflow reading
# ---------------------------------------------------------------------------


def load_job(workflow_path: Path, job_id: str) -> dict:
    """Return one job of a workflow, or raise when the workflow lacks it."""
    if not workflow_path.is_file():
        raise GateError(f"{workflow_path} does not exist")
    document = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise GateError(f"{workflow_path} does not parse as a YAML mapping")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        raise GateError(f"{workflow_path} declares no `jobs` mapping")
    job = jobs.get(job_id)
    if not isinstance(job, dict):
        raise GateError(
            f"{workflow_path} declares no job `{job_id}`. Restore that job id, "
            "or update this gate to name the job that replaced it."
        )
    return job


def job_steps(job: dict) -> list[dict]:
    """Return the job's steps in the order the runner executes them."""
    steps = job.get("steps")
    if not isinstance(steps, list):
        return []
    return [step for step in steps if isinstance(step, dict)]


def job_script(job: dict) -> str:
    """Concatenate every `run` script the job's steps declare."""
    scripts = [
        step["run"] for step in job_steps(job) if isinstance(step.get("run"), str)
    ]
    return "\n".join(scripts)


def join_continuations(script: str) -> str:
    """Join backslash line continuations so one command reads as one line."""
    return re.sub(r"\\\n\s*", " ", script)


def gradle_invocations(script: str) -> list[list[str]]:
    """Split a shell script into the argument lists of its gradlew commands.

    Backslash line continuations are joined first, so a task spelled on its own
    continuation line belongs to the invocation that opened it.
    """
    invocations = []
    for line in join_continuations(script).splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        match = GRADLEW_COMMAND.search(stripped)
        if match:
            invocations.append(match.group(1).split())
    return invocations


def run_tasks(invocation: list[str]) -> list[str]:
    """Return the task arguments the invocation runs.

    An argument that starts with `-` is a flag, and the argument that follows
    `-x` names a task the invocation excludes, so neither is a task it runs.
    """
    tasks = []
    skip_next = False
    for argument in invocation[1:]:
        if skip_next:
            skip_next = False
            continue
        if argument == "-x":
            skip_next = True
            continue
        if argument.startswith("-"):
            continue
        tasks.append(argument)
    return tasks


def module_tasks(invocation: list[str]) -> set[str]:
    """Return the `:module:task` arguments the invocation runs."""
    return {task for task in run_tasks(invocation) if MODULE_TASK.match(task)}


def names_a_publish_task(invocation: list[str]) -> bool:
    """Report whether any task the invocation runs publishes."""
    return any(
        task.split(":")[-1].lower().startswith("publish")
        for task in run_tasks(invocation)
    )


def first_publish_step(steps: list[dict]) -> int | None:
    """Return the index of the first step that runs a Gradle publish task."""
    for index, step in enumerate(steps):
        run = step.get("run")
        if not isinstance(run, str):
            continue
        if any(names_a_publish_task(inv) for inv in gradle_invocations(run)):
            return index
    return None


# ---------------------------------------------------------------------------
# Criterion 1 — the Swift mirror's license
# ---------------------------------------------------------------------------


def bindings_license_file(licensing_text: str) -> str:
    """Return the license file LICENSING.md assigns to the bindings.

    The license table gives each component a row, and the bindings share the
    Client SDK row. This gate reads that row's link target rather than a fixed
    file name, so relicensing the bindings moves the gate with them.
    """
    targets = []
    for line in licensing_text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2 or "bindings" not in cells[0].lower():
            continue
        link = MARKDOWN_LINK.search(cells[1])
        if link:
            targets.append(link.group(1))
    if len(targets) != 1:
        raise GateError(
            "LICENSING.md must give the bindings exactly one license-table row "
            f"whose license cell links to a file; this gate found {len(targets)}."
        )
    return targets[0]


def check_mirror_license(failures: list[str]) -> None:
    if not LICENSING.is_file():
        raise GateError(f"{LICENSING} does not exist")
    expected = bindings_license_file(LICENSING.read_text(encoding="utf-8"))
    if not (REPO_ROOT / expected).is_file():
        failures.append(
            f"LICENSING.md links the bindings to `{expected}`, which the "
            "repository root does not contain."
        )
        return

    job = load_job(RELEASE_WORKFLOW, SPM_JOB)
    copied = COPY_TO_MIRROR_LICENSE.findall(job_script(job))
    if len(copied) != 1:
        failures.append(
            f"Job `{SPM_JOB}` of release.yml must copy exactly one file to the "
            f"mirror's LICENSE; this gate found {len(copied)} "
            f"({sorted(copied) if copied else 'none'}). A published package "
            "that carries no license grants a consumer nothing."
        )
        return
    if copied[0] != expected:
        failures.append(
            f"Job `{SPM_JOB}` of release.yml publishes `{copied[0]}` as the "
            f"mirror's LICENSE, but LICENSING.md assigns the bindings "
            f"`{expected}`. Copy `../{expected}` instead: the mirror carries "
            "only the Swift binding, so it must carry that grant in full."
        )


# ---------------------------------------------------------------------------
# Criterion 2 — the build gate compiles what the publish job publishes
# ---------------------------------------------------------------------------


def published_kotlin_modules() -> set[str]:
    """Return the Gradle modules that publish a Maven coordinate."""
    if not KOTLIN_SETTINGS.is_file():
        raise GateError(f"{KOTLIN_SETTINGS} does not exist")
    included = GRADLE_INCLUDE.findall(KOTLIN_SETTINGS.read_text(encoding="utf-8"))
    if not included:
        raise GateError(f"{KOTLIN_SETTINGS} includes no modules")
    published = set()
    for module in included:
        build_file = KOTLIN_ROOT / module / "build.gradle.kts"
        if not build_file.is_file():
            raise GateError(f"{build_file} does not exist")
        if MAVEN_PUBLISH_PLUGIN in build_file.read_text(encoding="utf-8"):
            published.add(module)
    if not published:
        raise GateError(
            f"No Kotlin module applies `{MAVEN_PUBLISH_PLUGIN}`, so this gate "
            "cannot tell which modules the release publishes."
        )
    return published


def check_build_gate_compiles_published_modules(failures: list[str]) -> None:
    published = published_kotlin_modules()

    maven_job = load_job(RELEASE_WORKFLOW, MAVEN_JOB)
    pre_publish: list[list[str]] = []
    for invocation in gradle_invocations(job_script(maven_job)):
        if names_a_publish_task(invocation):
            break
        pre_publish.append(invocation)

    required: set[str] = set()
    for invocation in pre_publish:
        required |= module_tasks(invocation)

    covered = {MODULE_TASK.match(task).group(1) for task in required}
    unassembled = published - covered
    if unassembled:
        failures.append(
            f"Job `{MAVEN_JOB}` of release.yml publishes {sorted(published)} "
            f"but assembles {sorted(covered) if covered else 'nothing'} before "
            f"its first publish task. Assemble {sorted(unassembled)} first, so "
            "a compile error aborts the job before the Central Portal takes an "
            "irreversible deployment. Naming those tasks here is also what "
            f"makes this gate require them of job `{KOTLIN_BUILD_JOB}` in "
            "build-matrix.yml."
        )
        return

    build_job = load_job(BUILD_MATRIX_WORKFLOW, KOTLIN_BUILD_JOB)
    available: set[str] = set()
    for invocation in gradle_invocations(job_script(build_job)):
        available |= module_tasks(invocation)

    missing = required - available
    if missing:
        failures.append(
            f"Job `{KOTLIN_BUILD_JOB}` of build-matrix.yml does not run "
            f"{sorted(missing)}, which job `{MAVEN_JOB}` of release.yml runs "
            "before it publishes. The build gate holds no credentials and "
            "every publish job depends on it, so run those tasks there. "
            "Otherwise a Kotlin compile error first surfaces while crates.io, "
            "PyPI, and npm are already uploading versions they will not let "
            "you re-upload, and a dry run never compiles Kotlin at all."
        )


# ---------------------------------------------------------------------------
# Criterion 3 — the published JVM coordinate carries its native libraries
# ---------------------------------------------------------------------------


def uniffi_cdylib_name() -> str:
    """Return the library name UniFFI's Kotlin loader passes to JNA.

    UniFFI writes the crate's `[lib] name` into the generated `Native.load`
    call, so this gate reads that name out of the manifest rather than
    repeating it.
    """
    if not UNIFFI_MANIFEST.is_file():
        raise GateError(f"{UNIFFI_MANIFEST} does not exist")
    match = CARGO_LIB_NAME.search(UNIFFI_MANIFEST.read_text(encoding="utf-8"))
    if match is None:
        raise GateError(
            f"{UNIFFI_MANIFEST} declares no `[lib] name`, so this gate cannot "
            "derive the file name JNA asks the classpath for."
        )
    return match.group(1)


def jvm_native_platforms() -> dict[str, str]:
    """Return each JNA resource prefix mapped to the library file under it.

    Job `kotlin-jvm-natives` of build-matrix.yml declares the platform set: one
    `matrix.include` row per platform, giving the prefix JNA composes and the
    file name JNA asks for beneath it. This function rejects a row whose file
    name JNA would never request, and rejects two rows that claim one prefix,
    because the release job merges every row's artifact into one directory and
    the second row would overwrite the first.
    """
    job = load_job(BUILD_MATRIX_WORKFLOW, JVM_NATIVES_JOB)
    rows = job.get("strategy", {}).get("matrix", {}).get("include")
    if not isinstance(rows, list) or not rows:
        raise GateError(
            f"Job `{JVM_NATIVES_JOB}` of build-matrix.yml declares no "
            "`strategy.matrix.include` rows, so this gate cannot tell which "
            "JVM platforms the release builds a native library for."
        )
    crate = uniffi_cdylib_name()
    platforms: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise GateError(
                f"Job `{JVM_NATIVES_JOB}` of build-matrix.yml has a "
                "`matrix.include` entry that is not a mapping."
            )
        target = row.get("target", "<unnamed>")
        prefix = row.get("jna-prefix")
        library = row.get("lib-file")
        if not isinstance(prefix, str) or not isinstance(library, str):
            raise GateError(
                f"Row `{target}` of job `{JVM_NATIVES_JOB}` in build-matrix.yml "
                "must declare both `jna-prefix` and `lib-file`. This gate reads "
                "those two keys as the platform's contract with JNA, and a row "
                "that omits either one leaves the published JAR unchecked."
            )
        family = prefix.split("-", 1)[0]
        template = JNA_LIBRARY_NAME_BY_OS.get(family)
        if template is None:
            raise GateError(
                f"Row `{target}` of job `{JVM_NATIVES_JOB}` declares prefix "
                f"`{prefix}`, whose `{family}` half this gate has no JNA library "
                f"naming rule for. Add `{family}` to JNA_LIBRARY_NAME_BY_OS with "
                "the name com.sun.jna.NativeLibrary.mapSharedLibraryName returns "
                "on that operating system."
            )
        wanted = template.format(crate=crate)
        if library != wanted:
            raise GateError(
                f"Row `{target}` of job `{JVM_NATIVES_JOB}` stages `{library}` "
                f"under `{prefix}`, but JNA asks the classpath for `{wanted}` "
                f"there. A file under any other name never loads."
            )
        if prefix in platforms:
            raise GateError(
                f"Two rows of job `{JVM_NATIVES_JOB}` declare prefix `{prefix}`. "
                f"Job `{MAVEN_JOB}` merges every row's artifact into one "
                "directory, so the second row's library would overwrite the "
                "first and one platform would ship the other's binary."
            )
        platforms[prefix] = library
    return platforms


def check_jvm_natives_staged_before_publish(failures: list[str]) -> None:
    platforms = jvm_native_platforms()
    steps = job_steps(load_job(RELEASE_WORKFLOW, MAVEN_JOB))
    publish_at = first_publish_step(steps)
    if publish_at is None:
        failures.append(
            f"Job `{MAVEN_JOB}` of release.yml runs no Gradle publish task, so "
            "this gate cannot tell which steps precede the Central Portal "
            "deployment."
        )
        return
    before = steps[:publish_at]

    staged_at = None
    for index, step in enumerate(before):
        uses = step.get("uses")
        if not isinstance(uses, str) or not uses.startswith(
            "actions/download-artifact@"
        ):
            continue
        inputs = step.get("with")
        if not isinstance(inputs, dict):
            continue
        if str(inputs.get("path", "")).rstrip("/") == JVM_RESOURCES:
            staged_at = index
    if staged_at is None:
        failures.append(
            f"Job `{MAVEN_JOB}` of release.yml downloads no artifact into "
            f"`{JVM_RESOURCES}` before its first publish task, so the "
            f"`works.limn:{JVM_MODULE}` JAR it uploads carries UniFFI's JNA "
            f"loader and no library for it to load. JNA reads the classpath at "
            f"{sorted(f'{prefix}/{library}' for prefix, library in platforms.items())}, "
            f"which job `{JVM_NATIVES_JOB}` of build-matrix.yml builds. Maven "
            "Central refuses a re-upload of a released coordinate, so a JAR "
            "published without them costs a version bump across every SDK the "
            "same run published."
        )
        return

    for step in before[staged_at + 1 :]:
        run = step.get("run")
        if not isinstance(run, str):
            continue
        if step.get("working-directory"):
            continue
        for match in VERIFY_STAGED_NATIVES.finditer(join_continuations(run)):
            if match.group(1).rstrip("/") == JVM_RESOURCES:
                return

    failures.append(
        f"Job `{MAVEN_JOB}` of release.yml stages `{JVM_RESOURCES}` but never "
        f"runs `scripts/check-release-pipeline.py --verify-staged-natives "
        f"{JVM_RESOURCES}` against it before its first publish task, from a "
        "step that sets no `working-directory`. actions/download-artifact "
        "reports success when its pattern matches some of the artifacts the "
        "build matrix uploads, so without that step a run that lost one "
        "platform's artifact publishes a JAR missing that platform's library."
    )


def verify_staged_natives(directory: Path) -> list[str]:
    """Return every way the staged tree departs from the declared platform set."""
    platforms = jvm_native_platforms()
    if not directory.is_dir():
        return [
            (
                f"`{directory}` is not a directory, so the JAR carries no "
                f"native library for any of {sorted(platforms)}."
            )
        ]

    problems: list[str] = []
    for prefix, library in sorted(platforms.items()):
        prefix_dir = directory / prefix
        if not prefix_dir.is_dir():
            problems.append(
                f"`{directory}/{prefix}/` is missing, so a JVM on that platform "
                f"finds no `{library}` on the classpath and every SCP call "
                "throws UnsatisfiedLinkError."
            )
            continue
        found = sorted(entry.name for entry in prefix_dir.iterdir())
        if found != [library]:
            problems.append(
                f"`{directory}/{prefix}/` holds {found or 'nothing'}; JNA asks "
                f"for exactly `{library}` there."
            )
            continue
        if (prefix_dir / library).stat().st_size == 0:
            problems.append(f"`{directory}/{prefix}/{library}` is an empty file.")

    unexpected = sorted(
        entry.name for entry in directory.iterdir() if entry.name not in platforms
    )
    if unexpected:
        problems.append(
            f"`{directory}` also holds {unexpected}, which no row of job "
            f"`{JVM_NATIVES_JOB}` in build-matrix.yml names. The release stages "
            "that directory for the JVM native libraries alone, so anything "
            "else there ships in the JAR unaccounted for. Add the platform to "
            "that job, or keep the file out of the module's resources."
        )
    return problems


# ---------------------------------------------------------------------------


def run_static_gate() -> int:
    failures: list[str] = []
    try:
        check_mirror_license(failures)
        check_build_gate_compiles_published_modules(failures)
        check_jvm_natives_staged_before_publish(failures)
    except GateError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print("PASS: the Swift mirror publishes the grant LICENSING.md assigns to")
    print("      the bindings, the credential-free build gate compiles every")
    print("      Kotlin module the release publishes, and the Maven publish job")
    print("      stages and verifies a JVM native library for every platform.")
    return 0


def run_verifier(directory: Path) -> int:
    try:
        problems = verify_staged_natives(directory)
    except GateError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(f"PASS: {directory} carries a native library for every JVM platform")
    print(f"      job `{JVM_NATIVES_JOB}` of build-matrix.yml builds one for.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--verify-staged-natives",
        metavar="DIR",
        help=(
            "Skip the static gate and instead check that DIR holds one UniFFI "
            "native library per JNA resource prefix that job "
            f"`{JVM_NATIVES_JOB}` of build-matrix.yml builds one for. The "
            "release workflow runs this over the scp-kt module's staged JAR "
            "resources before it publishes."
        ),
    )
    arguments = parser.parse_args([] if argv is None else argv)
    if arguments.verify_staged_natives is not None:
        return run_verifier(Path(arguments.verify_staged_natives))
    return run_static_gate()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
