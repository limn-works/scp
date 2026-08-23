#!/usr/bin/env python3.12
"""Gate the release pipeline's two fail-closed properties.

The release workflow publishes to registries that refuse to overwrite a
published coordinate, so a defect it carries costs a version bump across every
SDK rather than a re-run. This gate states two criteria and derives both sides
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

Run: python3.12 scripts/check-release-pipeline.py
Exit 0 when both criteria hold, 1 otherwise.
"""

from __future__ import annotations

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

# The job that assembles and pushes the limn-works/scp-swift mirror.
SPM_JOB = "publish-spm"
# The job that publishes works.limn:scp-kt and works.limn:scp-kt-android.
MAVEN_JOB = "publish-maven"
# The credential-free build-matrix job that produces the Kotlin release inputs.
KOTLIN_BUILD_JOB = "kotlin-aar"
# The Gradle plugin id a module applies to become a published Maven coordinate.
MAVEN_PUBLISH_PLUGIN = "com.vanniktech.maven.publish"

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


def job_script(job: dict) -> str:
    """Concatenate every `run` script the job's steps declare."""
    steps = job.get("steps")
    if not isinstance(steps, list):
        return ""
    scripts = [
        step["run"]
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("run"), str)
    ]
    return "\n".join(scripts)


def gradle_invocations(script: str) -> list[list[str]]:
    """Split a shell script into the argument lists of its gradlew commands.

    Backslash line continuations are joined first, so a task spelled on its own
    continuation line belongs to the invocation that opened it.
    """
    joined = re.sub(r"\\\n\s*", " ", script)
    invocations = []
    for line in joined.splitlines():
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


def main() -> int:
    failures: list[str] = []
    try:
        check_mirror_license(failures)
        check_build_gate_compiles_published_modules(failures)
    except GateError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print("PASS: the Swift mirror publishes the grant LICENSING.md assigns to")
    print("      the bindings, and the credential-free build gate compiles")
    print("      every Kotlin module the release publishes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
