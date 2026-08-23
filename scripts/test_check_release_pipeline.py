"""Self-tests for check-release-pipeline.py.

Each test builds a synthetic repository tree that exhibits one shape, points
the gate's path constants at that tree, and asserts the verdict. The two
"rejects" tests reproduce the exact shapes the live workflows carried before
this gate existed, so a passing suite proves the gate detects those defects
rather than merely agreeing with the current files.

Covered:
  1.  The real repository passes.
  2.  Copying the root LICENSE pointer into the mirror fails, and the message
      names the file LICENSING.md assigns to the bindings.
  3.  Copying nothing into the mirror's LICENSE fails.
  4.  Copying the file LICENSING.md assigns to the bindings passes.
  5.  Relicensing the bindings in LICENSING.md moves the requirement, so the
      gate derives the expected file instead of hardcoding one.
  6.  A build gate that only generates bindings fails, and the message names
      the assemble tasks it does not run.
  7.  A publish job that publishes without assembling first fails.
  8.  A task named after `-x` counts as excluded, not as a task to mirror.
  9.  An excluded publish task does not end the pre-publish run of invocations.
  10. A task on a backslash continuation line belongs to the invocation that
      opened it.
  11. A renamed job fails closed rather than passing vacuously.
  12. A missing module build file fails closed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check-release-pipeline.py"

APACHE_TEXT = "Apache License\nVersion 2.0, January 2004\n"
LICENSE_POINTER = (
    "SCP is distributed under multiple licenses. See LICENSING.md for the full\n"
    "structure, FAQ, and rationale.\n"
)
LICENSING_TABLE = (
    "# SCP Licensing\n"
    "\n"
    "| Component | License | SPDX |\n"
    "|---|---|---|\n"
    "| Client SDK (`scp-core`, bindings) | [Apache 2.0](LICENSE-APACHE) | `Apache-2.0` |\n"
    "| Application node (`scp-node`) | [AGPL v3 only](LICENSE-AGPL) | `AGPL-3.0-only` |\n"
)

SETTINGS_GRADLE = 'rootProject.name = "scp-kt"\ninclude("scp-kt")\ninclude("scp-kt-android")\n'
PUBLISHING_MODULE_GRADLE = 'plugins {\n    id("com.vanniktech.maven.publish")\n}\n'

# The `publish-maven` shape this branch ships: assemble both modules, then
# publish. The gate mirrors its pre-publish tasks onto the build gate.
MAVEN_JOB_ASSEMBLE_THEN_PUBLISH = """\
          ./gradlew \\
            :scp-kt:assemble :scp-kt-android:assembleRelease \\
            -x generateUniffiBindings \\
            -PscpVersion=1.2.3 \\
            --no-configuration-cache
          ./gradlew publishAndReleaseToMavenCentral \\
            -x generateUniffiBindings \\
            -PscpVersion=1.2.3 \\
            --no-configuration-cache
"""

# The `kotlin-aar` shape that carried the defect: codegen only, no compile.
BUILD_JOB_CODEGEN_ONLY = "          ./gradlew :scp-kt:generateUniffiBindings\n"

# The fixed `kotlin-aar` shape: codegen, then compile both published modules.
BUILD_JOB_CODEGEN_AND_COMPILE = (
    "          ./gradlew :scp-kt:generateUniffiBindings\n"
    "          ./gradlew :scp-kt:assemble :scp-kt-android:assembleRelease \\\n"
    "            -x generateUniffiBindings\n"
)


def _load_gate() -> ModuleType:
    """Load check-release-pipeline.py fresh, so each test patches its own copy."""
    spec = importlib.util.spec_from_file_location("check_release_pipeline", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _release_workflow(spm_license_copy: str, maven_gradle_script: str) -> str:
    return f"""\
name: Release
on:
  workflow_dispatch:
jobs:
  publish-maven:
    runs-on: ubuntu-latest
    steps:
      - name: Publish to Maven Central (JVM + Android)
        working-directory: bindings/kotlin
        run: |
{maven_gradle_script}
  publish-spm:
    runs-on: ubuntu-latest
    steps:
      - name: Assemble and publish scp-swift mirror
        working-directory: mirror
        run: |
          set -euo pipefail
          sed -e "s|__URL__|x|" ../bindings/swift/Package.dist.swift > Package.swift
{spm_license_copy}          git add -A
          git commit -m "Release 1.2.3" --quiet
"""


def _build_matrix_workflow(kotlin_gradle_script: str) -> str:
    return f"""\
name: Build Matrix
on:
  workflow_call:
jobs:
  kotlin-aar:
    runs-on: ubuntu-latest
    steps:
      - name: Build Kotlin
        working-directory: bindings/kotlin
        run: |
{kotlin_gradle_script}
"""


def _make_repo(
    tmp_path: Path,
    *,
    spm_license_copy: str = "          cp ../LICENSE-APACHE LICENSE\n",
    maven_gradle_script: str = MAVEN_JOB_ASSEMBLE_THEN_PUBLISH,
    kotlin_gradle_script: str = BUILD_JOB_CODEGEN_AND_COMPILE,
    licensing: str = LICENSING_TABLE,
) -> Path:
    """Build a synthetic repository tree and return its root."""
    _write(tmp_path / "LICENSE", LICENSE_POINTER)
    _write(tmp_path / "LICENSE-APACHE", APACHE_TEXT)
    _write(tmp_path / "LICENSE-AGPL", "GNU AFFERO GENERAL PUBLIC LICENSE\n")
    _write(tmp_path / "LICENSING.md", licensing)
    _write(
        tmp_path / ".github" / "workflows" / "release.yml",
        _release_workflow(spm_license_copy, maven_gradle_script),
    )
    _write(
        tmp_path / ".github" / "workflows" / "build-matrix.yml",
        _build_matrix_workflow(kotlin_gradle_script),
    )
    kotlin = tmp_path / "bindings" / "kotlin"
    _write(kotlin / "settings.gradle.kts", SETTINGS_GRADLE)
    _write(kotlin / "scp-kt" / "build.gradle.kts", PUBLISHING_MODULE_GRADLE)
    _write(kotlin / "scp-kt-android" / "build.gradle.kts", PUBLISHING_MODULE_GRADLE)
    return tmp_path


def _run(root: Path) -> tuple[int, str]:
    """Point a fresh gate at `root`, run it, and return its code and output."""
    gate = _load_gate()
    gate.REPO_ROOT = root
    gate.RELEASE_WORKFLOW = root / ".github" / "workflows" / "release.yml"
    gate.BUILD_MATRIX_WORKFLOW = root / ".github" / "workflows" / "build-matrix.yml"
    gate.LICENSING = root / "LICENSING.md"
    gate.KOTLIN_ROOT = root / "bindings" / "kotlin"
    gate.KOTLIN_SETTINGS = gate.KOTLIN_ROOT / "settings.gradle.kts"

    failures: list[str] = []
    try:
        gate.check_mirror_license(failures)
        gate.check_build_gate_compiles_published_modules(failures)
    except gate.GateError as error:
        return 1, str(error)
    return (1 if failures else 0), "\n".join(failures)


# ---------------------------------------------------------------------------
# 1. The live repository
# ---------------------------------------------------------------------------


def test_real_repository_passes() -> None:
    gate = _load_gate()
    assert gate.main() == 0


# ---------------------------------------------------------------------------
# Criterion 1 — the Swift mirror's license
# ---------------------------------------------------------------------------


def test_rejects_the_root_license_pointer(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, spm_license_copy="          cp ../LICENSE LICENSE\n")
    code, output = _run(root)
    assert code == 1
    assert "LICENSE-APACHE" in output
    assert "publish-spm" in output


def test_rejects_a_mirror_with_no_license(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, spm_license_copy="")
    code, output = _run(root)
    assert code == 1
    assert "exactly one file" in output


def test_accepts_the_license_licensing_md_assigns(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    code, output = _run(root)
    assert code == 0, output


def test_follows_a_relicense_of_the_bindings(tmp_path: Path) -> None:
    """The expected file comes from LICENSING.md, not from a constant."""
    relicensed = LICENSING_TABLE.replace(
        "[Apache 2.0](LICENSE-APACHE)", "[MPL 2.0](LICENSE-MPL)"
    )
    root = _make_repo(tmp_path, licensing=relicensed)
    _write(root / "LICENSE-MPL", "Mozilla Public License Version 2.0\n")
    code, output = _run(root)
    assert code == 1
    assert "LICENSE-MPL" in output

    root_fixed = _make_repo(
        tmp_path / "fixed",
        licensing=relicensed,
        spm_license_copy="          cp ../LICENSE-MPL LICENSE\n",
    )
    _write(root_fixed / "LICENSE-MPL", "Mozilla Public License Version 2.0\n")
    code_fixed, output_fixed = _run(root_fixed)
    assert code_fixed == 0, output_fixed


# ---------------------------------------------------------------------------
# Criterion 2 — the build gate compiles what the publish job publishes
# ---------------------------------------------------------------------------


def test_rejects_a_build_gate_that_only_generates_bindings(tmp_path: Path) -> None:
    root = _make_repo(tmp_path, kotlin_gradle_script=BUILD_JOB_CODEGEN_ONLY)
    code, output = _run(root)
    assert code == 1
    assert ":scp-kt:assemble" in output
    assert ":scp-kt-android:assembleRelease" in output
    assert "kotlin-aar" in output


def test_rejects_a_publish_job_that_never_assembles(tmp_path: Path) -> None:
    publish_only = (
        "          ./gradlew publishAndReleaseToMavenCentral"
        " -PscpVersion=1.2.3 --no-configuration-cache\n"
    )
    root = _make_repo(tmp_path, maven_gradle_script=publish_only)
    code, output = _run(root)
    assert code == 1
    assert "publish-maven" in output
    assert "scp-kt" in output


def test_an_excluded_task_is_not_a_task_to_mirror(tmp_path: Path) -> None:
    """`-x :scp-kt:test` names a task the publish job skips, so the build gate
    owes nothing for it."""
    maven = (
        "          ./gradlew :scp-kt:assemble :scp-kt-android:assembleRelease"
        " -x :scp-kt:test\n"
        "          ./gradlew publishAndReleaseToMavenCentral\n"
    )
    root = _make_repo(tmp_path, maven_gradle_script=maven)
    code, output = _run(root)
    assert code == 0, output


def test_an_excluded_publish_task_does_not_end_the_pre_publish_run(
    tmp_path: Path,
) -> None:
    """`-x publishToMavenLocal` excludes a publish task, so the invocation that
    carries it is still an assemble invocation."""
    maven = (
        "          ./gradlew :scp-kt:assemble :scp-kt-android:assembleRelease"
        " -x publishToMavenLocal\n"
        "          ./gradlew publishAndReleaseToMavenCentral\n"
    )
    root = _make_repo(
        tmp_path,
        maven_gradle_script=maven,
        kotlin_gradle_script=BUILD_JOB_CODEGEN_ONLY,
    )
    code, output = _run(root)
    assert code == 1
    assert ":scp-kt:assemble" in output


def test_a_continued_line_belongs_to_its_invocation(tmp_path: Path) -> None:
    """The Android task sits on its own continuation line in both workflows."""
    maven = (
        "          ./gradlew :scp-kt:assemble \\\n"
        "            :scp-kt-android:assembleRelease\n"
        "          ./gradlew publishAndReleaseToMavenCentral\n"
    )
    build_missing_android = "          ./gradlew :scp-kt:assemble\n"
    root = _make_repo(
        tmp_path,
        maven_gradle_script=maven,
        kotlin_gradle_script=build_missing_android,
    )
    code, output = _run(root)
    assert code == 1
    assert ":scp-kt-android:assembleRelease" in output


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("renamed", ["publish-spm", "publish-maven", "kotlin-aar"])
def test_a_renamed_job_fails_closed(tmp_path: Path, renamed: str) -> None:
    root = _make_repo(tmp_path)
    for workflow in ("release.yml", "build-matrix.yml"):
        path = root / ".github" / "workflows" / workflow
        path.write_text(
            path.read_text(encoding="utf-8").replace(f"{renamed}:", f"{renamed}-v2:"),
            encoding="utf-8",
        )
    code, output = _run(root)
    assert code == 1
    assert renamed in output


def test_a_missing_kotlin_module_build_file_fails_closed(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    (root / "bindings" / "kotlin" / "scp-kt-android" / "build.gradle.kts").unlink()
    code, output = _run(root)
    assert code == 1
    assert "build.gradle.kts" in output


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
