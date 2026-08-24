"""Self-tests for check-release-pipeline.py.

Each test builds a synthetic repository tree that exhibits one shape, points
the gate's path constants at that tree, and asserts the verdict. The "rejects"
tests reproduce the exact shapes the live workflows carried before this gate
existed, so a passing suite proves the gate detects those defects rather than
merely agreeing with the current files.

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
  11. A publish job that stages no JVM native libraries fails, and the message
      names the JNA classpath entries the JAR would lack.
  12. A publish job that stages the libraries after its first publish task
      fails.
  13. A publish job that stages the libraries but never verifies the staged set
      fails.
  14. A verification step that sets `working-directory` does not satisfy the
      requirement, because its path argument then means another directory.
  15. A matrix row that omits `jna-prefix` or `lib-file` fails closed.
  16. A matrix row whose `lib-file` JNA would never ask for fails closed.
  17. Two matrix rows that claim one JNA prefix fail closed.
  18. The library name comes from the UniFFI crate's `[lib] name`, so renaming
      the crate moves the requirement.
  19. The verifier accepts a complete staged tree.
  20. The verifier rejects a tree missing one platform, and names it.
  21. The verifier rejects a wrongly named library, an empty library, and an
      entry no matrix row names.
  22. A renamed job fails closed rather than passing vacuously.
  23. A missing module build file fails closed.
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

SETTINGS_GRADLE = (
    'rootProject.name = "scp-kt"\ninclude("scp-kt")\ninclude("scp-kt-android")\n'
)
PUBLISHING_MODULE_GRADLE = 'plugins {\n    id("com.vanniktech.maven.publish")\n}\n'
UNIFFI_MANIFEST = (
    '[package]\nname = "scp-ffi-uniffi"\n\n'
    '[lib]\nname = "scp_ffi_uniffi"\ncrate-type = ["cdylib", "staticlib", "lib"]\n'
)

JVM_RESOURCES = "bindings/kotlin/scp-kt/src/main/resources"

# The five rows the `kotlin-jvm-natives` job of build-matrix.yml declares.
JVM_NATIVE_ROWS = [
    ("x86_64-unknown-linux-gnu", "linux-x86-64", "libscp_ffi_uniffi.so"),
    ("aarch64-unknown-linux-gnu", "linux-aarch64", "libscp_ffi_uniffi.so"),
    ("x86_64-apple-darwin", "darwin-x86-64", "libscp_ffi_uniffi.dylib"),
    ("aarch64-apple-darwin", "darwin-aarch64", "libscp_ffi_uniffi.dylib"),
    ("x86_64-pc-windows-msvc", "win32-x86-64", "scp_ffi_uniffi.dll"),
]

# The steps `publish-maven` runs to stage and check the JVM native libraries.
STAGE_JVM_NATIVES_STEP = f"""\
      - name: Download JVM native libraries
        uses: actions/download-artifact@v4
        with:
          pattern: kotlin-jvm-natives-*
          merge-multiple: true
          path: {JVM_RESOURCES}/
"""
VERIFY_JVM_NATIVES_STEP = f"""\
      - name: Verify every JVM platform carries a native library
        run: |
          python3 scripts/check-release-pipeline.py \\
            --verify-staged-natives {JVM_RESOURCES}
"""
STAGE_AND_VERIFY_STEPS = STAGE_JVM_NATIVES_STEP + VERIFY_JVM_NATIVES_STEP

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


def _release_workflow(
    spm_license_copy: str,
    maven_gradle_script: str,
    maven_native_steps: str,
    maven_steps_after_publish: str,
) -> str:
    return f"""\
name: Release
on:
  workflow_dispatch:
jobs:
  publish-maven:
    runs-on: ubuntu-latest
    steps:
{maven_native_steps}\
      - name: Publish to Maven Central (JVM + Android)
        working-directory: bindings/kotlin
        run: |
{maven_gradle_script}\
{maven_steps_after_publish}\
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


def _build_matrix_workflow(
    kotlin_gradle_script: str,
    jvm_native_rows: list[tuple[str, str | None, str | None]],
) -> str:
    rows = ""
    for target, prefix, library in jvm_native_rows:
        rows += f"          - target: {target}\n            runner: ubuntu-latest\n"
        if prefix is not None:
            rows += f"            jna-prefix: {prefix}\n"
        if library is not None:
            rows += f"            lib-file: {library}\n"
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
{kotlin_gradle_script}\
  kotlin-jvm-natives:
    runs-on: ${{{{ matrix.runner }}}}
    strategy:
      matrix:
        include:
{rows}\
    steps:
      - name: Build cdylib
        run: cargo build --release --target ${{{{ matrix.target }}}} -p scp-ffi-uniffi
"""


def _make_repo(
    tmp_path: Path,
    *,
    spm_license_copy: str = "          cp ../LICENSE-APACHE LICENSE\n",
    maven_gradle_script: str = MAVEN_JOB_ASSEMBLE_THEN_PUBLISH,
    maven_native_steps: str = STAGE_AND_VERIFY_STEPS,
    maven_steps_after_publish: str = "",
    kotlin_gradle_script: str = BUILD_JOB_CODEGEN_AND_COMPILE,
    licensing: str = LICENSING_TABLE,
    jvm_native_rows: list[tuple[str, str | None, str | None]] | None = None,
    uniffi_manifest: str = UNIFFI_MANIFEST,
) -> Path:
    """Build a synthetic repository tree and return its root."""
    _write(tmp_path / "LICENSE", LICENSE_POINTER)
    _write(tmp_path / "LICENSE-APACHE", APACHE_TEXT)
    _write(tmp_path / "LICENSE-AGPL", "GNU AFFERO GENERAL PUBLIC LICENSE\n")
    _write(tmp_path / "LICENSING.md", licensing)
    _write(
        tmp_path / ".github" / "workflows" / "release.yml",
        _release_workflow(
            spm_license_copy,
            maven_gradle_script,
            maven_native_steps,
            maven_steps_after_publish,
        ),
    )
    _write(
        tmp_path / ".github" / "workflows" / "build-matrix.yml",
        _build_matrix_workflow(
            kotlin_gradle_script,
            JVM_NATIVE_ROWS if jvm_native_rows is None else jvm_native_rows,
        ),
    )
    _write(tmp_path / "crates" / "scp-ffi" / "uniffi" / "Cargo.toml", uniffi_manifest)
    kotlin = tmp_path / "bindings" / "kotlin"
    _write(kotlin / "settings.gradle.kts", SETTINGS_GRADLE)
    _write(kotlin / "scp-kt" / "build.gradle.kts", PUBLISHING_MODULE_GRADLE)
    _write(kotlin / "scp-kt-android" / "build.gradle.kts", PUBLISHING_MODULE_GRADLE)
    return tmp_path


def _point_at(gate: ModuleType, root: Path) -> None:
    gate.REPO_ROOT = root
    gate.RELEASE_WORKFLOW = root / ".github" / "workflows" / "release.yml"
    gate.BUILD_MATRIX_WORKFLOW = root / ".github" / "workflows" / "build-matrix.yml"
    gate.LICENSING = root / "LICENSING.md"
    gate.KOTLIN_ROOT = root / "bindings" / "kotlin"
    gate.KOTLIN_SETTINGS = gate.KOTLIN_ROOT / "settings.gradle.kts"
    gate.UNIFFI_MANIFEST = root / "crates" / "scp-ffi" / "uniffi" / "Cargo.toml"


def _run(root: Path) -> tuple[int, str]:
    """Point a fresh gate at `root`, run it, and return its code and output."""
    gate = _load_gate()
    _point_at(gate, root)

    failures: list[str] = []
    try:
        gate.check_mirror_license(failures)
        gate.check_build_gate_compiles_published_modules(failures)
        gate.check_jvm_natives_staged_before_publish(failures)
    except gate.GateError as error:
        return 1, str(error)
    return (1 if failures else 0), "\n".join(failures)


def _verify(root: Path, staged: Path) -> tuple[int, str]:
    """Run the release-time verifier over `staged` with the gate reading `root`."""
    gate = _load_gate()
    _point_at(gate, root)
    try:
        problems = gate.verify_staged_natives(staged)
    except gate.GateError as error:
        return 1, str(error)
    return (1 if problems else 0), "\n".join(problems)


def _stage_natives(directory: Path, *, skip: str | None = None) -> Path:
    """Write one non-empty library per declared platform, minus `skip`."""
    for _target, prefix, library in JVM_NATIVE_ROWS:
        if prefix == skip:
            continue
        _write(directory / prefix / library, "ELF\n")
    return directory


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
# Criterion 3 — the published JVM coordinate carries its native libraries
# ---------------------------------------------------------------------------


def test_rejects_a_publish_job_that_stages_no_jvm_natives(tmp_path: Path) -> None:
    """The shape `publish-maven` carried before this criterion existed: it
    assembles and publishes `works.limn:scp-kt` with no library in the JAR."""
    root = _make_repo(tmp_path, maven_native_steps="")
    code, output = _run(root)
    assert code == 1
    assert JVM_RESOURCES in output
    assert "linux-x86-64/libscp_ffi_uniffi.so" in output
    assert "win32-x86-64/scp_ffi_uniffi.dll" in output


def test_rejects_staging_that_follows_the_first_publish_task(tmp_path: Path) -> None:
    """A download that runs after the Portal deployment changes nothing about
    the JAR that deployment uploaded."""
    root = _make_repo(
        tmp_path,
        maven_native_steps="",
        maven_steps_after_publish=STAGE_AND_VERIFY_STEPS,
    )
    code, output = _run(root)
    assert code == 1
    assert "before its first publish task" in output


def test_rejects_staging_without_verification(tmp_path: Path) -> None:
    """actions/download-artifact reports success on a partial pattern match, so
    staging alone leaves a lost artifact undetected."""
    root = _make_repo(tmp_path, maven_native_steps=STAGE_JVM_NATIVES_STEP)
    code, output = _run(root)
    assert code == 1
    assert "--verify-staged-natives" in output


def test_a_verification_step_with_a_working_directory_does_not_count(
    tmp_path: Path,
) -> None:
    """`working-directory` re-roots the relative path, so the step then checks
    a directory that is not the module's resources."""
    relocated = VERIFY_JVM_NATIVES_STEP.replace(
        "        run: |",
        "        working-directory: bindings/kotlin\n        run: |",
    )
    root = _make_repo(tmp_path, maven_native_steps=STAGE_JVM_NATIVES_STEP + relocated)
    code, output = _run(root)
    assert code == 1
    assert "--verify-staged-natives" in output


@pytest.mark.parametrize("dropped", ["jna-prefix", "lib-file"])
def test_a_matrix_row_missing_a_key_fails_closed(tmp_path: Path, dropped: str) -> None:
    rows: list[tuple[str, str | None, str | None]] = [
        (
            target,
            None if dropped == "jna-prefix" else prefix,
            None if dropped == "lib-file" else library,
        )
        if target == "x86_64-pc-windows-msvc"
        else (target, prefix, library)
        for target, prefix, library in JVM_NATIVE_ROWS
    ]
    root = _make_repo(tmp_path, jvm_native_rows=rows)
    code, output = _run(root)
    assert code == 1
    assert "x86_64-pc-windows-msvc" in output
    assert "jna-prefix" in output


def test_a_library_name_jna_never_asks_for_fails_closed(tmp_path: Path) -> None:
    """`linux-x86-64/libscp_ffi_uniffi.dylib` sits on the classpath and never
    loads, because JNA asks for the `.so` name under a `linux-` prefix."""
    rows = [
        (
            target,
            prefix,
            "libscp_ffi_uniffi.dylib" if prefix == "linux-x86-64" else library,
        )
        for target, prefix, library in JVM_NATIVE_ROWS
    ]
    root = _make_repo(tmp_path, jvm_native_rows=rows)
    code, output = _run(root)
    assert code == 1
    assert "libscp_ffi_uniffi.so" in output


def test_two_rows_sharing_a_prefix_fail_closed(tmp_path: Path) -> None:
    """`merge-multiple` unions the artifacts into one directory, so the second
    row's library would overwrite the first."""
    rows = [
        (target, "linux-x86-64" if prefix == "linux-aarch64" else prefix, library)
        for target, prefix, library in JVM_NATIVE_ROWS
    ]
    root = _make_repo(tmp_path, jvm_native_rows=rows)
    code, output = _run(root)
    assert code == 1
    assert "linux-x86-64" in output
    assert "overwrite" in output


def test_the_library_name_follows_the_uniffi_crate(tmp_path: Path) -> None:
    """Renaming the crate's `[lib] name` moves the required file names, because
    UniFFI writes that name into the `Native.load` call it generates."""
    renamed = UNIFFI_MANIFEST.replace('name = "scp_ffi_uniffi"', 'name = "scp_bridge"')
    root = _make_repo(tmp_path, uniffi_manifest=renamed)
    code, output = _run(root)
    assert code == 1
    assert "libscp_bridge.so" in output


# ---------------------------------------------------------------------------
# Criterion 3 — the release-time verifier over a staged tree
# ---------------------------------------------------------------------------


def test_verifier_accepts_a_complete_tree(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    staged = _stage_natives(tmp_path / "staged")
    code, output = _verify(root, staged)
    assert code == 0, output


def test_verifier_rejects_a_missing_platform(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    staged = _stage_natives(tmp_path / "staged", skip="darwin-aarch64")
    code, output = _verify(root, staged)
    assert code == 1
    assert "darwin-aarch64" in output
    assert "UnsatisfiedLinkError" in output


def test_verifier_rejects_a_wrongly_named_library(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    staged = _stage_natives(tmp_path / "staged", skip="win32-x86-64")
    _write(staged / "win32-x86-64" / "libscp_ffi_uniffi.so", "MZ\n")
    code, output = _verify(root, staged)
    assert code == 1
    assert "scp_ffi_uniffi.dll" in output


def test_verifier_rejects_an_empty_library(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    staged = _stage_natives(tmp_path / "staged", skip="linux-aarch64")
    _write(staged / "linux-aarch64" / "libscp_ffi_uniffi.so", "")
    code, output = _verify(root, staged)
    assert code == 1
    assert "empty file" in output


def test_verifier_rejects_an_entry_no_row_names(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    staged = _stage_natives(tmp_path / "staged")
    _write(staged / "linux-riscv64" / "libscp_ffi_uniffi.so", "ELF\n")
    code, output = _verify(root, staged)
    assert code == 1
    assert "linux-riscv64" in output


def test_verifier_rejects_a_directory_that_does_not_exist(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    code, output = _verify(root, tmp_path / "never-staged")
    assert code == 1
    assert "not a directory" in output


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "renamed", ["publish-spm", "publish-maven", "kotlin-aar", "kotlin-jvm-natives"]
)
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


def test_a_missing_uniffi_manifest_fails_closed(tmp_path: Path) -> None:
    root = _make_repo(tmp_path)
    (root / "crates" / "scp-ffi" / "uniffi" / "Cargo.toml").unlink()
    code, output = _run(root)
    assert code == 1
    assert "Cargo.toml" in output


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
