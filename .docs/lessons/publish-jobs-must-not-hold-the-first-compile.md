# A Publish Job Must Not Hold the First Compile of What It Publishes

**Date:** 2026-08-23
**Source:** branch `ci/release-pipeline-multiregistry` — review of the Maven Central
Portal migration in `.github/workflows/release.yml` and `.github/workflows/build-matrix.yml`

## The Rule

Every compile step that a credential-bearing publish job runs MUST also run in a
credential-free job that the publish job depends on. A publish job may repeat the
compile; it may not own the first one.

Two properties make the rule load-bearing:

1. crates.io, PyPI, npm, and the Maven Central Portal all reject a re-upload of a
   version. A build failure that first surfaces inside one publish job, while its
   sibling publish jobs are uploading, cannot be fixed by re-running the release —
   it forces a version bump across every SDK.
2. A dry run skips every publish job. Work that only the publish job performs is
   work the dry run never performs, so a dry run reports success on a tree that
   cannot be released.

## Context

The Maven migration moved `./gradlew :scp-kt:assemble` and
`./gradlew :scp-kt-android:assembleRelease` out of the `kotlin-aar` job of
build-matrix.yml and into the `publish-maven` job of release.yml, leaving
`kotlin-aar` running only `./gradlew :scp-kt:generateUniffiBindings`. That task
writes source files and never invokes `compileKotlin`, so the build gate stopped
compiling Kotlin.

`publish-maven`, `publish-crates`, `publish-pypi`, and `publish-npm` all declare
`needs: [sign-apple, sign-windows]`, so all four start together. A UniFFI bridge
change that broke the hand-written Kotlin wrapper would therefore have passed the
build gate, passed a dry run, and then failed inside `publish-maven` while
eighteen crates, the Python wheels, and six npm packages were already published
at that version.

## The Fix

`kotlin-aar` compiles both published modules before it uploads its artifacts:

```yaml
- name: Compile Kotlin modules
  working-directory: bindings/kotlin
  run: |
    ./gradlew :scp-kt:assemble :scp-kt-android:assembleRelease \
      -x generateUniffiBindings
```

`scripts/check-release-pipeline.py` enforces the rule mechanically. It reads the
Gradle invocations that `publish-maven` runs before its first publish task,
collects the `:module:task` arguments, and requires the `kotlin-aar` job to run
every one of them. It derives the set of published modules from
`bindings/kotlin/settings.gradle.kts` plus each module's `build.gradle.kts`, so
adding a third published module makes the gate demand a build-gate compile for it
without anyone editing the gate.
