# A Published JVM JAR Carries the Library Its Loader Asks For

**Date:** 2026-08-23
**Source:** branch `ci/release-pipeline-multiregistry` — review of the
`publish-maven` job in `.github/workflows/release.yml`

## The Rule

When a release job publishes a JVM coordinate whose code loads a native library
at run time, the artifact it uploads MUST carry that library for every platform
the package claims to support, and a step that runs before the first publish
task MUST fail the job when one platform's library is absent.

## Context

`works.limn:scp-kt` is a plain JVM coordinate. Its UniFFI-generated bindings call
`Native.load("scp_ffi_uniffi", ...)`, and JNA resolves that name in three steps:
`jna.library.path`, then the operating system's library path, then the classpath
at `<Platform.RESOURCE_PREFIX>/<NativeLibrary.mapSharedLibraryName(name)>`. A
consumer who added the dependency and installed nothing else reaches only the
third step, so the JAR itself has to hold the library.

The `publish-maven` job built that coordinate from `:scp-kt:assemble` alone.
`bindings/kotlin/scp-kt/build.gradle.kts` declared the JNA runtime dependency on
line 30 and staged no resources, and the only cargo command in the `kotlin-aar`
job of `.github/workflows/build-matrix.yml` cross-compiled the four Android ABIs
into the `scp-kt-android` module's `jniLibs`. Nothing in the pipeline compiled
`scp-ffi-uniffi` for a desktop JVM target, so the published JAR carried the
loader and no library for it to load. A consumer following
`bindings/kotlin/README.md` line 12 would have hit
`UnsatisfiedLinkError: Unable to load library 'scp_ffi_uniffi'` on the first SCP
call, while `.docs/scaffold/kotlin.md` line 261 promised "Native libraries for
Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64) bundled in
JAR resources". Maven Central refuses a re-upload of a released coordinate, so
the repair would have cost a version bump across every SDK the same run
published.

## The Fix

Job `kotlin-jvm-natives` of `build-matrix.yml` cross-compiles `scp-ffi-uniffi`
for the five desktop targets and uploads each one under the JNA resource prefix
that platform's JVM composes. Job `publish-maven` downloads those five artifacts
into `bindings/kotlin/scp-kt/src/main/resources/`, where Gradle's
`processResources` task copies them into the JAR, and then runs

```sh
python3 scripts/check-release-pipeline.py \
  --verify-staged-natives bindings/kotlin/scp-kt/src/main/resources
```

before the first Gradle publish task. `actions/download-artifact` reports success
when its pattern matches some of the artifacts the build matrix uploaded, so
that verification is what turns a lost artifact into a failed job instead of a
JAR missing one platform.

`scripts/check-release-pipeline.py` enforces the rule statically as well. It
reads the `matrix.include` rows of `kotlin-jvm-natives` as the platform set, and
it reads the file name each row stages against the crate's `[lib] name` in
`crates/scp-ffi/uniffi/Cargo.toml` and JNA's per-operating-system naming rule, so
a row that stages `libscp_ffi_uniffi.dylib` under a `linux-` prefix fails the
gate. It then requires `publish-maven` to download into the module's resources
and to run the verifier over that directory, both before its first publish task.
