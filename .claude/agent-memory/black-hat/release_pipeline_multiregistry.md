---
name: release-pipeline-multiregistry
description: Threat model of ci/release-pipeline-multiregistry worktree — GitHub Actions release.yml + build-matrix.yml + Kotlin Gradle vanniktech Central Portal + scp-swift SPM mirror
metadata:
  type: project
---

# Release pipeline (ci/release-pipeline-multiregistry) supply-chain threat model

Worktree: /Users/alec/Developer/limn/scp-wt-release. Files: .github/workflows/release.yml, build-matrix.yml, bindings/kotlin/*build.gradle.kts, bindings/swift/Package.dist.swift (untracked).

**Why:** First multi-registry release pipeline (crates.io, PyPI OIDC, npm, Maven Central Central Portal via vanniktech, scp-swift SPM mirror). Reviewed read-only 2026-06-24.

**How to apply:** When release.yml changes, re-check these residual risks.

## Confirmed-sound design choices
- SWIFT_MIRROR_TOKEN via actions/checkout `token:` → scrubbed http.extraHeader, removed in post step, never URL-embedded. Correct.
- Mirror tag immutability: `git ls-remote --exit-code --tags origin refs/tags/$VERSION` guard + non-force `git push origin refs/tags/$VERSION`. VERSION=inputs.version, tag=$VERSION, check=$VERSION — all consistent. Real guarantee AGAINST RE-RUN race within GH Actions, but NOT against a token holder (mirror repo unprotected by design).
- Maven signing: signAllPublications (vanniktech) GPG-signs inline; Central Portal server-side validates sig+checksums. Artifacts ARE signed. Standalone sign-maven job correctly dropped.
- Maven creds now STEP-level env (ORG_GRADLE_PROJECT_*) not job-level — narrows exposure window.
- Swift binaryTarget: url=deterministic scp-core@VERSION release asset, checksum=sha256 of exact zip. SwiftPM verifies checksum on download → substituted asset = checksum mismatch = resolve fails. Strong.

## RESOLVED in current diff (2026-06-24 re-review)
- **Prior HIGH (cargo-in-credentialed-step) is FIXED by this diff.** publish-maven now runs `./gradlew publishAndReleaseToMavenCentral -x generateUniffiBindings`. Verified: (1) generateUniffiBindings (scp-kt/build.gradle.kts:122) is the ONLY Exec/cargo hook in the entire gradle build — grep of both modules + root + settings shows no other Exec/cargo/cmake/ndk/commandLine; android module has zero native build (consumes prebuilt jniLibs via implementation(project(":scp-kt"))). (2) The task is registered once, in :scp-kt; `-x` removes it build-wide. (3) compileKotlin dependsOn(generateUniffiBindings) — `-x` drops the dependency from the task graph; compileKotlin then compiles against the downloaded kotlin-bindings (.kt placed into src/main/kotlin/.../internal/). (4) The real cargo run moved to the credential-FREE build-matrix `Generate Kotlin bindings` step (no env:/secrets). Net: no build.rs/proc-macro executes with the signing key/Portal token in scope. Sound.

## Residual risks (findings) — still open
- **MEDIUM — automaticRelease=true removes human staging gate.** Compromised pipeline → instant irreversible Maven Central publish, no manual close/release checkpoint.
- **MEDIUM — GitHub release assets are mutable even though tag is immutable.** Swift checksum binds the zip, but SHA256SUMS / python wheels / sdist attached to the same release can be swapped post-publish by anyone with contents:write. Only the Swift zip is checksum-pinned by a consumer.
- **MEDIUM — mirror file filter is a denylist not allowlist.** `cp -R ../swift-sources/SCP/.` then `find -type l -delete` then `find ! -name '*.swift' -delete`. Keeps ONLY *.swift (good), but the artifact source (swift-sources) is an unverified upload-artifact from build-matrix; a compromised build job could inject a malicious *.swift that survives the filter and ships to all SwiftPM consumers. No checksum/signature on Swift SOURCE (only the binary XCFramework is checksummed).
- **LOW — npm package.json repository url hardcoded, per-platform packages published unsigned (npm has no sig); provenance attestation (npm --provenance) not used.**
- **LOW — dry-run skips sign-apple/sign-windows entirely** (if: !inputs.dry-run) so dry-run validates less than a real run; acceptable but means signing path is only exercised on real releases.
