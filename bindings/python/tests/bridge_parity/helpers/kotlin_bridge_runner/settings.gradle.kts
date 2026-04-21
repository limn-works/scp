/*
 * Kotlin parity runner for the ADR-046 bridge parity harness.
 *
 * A standalone Gradle project that depends on the in-tree scp-kt module
 * via composite build. That gives the runner access to the UniFFI-
 * generated bindings (`uniffi.scp.*`) that the main SDK uses, rather
 * than duplicating the binding generation step here.
 *
 * The relative path climbs out of
 *   bindings/python/tests/bridge_parity/helpers/kotlin_bridge_runner/
 * to the repo root, then back down to
 *   bindings/kotlin/ (which declares `scp-kt` in its settings).
 */
rootProject.name = "kotlin-bridge-runner"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
    }
}

// Composite build: brings in `:scp-kt` and its UniFFI bindings.
// Six levels up to repo root, then down to bindings/kotlin.
includeBuild("../../../../../../bindings/kotlin")
