/*
 * Kotlin parity runner for the ADR-046 bridge parity harness.
 *
 * Long-lived JVM executable that reads length-prefixed JSON-RPC frames
 * on stdin and writes length-prefixed responses on stdout. Dispatches
 * to UniFFI-generated Kotlin bindings (`uniffi.scp.*`), which are
 * produced by the scp-kt composite-included project.
 *
 * The runner intentionally does NOT depend on works.limn:scp-kt (the
 * Kotlin SDK wrapper layer). It consumes the UniFFI-generated package
 * directly so the parity harness tests the bridge surface, not the
 * higher-level Kotlin ergonomics. But to get those generated bindings
 * on the classpath without re-running binding generation here, we pull
 * in scp-kt's output — the bindings live inside its `main` source set.
 *
 * Run: ./gradlew :kotlin-bridge-runner:run --args="" --quiet
 * (The harness resolves the application script directly via distTar /
 * installDist — see conftest.py.)
 */

plugins {
    kotlin("jvm") version "2.1.10"
    application
}

group = "works.limn.scp.parity"
version = "0.1.0"

repositories {
    mavenCentral()
    google()
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // scp-kt carries the UniFFI-generated `uniffi.scp.*` package in its
    // main source set. Depending on it gives us the generated bindings
    // plus its transitive JNA + coroutines dependencies, all version-
    // aligned with the in-tree Kotlin SDK.
    implementation("works.limn:scp-kt:0.1.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0")
    implementation("net.java.dev.jna:jna:5.18.1")
}

application {
    mainClass.set("works.limn.scp.parity.MainKt")
    // Keep JVM warmup overhead low — the runner is long-lived, so
    // tiered compilation pays off, but we don't need AOT.
    applicationDefaultJvmArgs = listOf(
        "-XX:+UseSerialGC",
        "-Xss1M"
    )
}

// The `run` task inherits stdin from the Gradle daemon by default,
// which breaks the JSON-RPC wire protocol. The harness does NOT invoke
// `./gradlew run` — it uses `installDist` and then launches the bin
// script directly so stdin is the harness's pipe. This configuration
// block exists so `./gradlew run` is still usable for manual smoke
// testing (e.g. `echo '{...}' | ./gradlew run --quiet`).
tasks.named<JavaExec>("run") {
    standardInput = System.`in`
}
