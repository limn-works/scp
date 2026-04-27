plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("org.jlleitschuh.gradle.ktlint") version "12.2.0"
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
    id("org.jetbrains.dokka")
    id("maven-publish")
    id("signing")
}

group = "works.limn"
version = "0.1.0"

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(17)
}

java {
    withJavadocJar()
    withSourcesJar()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0")
    implementation("net.java.dev.jna:jna:5.18.1")

    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}

// Exclude RealFFITest from compilation when UniFFI bindings are not generated.
// The test references `uniffi.scp.*` classes that only exist after running
// `./scripts/generate-uniffi-kotlin.sh`. CI generates bindings before tests;
// local dev can skip these tests safely.
val uniffiBindingsDir = file("src/main/kotlin/works/limn/scp/internal")
val hasUniffiBindings = uniffiBindingsDir.exists() && uniffiBindingsDir.listFiles()?.any { it.extension == "kt" } == true

if (!hasUniffiBindings) {
    sourceSets.test {
        kotlin.exclude("**/RealFFITest.kt")
        // SCP-OUT-023 AC-7: caveats round-trip test exercises `uniffi.scp.*`
        // identifiers (real bridge); skip when bindings aren't generated.
        kotlin.exclude("**/CaveatsRoundtripTest.kt")
    }
}

tasks.test {
    useJUnitPlatform()

    // JNA needs to find `libscp_ffi_uniffi.{dylib,so,dll}` to load the
    // UniFFI-generated bindings. The Rust cdylib is built to the
    // workspace's `target/{debug,release}` directory. Point JNA at
    // both candidate paths so the tests run without the caller having
    // to set `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` manually.
    //
    // PersistenceTest and ScpClassTest skip themselves via
    // `assumeTrue(nativeAvailable)` when the dylib is absent (browser
    // runtime, fresh checkout without a cargo build yet). This just
    // lets them run locally after `cargo build -p scp-ffi-uniffi` or
    // `./scripts/generate-uniffi-kotlin.sh` (which builds the lib).
    //
    // Matches CI (`.github/workflows/ci.yml`) which sets
    // `LD_LIBRARY_PATH` to `target/debug` before `./gradlew test`.
    // Here we do it structurally in Gradle so local dev matches CI.
    val workspaceRoot = rootProject.projectDir.parentFile.parentFile
    val candidates =
        listOf(
            "${workspaceRoot}/target/debug",
            "${workspaceRoot}/target/release",
        )
    systemProperty("jna.library.path", candidates.joinToString(File.pathSeparator))
}

detekt {
    config.setFrom("../detekt.yml")
    buildUponDefaultConfig = true
}

// Exclude UniFFI-generated bindings from detekt analysis. The generated
// `src/main/kotlin/works/limn/scp/internal/uniffi/scp/scp.kt` file is
// produced by `./scripts/generate-uniffi-kotlin.sh` and necessarily
// violates `LongParameterList` (callback trampolines have ≥6 params by
// the UniFFI ABI) and other style rules that apply to hand-written
// code. CI does not generate these bindings before detekt so the issue
// does not surface there; locally we get false positives on every run.
//
// detekt 1.23 deprecated the `build.excludes` YAML key, so the
// exclusion lives on the Gradle task instead.
tasks.withType<io.gitlab.arturbosch.detekt.Detekt>().configureEach {
    exclude("**/internal/uniffi/**")
}

// ktlint also needs to skip the generated bindings — it fails to parse
// UniFFI's output (single-file, ≥3000 lines of trampolines, Long alias
// declarations etc.). Same CI / local divergence as detekt: CI doesn't
// generate before lint, so we only hit this locally.
ktlint {
    filter {
        exclude { element -> element.file.path.contains("/internal/uniffi/") }
    }
}

// ---------------------------------------------------------------------------
// UniFFI Kotlin binding generation
//
// UniFFI proc-macro bindings require the compiled Rust cdylib because metadata
// is embedded at compile time via uniffi::include_scaffolding!. The generation
// script builds the Rust library then invokes uniffi-bindgen to produce Kotlin
// source files into src/main/kotlin/works/limn/scp/internal/.
//
// Run manually: ./scripts/generate-uniffi-kotlin.sh
// Run via Gradle: ./gradlew :scp-kt:generateUniffiBindings
//
// The generated files are NOT checked into version control. They must be
// regenerated after any change to the UniFFI bridge (crates/scp-ffi/uniffi/).
//
// See ADR-021 (UniFFI Bridge) and .docs/scaffold/kotlin.md.
// ---------------------------------------------------------------------------
tasks.register<Exec>("generateUniffiBindings") {
    group = "codegen"
    description = "Generate Kotlin bindings from the scp-ffi-uniffi Rust crate via UniFFI"
    workingDir = rootProject.projectDir.parentFile.parentFile
    commandLine("./scripts/generate-uniffi-kotlin.sh")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = "works.limn"
            artifactId = "scp-kt"
            version = project.version.toString()

            from(components["java"])

            pom {
                name.set("SCP SDK for Kotlin")
                description.set("Kotlin SDK for the Shared Context Protocol")
                url.set("https://github.com/limn/scp")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        id.set("limn")
                        name.set("Limn")
                        email.set("dev@limn.dev")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/limn/scp.git")
                    developerConnection.set("scm:git:ssh://github.com/limn/scp.git")
                    url.set("https://github.com/limn/scp")
                }
            }
        }
    }
    repositories {
        maven {
            name = "sonatypeStaging"
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = System.getenv("MAVEN_CENTRAL_USERNAME")
                password = System.getenv("MAVEN_CENTRAL_TOKEN")
            }
        }
        maven {
            name = "sonatypeSnapshots"
            url = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            credentials {
                username = System.getenv("MAVEN_CENTRAL_USERNAME")
                password = System.getenv("MAVEN_CENTRAL_TOKEN")
            }
        }
    }
}

signing {
    val signingKeyId = System.getenv("GPG_KEY_ID")
    val signingKey = System.getenv("GPG_PRIVATE_KEY")
    val signingPassword = System.getenv("GPG_PASSPHRASE")
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications["mavenJava"])
}

tasks.withType<Sign>().configureEach {
    onlyIf { System.getenv("GPG_PRIVATE_KEY") != null }
}
