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
version = findProperty("scpVersion")?.toString() ?: "0.1.0-SNAPSHOT"

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

// Directory `generateUniffiBindings` writes the generated Kotlin bindings into.
// `compileKotlin` depends on that task (see the bottom of this file), so every
// compilation regenerates the bindings and no source-set exclusion is needed to
// keep a `uniffi.scp.*` reference compiling. The exclusion that used to sit here
// named `RealFFITest.kt`, a file the repository no longer contains, and it
// gated on `listFiles()`, which lists only this directory's immediate children
// while the generator writes `uniffi/scp/scp.kt` two levels down — so the
// condition was already always false.
val uniffiBindingsDir = file("src/main/kotlin/works/limn/scp/internal")

// ---------------------------------------------------------------------------
// Ordering against the generator
// ---------------------------------------------------------------------------
// `generateUniffiBindings` declares `uniffiBindingsDir` as its output, and that
// directory sits inside `src/main/kotlin`, this project's own Kotlin source
// root. Gradle fails any task that reads a directory another task declares as
// output unless the two carry an ordering edge, so THE RULE IS: every task in
// this project that reads a file under `src/main/kotlin` declares
// `dependsOn("generateUniffiBindings")` or `mustRunAfter("generateUniffiBindings")`.
// `checkUniffiBindingsOrdering` at the bottom of this file enforces the rule
// against Gradle's task model, so a task added later is covered without anyone
// editing a list of names.
//
// Which of the two edges a task takes follows from whether it consumes what the
// generator writes:
//   - `compileKotlin`, `sourcesJar` and `kotlinSourcesJar` compile and package
//     the generated bindings, so they take `dependsOn` — those files must exist
//     before the task runs, or the compiled classes and the published sources
//     jar disagree about what the module contains.
//   - detekt, ktlint and Dokka each drop the generated tree from their own
//     inputs (see the `exclude`, `filter` and `suppressedFiles` calls below),
//     so they take `mustRunAfter`: Gradle gets the ordering it asked for when
//     both tasks are in one build, and nothing compiles Rust when they run
//     alone. `dependsOn` would put a full `cargo build -p scp-ffi-uniffi` on
//     the `kotlin-lint` job in `.github/workflows/ci.yml` and the
//     `kotlin-docs` job in `.github/workflows/docs.yml`, neither of which
//     installs a Rust toolchain or caches a cargo target directory.

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
//
// detekt declares the whole main source tree as an input, so it falls under the
// ordering rule stated above and takes the `mustRunAfter` edge: `./gradlew
// detekt test` failed with an implicit-dependency validation error once the
// generated bindings existed on disk.
// `detektBaseline` reads the same tree under a different task type, so it takes
// the same exclusion and the same edge; `withType<Detekt>` alone skips it.
tasks.withType<io.gitlab.arturbosch.detekt.Detekt>().configureEach {
    mustRunAfter("generateUniffiBindings")
    exclude("**/internal/uniffi/**")
}
tasks.withType<io.gitlab.arturbosch.detekt.DetektCreateBaselineTask>().configureEach {
    mustRunAfter("generateUniffiBindings")
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

// Every ktlint task reads the same main source tree detekt reads, so the
// ordering rule stated above covers it too, and the `ktlint` filter above
// drops the generated tree from every ktlint task — so `mustRunAfter`, for the
// reason detekt uses it. Name-matching covers the check and format tasks the
// plugin generates per source set (`runKtlintCheckOverMainSourceSet`,
// `runKtlintFormatOverTestSourceSet`, and their siblings) without naming
// each one.
tasks.matching { it.name.startsWith("runKtlint") }.configureEach {
    mustRunAfter("generateUniffiBindings")
}

// Dokka reads the main source tree to build the published Kotlin API reference,
// so the ordering rule covers every Dokka task. `suppressedFiles` drops the
// generated tree from the reference, because UniFFI emits public declarations
// in package `uniffi.scp`: a `./gradlew build dokkaHtml` renders that package
// into the reference, while `./gradlew dokkaHtml` alone leaves it out, and the
// suppression makes both runs render the same API. The suppression is also what
// leaves Dokka reading none of what the generator writes, which is what makes
// `mustRunAfter` the right edge here.
tasks.withType<org.jetbrains.dokka.gradle.AbstractDokkaTask>().configureEach {
    mustRunAfter("generateUniffiBindings")
}
tasks.withType<org.jetbrains.dokka.gradle.AbstractDokkaLeafTask>().configureEach {
    dokkaSourceSets.configureEach {
        suppressedFiles.from(uniffiBindingsDir)
    }
}

// `sourcesJar` packages `src/main/kotlin` into the published sources artifact,
// generated bindings included, so it takes the `dependsOn` edge rather than an
// ordering-only one: the sources jar that ships to Maven Central must carry the
// sources for every class in the binary jar beside it, whatever else the build
// happened to ask for. `java.withSourcesJar()` above registers the task, and
// `.github/workflows/release.yml` reaches it through
// `:scp-kt:publishMavenJavaPublicationToSonatypeStagingRepository`.
// `kotlinSourcesJar`, which the Kotlin JVM plugin registers, packages the same
// tree and takes the same edge for the same reason.
listOf("sourcesJar", "kotlinSourcesJar").forEach { sourcesJarTask ->
    tasks.named(sourcesJarTask) {
        dependsOn("generateUniffiBindings")
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
    // Extra cargo features passed alongside the default `testing` feature
    // (which now gates the in-memory custody arm). The bridge-parity CI job
    // sets `-Pscp.uniffi.extraFeatures=testing` so the regenerated cdylib keeps
    // the `signed_at_override` parity affordance (`#[cfg(feature = "testing")]`).
    // Production consumers leave it unset so the testing surface is not linked
    // into release binaries.
    val extraFeatures = providers.gradleProperty("scp.uniffi.extraFeatures").getOrElse("")
    val featuresArg = if (extraFeatures.isEmpty()) {
        "--features=testing"
    } else {
        "--features=testing,$extraFeatures"
    }
    commandLine("./scripts/generate-uniffi-kotlin.sh", featuresArg)
    // Invalidate on any Rust change under the uniffi crate so stale bindings never compile.
    inputs.files(fileTree(rootProject.projectDir.parentFile.parentFile.resolve("crates/scp-ffi/uniffi/src")))
    inputs.files(fileTree(rootProject.projectDir.parentFile.parentFile.resolve("crates/scp-ffi/common/src")))
    outputs.dir(uniffiBindingsDir)
}

// Wire generation into the compile chain so `./gradlew :scp-kt:build` or `test`
// always regenerates when Rust sources change. Without this, a developer who
// edits the UniFFI bridge and forgets to regenerate would compile Kotlin
// against stale bindings — every caller would silently miss any new handle-
// affinity check or API change. (Round-2 black-hat finding.)
tasks.matching { it.name == "compileKotlin" }.configureEach {
    dependsOn("generateUniffiBindings")
}

// ---------------------------------------------------------------------------
// Ordering gate
// ---------------------------------------------------------------------------
// Enforces the rule stated near the top of this file: every task in this
// project that reads a file under `src/main/kotlin` reaches
// `generateUniffiBindings` through `dependsOn`, or names it in `mustRunAfter`.
// Gradle itself reports a violation only when both tasks land in one build and
// the offending task actually executes, which is why `sourcesJar`,
// `kotlinSourcesJar`, `detektBaseline` and the six Dokka tasks all shipped
// without an edge — no CI job ran any of them beside the generator. This gate
// reads the edges out of Gradle's task model instead, so it fails on a missing
// edge whichever tasks the caller asked for, and a task added later is covered
// without anyone editing a list of names.
//
// A task's inputs decide membership: any input file under `src/main/kotlin`
// puts the task under the rule, because the generator's output directory sits
// inside that root. The hand-written sources are always on disk, so the gate
// reports the same set whether or not the generator has ever run.
fun isOrderedAfter(consumer: Task, producer: Task): Boolean {
    val visited = mutableSetOf<Task>()
    val pending = ArrayDeque<Task>()
    pending.addLast(consumer)
    while (pending.isNotEmpty()) {
        val current = pending.removeFirst()
        if (!visited.add(current)) continue
        if (current === producer) return true
        if (current.mustRunAfter.getDependencies(current).contains(producer)) return true
        pending.addAll(current.taskDependencies.getDependencies(current))
    }
    return false
}

tasks.register("checkUniffiBindingsOrdering") {
    group = "verification"
    description = "Assert every task reading src/main/kotlin is ordered after generateUniffiBindings"
    notCompatibleWithConfigurationCache("Reads the ordering edges of every task in the project")
    val kotlinSourceRoot = file("src/main/kotlin").toPath()
    val projectTasks = tasks
    val gateName = name
    doLast {
        val generator = projectTasks.getByName("generateUniffiBindings")
        val unordered =
            projectTasks
                .filter { it.name != generator.name && it.name != gateName }
                .filter { candidate ->
                    candidate.inputs.files.files.any { it.toPath().startsWith(kotlinSourceRoot) }
                }
                .filterNot { isOrderedAfter(it, generator) }
                .map { it.path }
                .sorted()
        require(unordered.isEmpty()) {
            buildString {
                appendLine("These tasks read src/main/kotlin without an ordering edge to generateUniffiBindings:")
                unordered.forEach { appendLine("  $it") }
                appendLine()
                appendLine("Gradle fails such a task with an implicit-dependency validation error whenever")
                appendLine("the generator shares its build. Add dependsOn(\"generateUniffiBindings\") when the")
                appendLine("task consumes the generated bindings, or mustRunAfter(\"generateUniffiBindings\")")
                appendLine("when the task drops them from its own inputs. The rule and the choice between")
                appendLine("the two edges are stated at the top of scp-kt/build.gradle.kts.")
            }
        }
    }
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
