import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.net.URLClassLoader

plugins {
    id("com.android.library")
    kotlin("android")
    kotlin("plugin.compose")
    kotlin("plugin.serialization")
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
    id("maven-publish")
    id("signing")
}

// The directory cargo compiles `libscp_ffi_uniffi` into, asked of `cargo metadata`
// exactly as `:scp-kt` does (a shared `build.target-dir` puts it outside this
// checkout). The provider runs only when a test task reads it.
val cargoTargetDir: Provider<String> =
    providers
        .exec {
            workingDir = rootProject.projectDir.parentFile.parentFile
            commandLine(
                "cargo",
                "metadata",
                "--manifest-path",
                "crates/scp-ffi/uniffi/Cargo.toml",
                "--format-version",
                "1",
                "--no-deps",
            )
        }.standardOutput.asText
        .map { json ->
            val metadata = groovy.json.JsonSlurper().parseText(json) as Map<*, *>
            metadata["target_directory"] as? String
                ?: throw GradleException("cargo metadata named no target_directory")
        }

// Passes `-Djna.library.path` to the unit-test JVM (same shape as `:scp-kt`).
class JnaLibraryPath(
    @get:Input val cargoTargetDir: Provider<String>,
) : CommandLineArgumentProvider {
    override fun asArguments(): Iterable<String> {
        val dir = cargoTargetDir.get()
        return listOf("-Djna.library.path=$dir/debug${File.pathSeparator}$dir/release")
    }
}

// Robolectric offline mode (robolectric.org/configuring, "Offline mode"). By
// default Robolectric downloads the `android-all-instrumented` jar for each SDK a
// test runs against from Maven Central at test time, through its own
// `MavenArtifactFetcher`, outside Gradle's resolution, cache, and retries, so a
// failed download failed every Robolectric test. Gradle now resolves those jars
// through `robolectricAndroidAll`, syncs them into one directory, and the test JVM
// runs with `robolectric.offline=true` and `robolectric.dependency.dir` set to it.
// In offline mode a jar missing from that directory fails the test with
// `IllegalArgumentException: Path is not a file: <dir>/<jar>`.
val robolectricVersion = "4.14.1"

// Every SDK level a Robolectric test runs against, read from the test sources.
// Robolectric takes a test's SDK from its `@Config(sdk = ...)`, else from an
// `sdk=` line in a `robolectric.properties` test resource, else from the
// manifest's targetSdkVersion (`DefaultSdkPicker`). That last default does not
// come from `compileSdk`: under `manifest = Config.NONE`, which every test here
// sets, Robolectric's `AndroidManifest` has no manifest to read and reports its
// built-in fallback, 21; without it, the merged test manifest's targetSdkVersion
// decides. Rather than mirror that rule, the build requires each Robolectric test
// class to name its SDK in `@Config` or `robolectric.properties`, and this
// function fails the build when one does not.
// A level this scan misses still fails closed at test time with the
// `Path is not a file` error above, never a download.
fun robolectricSdkLevels(): Set<Int> {
    val sources =
        fileTree("src").matching { include("test*/**/*.kt", "test*/**/*.java") }.files
    val propertyFiles =
        fileTree("src").matching { include("test*/resources/**/robolectric.properties") }.files
    val levels = sortedSetOf<Int>()
    fun parseLevels(
        text: String,
        where: String,
    ): List<Int> =
        text.split(',').map { it.trim() }.filter { it.isNotEmpty() }.map {
            it.toIntOrNull()
                ?: throw GradleException(
                    "$where: Robolectric SDK `$it` is not an integer literal; the build " +
                        "resolves the android-all jar for each level and reads only literals",
                )
        }
    var propertiesNameSdk = false
    propertyFiles.forEach { file ->
        file.readLines().map { it.trim() }.filter { it.startsWith("sdk=") }.forEach {
            levels += parseLevels(it.removePrefix("sdk="), file.path)
            propertiesNameSdk = true
        }
    }
    val runner = Regex("""@RunWith\(\s*\w*RobolectricTestRunner::class""")
    val sdkArgument = Regex("""\bsdk\s*=\s*(?:\[([^\]]*)]|intArrayOf\(([^)]*)\)|\{([^}]*)}|(\d+))""")
    sources.forEach { file ->
        val text = file.readText()
        var sdkConfigs = 0
        var start = text.indexOf("@Config(")
        while (start >= 0) {
            var depth = 0
            var end = start + "@Config".length
            do {
                when (text[end]) {
                    '(' -> depth++
                    ')' -> depth--
                }
                end++
            } while (depth > 0 && end < text.length)
            val annotation = text.substring(start, end)
            if (Regex("""\b(minSdk|maxSdk)\s*=""").containsMatchIn(annotation)) {
                throw GradleException(
                    "${file.path}: `$annotation` uses minSdk/maxSdk; name each level in `sdk`",
                )
            }
            sdkArgument.find(annotation)?.let { match ->
                levels += parseLevels(match.groupValues.drop(1).first { it.isNotEmpty() }, file.path)
                sdkConfigs++
            }
            start = text.indexOf("@Config(", end)
        }
        val runners = runner.findAll(text).count()
        if (runners > sdkConfigs && !propertiesNameSdk) {
            throw GradleException(
                "${file.path}: $runners Robolectric test class(es) but $sdkConfigs `@Config(sdk = ...)`; " +
                    "name the SDK level in each class's `@Config` so the build resolves its android-all jar",
            )
        }
    }
    return levels
}

// The Maven coordinates of the android-all jar Robolectric loads for each level,
// asked of Robolectric's own `DefaultSdkProvider` on the unit-test classpath, so
// they match the table the test JVM reads and follow a Robolectric upgrade. The
// provider calls its `DependencyResolver` with the jar it wants; the proxy below
// records that jar and answers with an existing file so `getJarPath` returns.
fun robolectricAndroidAllCoordinates(
    classpath: Set<File>,
    levels: Set<Int>,
): List<String> {
    val loader =
        URLClassLoader(
            classpath.map { it.toURI().toURL() }.toTypedArray(),
            ClassLoader.getPlatformClassLoader(),
        )
    return loader.use { robolectric ->
        val dependencyJar = robolectric.loadClass("org.robolectric.internal.dependency.DependencyJar")
        val resolverType = robolectric.loadClass("org.robolectric.internal.dependency.DependencyResolver")
        val anyExistingFile = classpath.first { file -> file.isFile }.toURI().toURL()
        val requested = mutableListOf<String>()
        val handler =
            InvocationHandler { proxy: Any, method: Method, args: Array<Any?>? ->
                when (method.name) {
                    "getLocalArtifactUrl" -> {
                        val jar = args?.firstOrNull()
                        val part = { name: String -> dependencyJar.getMethod(name).invoke(jar).toString() }
                        requested += "${part("getGroupId")}:${part("getArtifactId")}:${part("getVersion")}"
                        anyExistingFile
                    }
                    "toString" -> "robolectricAndroidAllCoordinates resolver"
                    "hashCode" -> System.identityHashCode(proxy)
                    "equals" -> proxy === args?.firstOrNull()
                    else -> throw GradleException("unexpected DependencyResolver call ${method.name}")
                }
            }
        val resolver = Proxy.newProxyInstance(robolectric, arrayOf(resolverType), handler)
        val provider =
            robolectric
                .loadClass("org.robolectric.plugins.DefaultSdkProvider")
                .getConstructor(resolverType)
                .newInstance(resolver)
        val sdks = (provider.javaClass.getMethod("getSdks").invoke(provider) as Collection<*>).filterNotNull()
        val byLevel = sdks.associateBy { sdk -> sdk.javaClass.getMethod("getApiLevel").invoke(sdk) as Int }
        levels.forEach { level ->
            val sdk =
                byLevel[level]
                    ?: throw GradleException(
                        "Robolectric $robolectricVersion knows no SDK $level (known: ${byLevel.keys.sorted()})",
                    )
            sdk.javaClass.getMethod("getJarPath").invoke(sdk)
        }
        requested.distinct()
    }
}

// One detached configuration per jar: the jars share `group:artifact` and differ
// only in version, so a single configuration would keep only the highest version
// through Gradle's conflict resolution and drop every other SDK's jar.
val robolectricAndroidAll: Provider<List<Configuration>> =
    provider {
        // External jars only: Robolectric's classes need no project output, so
        // resolving them must not compile this module or `:scp-kt`.
        val classpath =
            configurations
                .getByName("debugUnitTestRuntimeClasspath")
                .incoming
                .artifactView {
                    attributes { attribute(Attribute.of("artifactType", String::class.java), "android-classes-jar") }
                    componentFilter { it is ModuleComponentIdentifier }
                }.files
                .files
        val levels = robolectricSdkLevels()
        val coordinates = robolectricAndroidAllCoordinates(classpath, levels)
        logger.info("Robolectric SDK levels {} resolve to {}", levels, coordinates)
        coordinates.map { coordinate ->
            configurations.detachedConfiguration(dependencies.create(coordinate)).apply { isTransitive = false }
        }
    }

val robolectricDependencyDir: Provider<Directory> = layout.buildDirectory.dir("robolectric/android-all")

val syncRobolectricAndroidAll =
    tasks.register<Sync>("syncRobolectricAndroidAll") {
        from(robolectricAndroidAll)
        into(robolectricDependencyDir)
    }

// Passes the offline-mode properties to the unit-test JVM. The directory is a task
// input, so a changed jar set reruns the tests.
class RobolectricOffline(
    @get:InputFiles @get:PathSensitive(PathSensitivity.NAME_ONLY) val dependencyDir: Provider<Directory>,
) : CommandLineArgumentProvider {
    override fun asArguments(): Iterable<String> =
        listOf(
            "-Drobolectric.offline=true",
            "-Drobolectric.dependency.dir=${dependencyDir.get().asFile.absolutePath}",
        )
}

group = "works.limn"
version = findProperty("scpVersion")?.toString() ?: "0.1.0-SNAPSHOT"

// Configures :scp-kt first, then registers scp-kt's uniffiPublishGuard (see
// scp-kt/build.gradle.kts) for this project's tasks, naming `compileReleaseKotlin`
// as this project's compile task.
evaluationDependsOn(":scp-kt")
@Suppress("UNCHECKED_CAST")
val uniffiPublishGuard =
    project(":scp-kt").extra["uniffiPublishGuard"] as (TaskExecutionGraph, Project, String) -> Unit
gradle.taskGraph.whenReady { uniffiPublishGuard(this, project, "compileReleaseKotlin") }

repositories {
    google()
    mavenCentral()
}

android {
    namespace = "works.limn.scp.android"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    testOptions {
        unitTests {
            isReturnDefaultValues = true
            isIncludeAndroidResources = true
            // The Android Gradle plugin runs unit tests on the JUnit 4 runner
            // unless a test task opts into the JUnit Platform, and the JUnit 4
            // runner never discovers a class annotated with Jupiter's `@Test`.
            // The Platform runs the Jupiter tests through `junit-jupiter-engine`
            // and the JUnit 4 tests (Robolectric, the Compose rule) through
            // `junit-vintage-engine`, both declared below.
            all {
                it.useJUnitPlatform()
                // The pseudonym tests call the `scp-ffi-uniffi` P-256 exports (§9.5,
                // §9.10.4) through the `:scp-kt` bindings, so JNA must find the cdylib.
                it.jvmArgumentProviders.add(JnaLibraryPath(cargoTargetDir))
                // Robolectric reads its android-all jars from the directory Gradle
                // fills, never from the network (see `robolectricAndroidAll`).
                it.dependsOn(syncRobolectricAndroidAll)
                it.jvmArgumentProviders.add(RobolectricOffline(robolectricDependencyDir))
            }
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

dependencies {
    // SCP core Kotlin SDK
    implementation(project(":scp-kt"))

    // Bouncy Castle — software Ed25519 fallback for API 26-32 (ADR-027)
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")

    // Play Integrity — device attestation (ADR-027)
    implementation("com.google.android.play:integrity:1.4.0")

    // Firebase Cloud Messaging — push notifications (ADR-027)
    implementation("com.google.firebase:firebase-messaging:24.1.0")

    // SQLCipher — encrypted database storage (ADR-027)
    implementation("net.zetetic:sqlcipher-android:4.6.1")
    implementation("androidx.sqlite:sqlite:2.2.0")

    // AndroidX Security — EncryptedSharedPreferences for key storage fallback (ADR-027)
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // AndroidX Core — Kotlin extensions
    implementation("androidx.core:core-ktx:1.15.0")

    // AndroidX Lifecycle — lifecycle-aware resource management (ADR-028, SCP-117)
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")

    // Jetpack Compose — state holders and remember patterns (ADR-028, SCP-118)
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.runtime:runtime")
    implementation("androidx.compose.ui:ui")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0")

    // UniFFI JNA dependency
    implementation("net.java.dev.jna:jna:5.18.1@aar")

    // Testing
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("org.robolectric:robolectric:$robolectricVersion")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.lifecycle:lifecycle-runtime-testing:2.8.7")
    testImplementation("junit:junit:4.13.2")
    // The JVM unit tests load the UniFFI cdylib through the jar build of JNA; the
    // `@aar` above carries only the Android native stubs.
    testImplementation("net.java.dev.jna:jna:5.18.1")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine:5.11.4")

    // SQLite JDBC — JVM-side SQLite for storage conformance tests (SCP-PERSIST-060)
    testImplementation("org.xerial:sqlite-jdbc:3.47.2.0")

    // Compose testing (SCP-118)
    testImplementation("androidx.compose.ui:ui-test-junit4")
    // Available in all test variants so Robolectric can resolve ComponentActivity
    // in both debug and release unit tests (see #144)
    testImplementation("androidx.compose.ui:ui-test-manifest")
}

detekt {
    config.setFrom("../detekt.yml")
    buildUponDefaultConfig = true
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])

                groupId = "works.limn"
                artifactId = "scp-kt-android"
                version = project.version.toString()

                pom {
                    name.set("SCP SDK for Kotlin — Android Extensions")
                    description.set("Android lifecycle and platform extensions for the SCP Kotlin SDK")
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
        sign(publishing.publications["release"])
    }

    tasks.withType<Sign>().configureEach {
        onlyIf { System.getenv("GPG_PRIVATE_KEY") != null }
    }
}
