import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    id("com.android.library")
    kotlin("android")
    kotlin("plugin.compose")
    kotlin("plugin.serialization")
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
    // Version declared in the root build.gradle.kts (apply false) — see there.
    id("com.vanniktech.maven.publish")
}

group = "works.limn"
version = findProperty("scpVersion")?.toString() ?: "0.1.0-SNAPSHOT"

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
        }
    }
    // The publication variant is configured by the vanniktech plugin via
    // AndroidSingleVariantLibrary("release") below — do not also declare
    // android { publishing { singleVariant } } here or AGP errors on a
    // double-configured variant.
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
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.lifecycle:lifecycle-runtime-testing:2.8.7")
    testImplementation("junit:junit:4.13.2")
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

// Publishing to Maven Central via the Central Portal (central.sonatype.com).
// See scp-kt/build.gradle.kts for the rationale and the ORG_GRADLE_PROJECT_*
// credential properties. AndroidSingleVariantLibrary publishes the assembled
// `release` AAR (which carries the UniFFI jniLibs staged by the release
// pipeline's native build) plus sources and an empty Javadoc jar.
mavenPublishing {
    configure(
        AndroidSingleVariantLibrary(
            variant = "release",
            sourcesJar = true,
            publishJavadocJar = true,
        ),
    )
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL, automaticRelease = true)
    signAllPublications()
    coordinates("works.limn", "scp-kt-android", project.version.toString())

    pom {
        name.set("SCP SDK for Kotlin — Android Extensions")
        description.set("Android lifecycle and platform extensions for the SCP Kotlin SDK")
        inceptionYear.set("2026")
        url.set("https://github.com/limn-works/scp")
        licenses {
            license {
                name.set("Apache-2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0")
                distribution.set("https://www.apache.org/licenses/LICENSE-2.0")
            }
        }
        developers {
            developer {
                id.set("limn")
                name.set("Limn")
                url.set("https://github.com/limn-works")
            }
        }
        scm {
            url.set("https://github.com/limn-works/scp")
            connection.set("scm:git:git://github.com/limn-works/scp.git")
            developerConnection.set("scm:git:ssh://git@github.com/limn-works/scp.git")
        }
    }
}
