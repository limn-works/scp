plugins {
    id("com.android.library")
    kotlin("android")
    kotlin("plugin.compose")
    kotlin("plugin.serialization")
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
    id("maven-publish")
    id("signing")
}

group = "com.limn"
version = "0.1.0"

repositories {
    google()
    mavenCentral()
}

android {
    namespace = "com.limn.scp.android"
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

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

dependencies {
    // SCP core Kotlin SDK
    implementation(project(":scp-sdk-kotlin"))

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

    // Compose testing (SCP-118)
    testImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
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

                groupId = "com.limn"
                artifactId = "scp-sdk-kotlin-android"
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
