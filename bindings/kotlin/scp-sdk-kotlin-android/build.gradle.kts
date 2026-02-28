plugins {
    id("com.android.library")
    kotlin("android")
    kotlin("plugin.serialization")
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
}

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

    // AndroidX Security — EncryptedSharedPreferences for key storage fallback (ADR-027)
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // AndroidX Core — Kotlin extensions
    implementation("androidx.core:core-ktx:1.15.0")

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
}

detekt {
    config.setFrom("../detekt.yml")
    buildUponDefaultConfig = true
}
