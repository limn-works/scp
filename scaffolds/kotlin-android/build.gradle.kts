plugins {
    kotlin("jvm") version "2.0.0"
    application
}

group = "com.example"
version = "0.1.0"

repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    implementation("works.limn:scp-kt:0.1.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
}

application {
    mainClass.set("com.example.scpapp.MainKt")
}

kotlin {
    jvmToolchain(17)
}
