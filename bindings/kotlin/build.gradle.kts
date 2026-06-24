plugins {
    kotlin("jvm") version "2.1.10" apply false
    kotlin("plugin.serialization") version "2.1.10" apply false
    kotlin("plugin.compose") version "2.1.10" apply false
    id("com.android.library") version "8.7.3" apply false
    kotlin("android") version "2.1.10" apply false
    id("org.jetbrains.dokka") version "2.0.0" apply false
    // Declared here (apply false) so it shares the build's classpath with the
    // Kotlin plugin — vanniktech's base plugin needs to access Kotlin plugin
    // classes, which fails when it is applied with a version directly in a
    // subproject. Subprojects apply it without a version. 0.31.0 is the last
    // release before the minimum was raised to Kotlin 2.2.0 (0.36.0); this
    // project is on Kotlin 2.1.10. Central Portal is supported since 0.28.0.
    id("com.vanniktech.maven.publish") version "0.31.0" apply false
}
