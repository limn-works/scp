plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("org.jlleitschuh.gradle.ktlint") version "12.2.0"
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
    id("maven-publish")
    id("signing")
}

group = "com.limn"
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

tasks.test {
    useJUnitPlatform()
}

detekt {
    config.setFrom("../detekt.yml")
    buildUponDefaultConfig = true
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            groupId = "com.limn"
            artifactId = "scp-sdk-kotlin"
            version = project.version.toString()

            from(components["java"])

            pom {
                name.set("SCP SDK for Kotlin")
                description.set("Kotlin SDK for the Shareable Context Protocol")
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
