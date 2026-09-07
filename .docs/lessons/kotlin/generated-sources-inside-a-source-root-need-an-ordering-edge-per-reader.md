# A Generator Writing Into a Source Root Needs an Ordering Edge From Every Reader

**Problem**: `generateUniffiBindings` in `bindings/kotlin/scp-kt/build.gradle.kts` declares
`src/main/kotlin/works/limn/scp/internal` as its output directory, and that directory sits inside
`src/main/kotlin`. Gradle 8.14.4 fails any task that reads a directory another task declares as
output when the two carry no ordering edge:

```
Reason: Task ':scp-kt:sourcesJar' uses this output of task ':scp-kt:generateUniffiBindings'
without declaring an explicit or implicit dependency.
```

Gradle raises that error only when both tasks land in one build and the reader executes. The Kotlin
CI jobs run `detekt`, `runKtlintCheckOverMainSourceSet`, `test`, and `dokkaHtml` in separate
invocations, so nine reader tasks sat in the build for months without an edge and no job failed:
`sourcesJar`, `kotlinSourcesJar`, `detektBaseline`, and the six Dokka tasks. The release workflow
would have hit the first of them, because
`:scp-kt:publishMavenJavaPublicationToSonatypeStagingRepository` puts `sourcesJar` and the generator
in one graph.

Fixing the readers one name at a time is what let the set grow. Pull request #2377, the Kotlin server
exemptions and identity-advanced wiring, added `mustRunAfter` to the `Detekt` task type and to every
`runKtlint*` task, and each of those two lines left a reader Gradle validates the same way:
`DetektCreateBaselineTask` is a different type from `Detekt`, and `kotlinSourcesJar` is a different
name from `sourcesJar`.

**Correct pattern**: state the rule once — every task in the project that reads a file under
`src/main/kotlin` declares `dependsOn("generateUniffiBindings")` or
`mustRunAfter("generateUniffiBindings")` — and enforce it against Gradle's task model rather than
against a list of task names:

```kotlin
tasks.register("checkUniffiBindingsOrdering") {
    doLast {
        val generator = projectTasks.getByName("generateUniffiBindings")
        val unordered = projectTasks
            .filter { candidate ->
                candidate.inputs.files.files.any { it.toPath().startsWith(kotlinSourceRoot) }
            }
            .filterNot { isOrderedAfter(it, generator) }
        require(unordered.isEmpty()) { /* names every offender */ }
    }
}
```

The gate found `detektBaseline` and `kotlinSourcesJar`, which reading the build file by hand had
missed. It needs no compiled Rust and no generated file on disk, because the hand-written sources
under `src/main/kotlin` already put every reader task in the candidate set, so it runs in the
`kotlin-lint` job of `.github/workflows/ci.yml`.

Which edge a reader takes follows from whether it consumes what the generator writes. `compileKotlin`
and the two sources jars compile and package the generated bindings, so they take `dependsOn`.
detekt, ktlint, and Dokka each drop the generated tree from their own inputs, so they take
`mustRunAfter`, which keeps `cargo build -p scp-ffi-uniffi` off the `kotlin-lint` job and off the
`kotlin-docs` job in `.github/workflows/docs.yml`, neither of which installs a Rust toolchain.

**Rule**: when a code generator writes into a directory a source set already reads, no single reader
task is the fix. Write the membership rule, then let a check enumerate the readers from the build
model. A `mustRunAfter` added per task name is an indicator list standing in for the rule, and the
next reader added to the build escapes it.

Applied in `bindings/kotlin/scp-kt/build.gradle.kts`.
