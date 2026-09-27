# A Generator Writing Into a Source Root Needs an Ordering Edge From Every Reader

`generateUniffiBindings` in `bindings/kotlin/scp-kt/build.gradle.kts` writes into
`src/main/kotlin/works/limn/scp/internal`, inside the `src/main/kotlin` source root. Gradle
8.14 fails any task that reads another task's declared output without an ordering edge
("uses this output of task ':scp-kt:generateUniffiBindings' without declaring an explicit or
implicit dependency"), but only when both tasks run in one build. The CI jobs run `detekt`,
ktlint, `test`, and `dokkaHtml` in separate invocations, so nine unordered readers sat
unnoticed until the release publish put `sourcesJar` and the generator in one graph.

Adding `mustRunAfter` per task name is what let the set grow: fixing `Detekt` missed
`DetektCreateBaselineTask`, and fixing `sourcesJar` missed `kotlinSourcesJar`.

## Rule

Every task that reads a file under `src/main/kotlin` declares either
`dependsOn("generateUniffiBindings")` or `mustRunAfter("generateUniffiBindings")`, and the
`checkUniffiBindingsOrdering` task enforces it against Gradle's task model by enumerating
every task whose inputs fall under the source root. It runs in the `kotlin-lint` job of
`.github/workflows/ci.yml` and needs no compiled Rust.

A reader that consumes the generated code (`compileKotlin` and both sources jars) takes
`dependsOn`. detekt, ktlint, and Dokka exclude the generated tree from their inputs and take
`mustRunAfter`, which keeps `cargo build -p scp-ffi-uniffi` out of the `kotlin-lint` and
`kotlin-docs` jobs, neither of which installs Rust.
