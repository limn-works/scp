# Kotlin Standards

Kotlin conventions, toolchain, and CI for the SCP Kotlin SDK. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions. See `.docs/scaffold/kotlin.md` for the build blueprint (package layout, UniFFI bridge, build config, type definitions).

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Kotlin | 2.0+ | Language version |
| JVM | 11+ | Minimum target (Android API 26+, server-side) |
| Gradle | 8.x (Kotlin DSL) | Build system |
| UniFFI | latest | FFI bridge from Rust (shared UDL with Swift) |
| kotlinx.coroutines | latest | Async/coroutine support |
| ktlint | latest | Linter (Kotlin style guide enforcement) |
| detekt | latest | Static analysis (complexity, code smells) |
| JUnit 5 | latest | Test framework |
| kotlinx.coroutines.test | latest | Coroutine test support |

## Code Style

### Coroutine-first

All I/O operations are `suspend` functions. Streaming uses `Flow<T>`. Blocking FFI calls are wrapped in `withContext(Dispatchers.IO)` to keep callers off the main thread.

### Naming

- Types/classes: `PascalCase`
- Functions/methods/properties: `camelCase`
- Constants: `SCREAMING_SNAKE_CASE`
- Packages: `lowercase` (`com.limn.scp`)
- Files: `PascalCase.kt`

## Testing

### JUnit 5

```kotlin
class IdentityTest {
    @Test
    fun `create identity returns valid DID`() = runTest {
        val identity = Identity.create(custody = "in_memory")
        assertTrue(identity.did.startsWith("did:dht:"))
    }

    @Test
    fun `context send requires active state`() = runTest {
        // ...
    }

    @Test
    fun `ucan rejects replayed nonce`() = runTest {
        // ...
    }
}
```

### Coroutine test support

Use `kotlinx.coroutines.test.runTest` for all suspend function tests.

### Test naming

Use backtick-quoted descriptive names: `` `action condition or expected result` ``.

## Lint Configuration

### ktlint

Enforces the official Kotlin coding conventions. No custom rules — use defaults.

### detekt

`detekt.yml`:

```yaml
complexity:
  CyclomaticComplexMethod:
    threshold: 25
  LongMethod:
    threshold: 60
  TooManyFunctions:
    thresholdInFiles: 30

style:
  ForbiddenComment:
    values: ["TODO", "FIXME", "HACK"]
  MaxLineLength:
    maxLineLength: 120
```

## CI Commands

```bash
# Format check
./gradlew ktlintCheck

# Lint
./gradlew detekt

# Build
./gradlew build

# Test
./gradlew test

# Publish to Maven Local
./gradlew publishToMavenLocal

# Publish to Maven Central (release)
./gradlew publish
```

## CI Matrix

| Job | Runs on | JDK | Trigger |
|-----|---------|-----|---------|
| ktlint | ubuntu-latest | 17 | Every PR |
| detekt | ubuntu-latest | 17 | Every PR |
| dependency-check | ubuntu-latest | 17 | Every PR |
| test | ubuntu-latest, macos-latest | 11, 17, 21 | Every PR |
| build | ubuntu-latest | 17 | Every PR |
| conformance | ubuntu-latest | 17 | Every PR |
| publish (Maven Central) | ubuntu-latest | 17 | Tagged release |
