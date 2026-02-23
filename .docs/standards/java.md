# Java Standards

Java conventions, toolchain, and CI for the SCP Java SDK. References `sdk-common.md` for cross-language invariants, `conventions.md` for git/branch conventions, and `.docs/scaffold/java.md` for the build blueprint (package layout, JNA bridge, build config, type definitions, publishing).

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Java | 21 LTS | Minimum target (records, sealed classes, pattern matching, virtual threads) |
| Gradle | 8.x (Kotlin DSL) | Build system |
| cbindgen + JNA | latest | C ABI bridge from Rust via Java Native Access |
| google-java-format | latest | Formatter |
| Checkstyle | latest | Linter (Google style) |
| SpotBugs | latest | Static analysis (bug patterns) |
| JUnit 5 | latest | Test framework |
| AssertJ | latest | Assertion library |

## Code Style

### Records for value types

**RULE:** Java 21 records for all immutable value types. Records provide `equals`, `hashCode`, `toString`, and component accessors automatically. Nullable fields are annotated in comments. See `.docs/scaffold/java.md` for the full record definitions (Message, ToolDefinition, TestVector).

### Sealed classes for error types

**RULE:** Use sealed classes for the error hierarchy. `ScpException` is the sealed base; each domain gets a `final` subclass. This lets `switch` expressions over error types be exhaustive. See `.docs/scaffold/java.md` for the full sealed exception hierarchy.

### CompletableFuture\<T\> for async

**PATTERN:** Java's `CompletableFuture<T>` for all async operations. Streaming uses `Flow.Publisher<T>` (Reactive Streams). Never block the calling thread inside async methods — delegate to `supplyAsync` / `runAsync`. See `.docs/scaffold/java.md` for Identity and Context class implementations.

### Resource management

**PATTERN:** `AutoCloseable` + `try-with-resources` for all native handles. Use `java.lang.ref.Cleaner` as a safety net for leaked handles (the cleanable captures only the `Pointer`, never `this`). See `.docs/scaffold/java.md` for the Cleaner-based handle wrapper.

```java
try (var identity = Identity.create("in_memory").join();
     var ctx = Context.create(identity, params).join()) {
    ctx.send(payload).join();
}
// Both identity and ctx are closed automatically
```

### Naming

- Types/classes/records: `PascalCase`
- Methods/fields: `camelCase`
- Constants: `SCREAMING_SNAKE_CASE`
- Packages: `lowercase` (`com.limn.scp`)
- Files: `PascalCase.java` (one public class per file)

## Testing

### JUnit 5 + AssertJ

```java
class IdentityTest {
    @Test
    void createReturnsIdentityWithValidDid() throws Exception {
        try (var identity = Identity.create("in_memory").join()) {
            assertThat(identity.did()).startsWith("did:dht:");
        }
    }

    @Test
    void sendThrowsWhenContextNotActive() {
        // ...
    }

    @ParameterizedTest
    @CsvSource({
        "messages:write, true",
        "context:close, false"
    })
    void validateCapabilityChecksCeiling(String capability, boolean shouldPass) {
        // ...
    }
}
```

### Test naming

Format: `actionConditionExpectedResult` in `camelCase`.

### Parameterized tests

Use JUnit 5 `@ParameterizedTest` with `@CsvSource`, `@MethodSource`, or `@JsonFileSource` for data-driven tests.

## Lint and Format Configuration

### google-java-format

Enforced via Spotless Gradle plugin. Format on build, check in CI.

### Checkstyle

`checkstyle.xml` based on Google Java Style Guide:

```xml
<?xml version="1.0"?>
<!DOCTYPE module PUBLIC
    "-//Checkstyle//DTD Checkstyle Configuration 1.3//EN"
    "https://checkstyle.org/dtds/configuration_1_3.dtd">
<module name="Checker">
    <module name="TreeWalker">
        <module name="CyclomaticComplexity">
            <property name="max" value="25"/>
        </module>
        <module name="MethodLength">
            <property name="max" value="60"/>
        </module>
    </module>
</module>
```

### SpotBugs

Runs at MAX effort, MEDIUM confidence. All findings are build failures.

## CI Commands

```bash
# Format check
./gradlew spotlessCheck

# Lint (Checkstyle)
./gradlew checkstyleMain checkstyleTest

# Static analysis (SpotBugs)
./gradlew spotbugsMain

# Build
./gradlew build

# Test
./gradlew test
```

## CI Matrix

| Job | Runs on | JDK | Trigger |
|-----|---------|-----|---------|
| spotless | ubuntu-latest | 21 | Every PR |
| checkstyle | ubuntu-latest | 21 | Every PR |
| spotbugs | ubuntu-latest | 21 | Every PR |
| dependency-check | ubuntu-latest | 21 | Every PR |
| test | ubuntu-latest, macos-latest | 21 | Every PR |
| build | ubuntu-latest | 21 | Every PR |
| conformance | ubuntu-latest | 21 | Every PR |
| publish (Maven Central) | ubuntu-latest | 21 | Tagged release |
