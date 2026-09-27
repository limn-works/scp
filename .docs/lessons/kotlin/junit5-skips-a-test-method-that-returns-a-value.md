# JUnit 5 Silently Skips a Kotlin Test Method That Returns a Value

JUnit 5 runs only `@Test` methods that return `void`. A Kotlin expression body takes its
return type from its last expression, and `assertNotNull`, `assertIs`, `assertIsNot`, and
`requireNotNull` all return their argument, so this test compiles, reports nothing, and never
runs:

```kotlin
@Test
fun `mints an identity that already carries an agent key`() =
    runBlocking {
        val identity = scp.identityCreateWithAgentKey(custody = "in_memory")
        assertNotNull(identity.getAgentPublicKey())   // method now returns String
    }
```

`./gradlew test` printed `BUILD SUCCESSFUL`, the JUnit XML listed four testcases for a class
with five `@Test` methods, and the missing method appeared in no pass, fail, or skip list.
JUnit's discovery warning does not reach the Gradle console at the default log level.

## Rules

- Give every `@Test` method a block body (`fun name() { runBlocking { … } }`), which pins the
  return type to `Unit` whatever the last expression is.
- When a test is your evidence, read the JUnit XML report, not the exit code, and count its
  `<testcase>` elements against the file's `@Test` methods.
