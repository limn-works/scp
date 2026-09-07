# JUnit 5 Silently Skips a Kotlin Test Method That Returns a Value

**Problem**: JUnit 5 executes only `@Test` methods that return `void`. Kotlin's expression-body
syntax makes a test return a value by accident, because the function's return type comes from the
last expression in the body. `kotlin.test.assertNotNull` returns its argument, so this test compiles,
reports no failure, and never runs:

```kotlin
@Test
fun `identityCreateWithAgentKey mints an identity that already carries an agent key`() =
    runBlocking {
        val identity = scp.identityCreateWithAgentKey(custody = "in_memory")
        assertTrue(identity.hasAgentKey())
        assertNotNull(identity.getAgentPublicKey())   // returns String -> method returns String
    }
```

`./gradlew test` printed `BUILD SUCCESSFUL`. The JUnit XML report listed four testcases for a class
holding five `@Test` methods, and the missing method appeared in neither the pass list, the failure
list, nor the skip list. JUnit's discovery warning does not reach the Gradle console at the default
log level, so nothing in the build output names the method that vanished.

Other assertion helpers carry the same hazard: `assertNotNull`, `assertIs`, `assertIsNot`, and
`requireNotNull` all return their argument.

**Correct pattern**: give every `@Test` method a block body, which pins its return type to `Unit`
whatever the last expression evaluates to:

```kotlin
@Test
fun `identityCreateWithAgentKey mints an identity that already carries an agent key`() {
    runBlocking {
        val identity = scp.identityCreateWithAgentKey(custody = "in_memory")
        assertTrue(identity.hasAgentKey())
        assertNotNull(identity.getAgentPublicKey())
    }
}
```

`fun name() = runBlocking<Unit> { ... }` fixes one method by pinning the type argument, and a block
body fixes the whole class by construction, so prefer the block body.

**Rule**: read the JUnit XML report, not the Gradle exit code, when you claim a test proves
something. Count the `<testcase>` elements against the `@Test` methods in the file. A green build
whose report holds fewer testcases than the class declares is a skipped test, not a passing one.

Applied in `bindings/kotlin/scp-kt/src/test/kotlin/works/limn/scp/IdentityAgentKeyRealFfiTest.kt`.
