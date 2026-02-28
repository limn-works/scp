# Kotlin/Android Tests Must Call the Production Class, Not a Copy

**Problem**: `AndroidPushProviderTest` contains a private `handleNotification()` function that
duplicates the production validation logic from `AndroidPushProvider.handleNotification()` inline.
All 12 tests pass, but they test the copy, not the class. A regression introduced only in
`AndroidPushProvider.kt` leaves the test suite green.

This is particularly dangerous in security-critical validation paths. `handleNotification` enforces
§10.7 FCM payload opacity — if its validation is broken, opaque payloads containing context IDs
or sender DIDs could be accepted silently.

**Correct pattern**: Call the actual class under test. When the class requires an Android
`Context` that is only used in I/O paths not exercised by the test, use a null-cast:

```kotlin
private fun provider(): AndroidPushProvider =
    AndroidPushProvider((null as Any?) as android.content.Context)

@Test
fun `valid scp payload returns WakeSignal Pull`() {
    val signal = provider().handleNotification(mapOf("scp" to "1"))
    assertEquals(WakeSignal.PULL, signal)
}
```

This pattern is already established in `AndroidDeviceAttestationTest.createAttestationWithMockContext()`.
Apply it consistently across all Android platform adapter unit tests.

**Rule**: If a test file contains a function that mirrors production logic without calling it,
the test is testing the wrong thing. Search for helper functions in test files that duplicate
production code and replace them.
