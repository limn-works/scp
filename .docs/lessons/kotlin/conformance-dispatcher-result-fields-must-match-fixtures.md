# Conformance Dispatcher Result Fields Must Match Shared Fixture `expected` Keys

**Discovered:** SCP-120 review
**Category:** Testing correctness, cross-platform conformance

## What Happened

`ConformanceDispatcher.dispatchIdentityCreate` returns `{"handle", "custody_type"}` but the shared conformance fixture format defined in `.docs/scaffold/shared.md` expects `"did_prefix": "did:dht:"` in the `expected` block:

```json
{
  "test_id": "identity-create-001",
  "operation": "identity_create",
  "expected": {
    "did_prefix": "did:dht:",
    "custody_type": "in_memory"
  }
}
```

`compareResults` iterates `expected` keys and checks each against the `actual` map. A key absent from `actual` produces a mismatch. The `did_prefix` field is never returned by the dispatcher, so every `identity_create` fixture in `tests/conformance/` will fail.

## Why It Was Silent

`ConformanceFixtureLoader.loadFixtures()` returns `emptyList()` when `tests/conformance/` does not exist. Infrastructure tests (fixture model, comparison logic, dispatcher dispatch) all pass — but no real fixtures execute. The omission is invisible until the shared fixture directory is populated.

## The Rule

Every key in any shared fixture's `expected` block must be present in the map returned by the corresponding dispatcher method. Before writing a dispatcher method:

1. Read the shared fixture format in `.docs/scaffold/shared.md`.
2. Identify all `expected` fields for that operation's category.
3. Ensure the returned map includes all of them.

Return extra keys freely — `compareResults` ignores keys in `actual` that are not in `expected`. Never omit a key that appears in `expected`.

## Fix Pattern

```kotlin
private suspend fun dispatchIdentityCreate(
    input: Map<String, String>,
): Map<String, String> = catchBridge {
    val custody = input["custody"] ?: "in_memory"
    val handle = bridge.identity.create(custody)
    mapOf(
        "handle" to handle.toString(),
        "custody_type" to custody,
        "did_prefix" to "did:dht:",  // required by shared fixture format
    )
}
```
