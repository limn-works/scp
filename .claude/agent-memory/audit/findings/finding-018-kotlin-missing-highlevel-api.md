# Finding 018: Kotlin SDK missing high-level type-safe API classes

## Severity: moderate

## Summary

The Kotlin SDK README shows a high-level API with `Identity`, `Context`, and `Message` classes, but these classes don't exist in the codebase. Only low-level bridge classes with opaque `Long` handles exist (`IdentityBridge`, `ContextBridge`, etc.). Developers must manage handle lifecycle manually with no type safety between context and identity handles.

## Evidence

**README shows:**
```kotlin
val identity = Identity.create(custody = "platform")
val ctx = Context.create(identity = identity, params = {...})
ctx.send(payload)
```

**Actually exists:** Only `CoroutineBridge.identity` (returns `IdentityBridge`) and `CoroutineBridge.context` (returns `ContextBridge`), which operate on opaque `Long` handles.

**Comparison:** Python SDK has `Identity` class (with `.did`, `.custody_type` properties), `Context` class (with `.send()`, `.receive()` methods), and `Message` dataclass. TypeScript SDK has equivalent `Identity` and `Context` classes. Swift SDK has `Identity` functions and `Context` actor.

## Impact

Kotlin SDK users must:
- Manage opaque `Long` handles manually
- Call `bridge.context.send(handle, identityHandle, payload)` instead of `ctx.send(payload)`
- No type safety prevents passing a context handle where an identity handle is expected
- No fluent API or IDE discoverability

## Suggested Fix

Add high-level wrapper classes (`Identity`, `Context`, `Message`) matching the README API and the pattern established by Python/TypeScript/Swift SDKs.
