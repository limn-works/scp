# Private Types in Generic Default Parameters Cause SIL Verifier Crash

**Problem**: Using a `private struct` as a default parameter value in a generic method signature causes the Swift compiler's SIL verifier to crash. The private type's metadata symbol leaks across compilation units when files are batch-compiled together.

```
Global is external, but doesn't have external or weak linkage!
```

**Fix**: Replace `private` sentinel types in generic defaults with method overloading:

```swift
// WRONG: private type leaks through generic default
private struct Empty: Encodable, Sendable {}
func post<T>(path: String, body: (some Encodable)? = nil as Empty?) async throws -> T

// RIGHT: separate overload for bodyless calls
func post<T>(path: String, body: some Encodable) async throws -> T
func post<T>(path: String) async throws -> T  // no body
```

**Applies to**: Any `private` or `fileprivate` type used as a default value in a generic method parameter that is visible from other files.
