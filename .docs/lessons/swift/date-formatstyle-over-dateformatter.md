# Prefer Date.FormatStyle Over DateFormatter in Concurrent Contexts

**Problem**: `DateFormatter` is a mutable reference type (`NSObject` subclass) and is not thread-safe. Under concurrent request handling, multiple tasks formatting timestamps simultaneously can cause data races and intermittent crashes.

**Solution**: Use `Date.FormatStyle`, which is a value type and inherently safe for concurrent use:

```swift
// Bad: DateFormatter is not thread-safe
private static let formatter: DateFormatter = {
    let f = DateFormatter()
    f.dateFormat = "HH:mm:ss"
    return f
}()

// Good: Date.FormatStyle is a value type, safe for concurrent use
private static func timestamp() -> String {
    Date.now.formatted(
        .dateTime.hour(.twoDigits(amPM: .omitted))
        .minute(.twoDigits).second(.twoDigits)
    )
}
```

**Applies to**: Any formatting in server-side Swift, actors, or concurrent task groups. `NumberFormatter`, `MeasurementFormatter`, and other `NS`-prefixed formatters have the same thread-safety issue. Prefer their modern Swift equivalents (`FormatStyle` protocol family).
