# os.Logger String Interpolation Requires `import os` at Call Site

**Problem**: Swift 6.2's `MemberImportVisibility` feature requires the defining module to be imported at every call site that uses its types. `os.Logger.error(_:)` takes an `OSLogMessage` parameter, which uses a custom `StringInterpolation` type from the `os` module. Without `import os`, the compiler cannot resolve `init(stringInterpolation:)` for the log message literal.

**Rule**: Any file that calls `Logger.error/warning/info/debug(...)` with string interpolation **must** have `import os` at the top. This applies even if no other `os` types are referenced directly.
