# Isolate SwiftPM Cache Between Build Lanes

**Problem**: When running `swift test` for a Swift package alongside Xcode build lanes, sharing the module cache causes crashes like `'NSFileManager' has different definitions in different modules`.

**Rule**: Use an isolated SwiftPM scratch path for package build/test lanes:

```bash
swift test --package-path MyPackage --scratch-path .build/swiftpm-mypackage
```

Do not force `swift test` to reuse a shared module-cache path used by other lanes (`CLANG_MODULE_CACHE_PATH`, `SWIFTPM_MODULECACHE_OVERRIDE`).
