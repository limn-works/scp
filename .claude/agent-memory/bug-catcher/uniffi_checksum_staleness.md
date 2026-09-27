---
name: uniffi-checksum-staleness
description: A committed ScpBindings.swift whose UniFFI checksum constants do not match the Rust signatures makes the whole Swift SDK fatalError on first use; only a fresh regen and diff detects it
metadata:
  type: project
---

UniFFI computes each `uniffi_scp_ffi_uniffi_checksum_method_*` integer over the FFI signature
(name, argument types, return type, `throws`), not over doc comments or bodies. When a Rust
UniFFI method's signature changes, the committed
`bindings/swift/Sources/SCP/Internal/ScpBindings.swift` must carry the regenerated checksum.

**The failure:** someone hand-edits the Swift signature lines to match (for example, adds
`throws`) but leaves the checksum constants from an earlier generation. The generated
initializer compares each checksum and `uniffiEnsureScpFfiUniffiInitialized()` calls
`fatalError("UniFFI API checksum mismatch...")`, so the entire Swift SDK crashes at first
object creation. Clippy, Rust tests, and other SDKs' checks never see it; it surfaces only
when Swift links the real dylib. It happened once (`identity_remove`,
`identity_remove_if_present`) while about 125 other checksums matched.

**Detection:** generate fresh bindings and diff the checksum lines.
```
cargo build -p scp-ffi-uniffi --release
cargo run -p scp-ffi-uniffi --bin uniffi-bindgen --release -- \
  generate --library target/release/libscp_ffi_uniffi.dylib --language swift --out-dir /tmp/gen
grep -o "checksum_method[a-z_]*() != [0-9]*" bindings/swift/Sources/SCP/Internal/ScpBindings.swift | sort > /tmp/c.txt
grep -o "checksum_method[a-z_]*() != [0-9]*" /tmp/gen/*.swift | sed 's/^[^:]*://' | sort > /tmp/g.txt
diff /tmp/c.txt /tmp/g.txt
```
Any differing line is a stale committed checksum. When only the changed methods differ and
the rest match, it is not a tool-version artifact. Fix by regenerating with
`bindings/swift/build-xcframework.sh`; never hand-edit a checksum integer.
