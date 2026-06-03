# UniFFI Swift checksum staleness (recurring CRITICAL)

When a Rust UniFFI method's signature changes (e.g. return type `()` -> `Result<(), ScpError>` makes a fn `throws`), the regenerated `bindings/swift/Sources/SCP/Internal/ScpBindings.swift` MUST carry the matching `uniffi_scp_ffi_uniffi_checksum_method_*` integer. A UniFFI checksum is computed over the FFI signature (name, arg types, return, throws) — NOT doc comments or bodies.

## The bug pattern
Hand-editing the throwing signature lines (e.g. `open func identityRemove(did: String)throws {...}`) correctly, but leaving STALE checksum constants from an intermediate regen. Swift's generated `initializationResult` runs `if checksum() != <constant> { return apiChecksumMismatch }`; `uniffiEnsureScpFfiUniffiInitialized()` then `fatalError("UniFFI API checksum mismatch...")`. Result: the ENTIRE Swift SDK crashes at first object init. Tests/clippy/tsc do NOT catch this — it only surfaces when Swift links against the real compiled dylib.

## Detection (definitive)
Generate fresh bindings and diff checksums:
```
cargo build -p scp-ffi-uniffi --release --features allow_in_memory_custody
cargo run -p scp-ffi-uniffi --bin uniffi-bindgen --release --features allow_in_memory_custody -- \
  generate --library target/release/libscp_ffi_uniffi.dylib --language swift --out-dir /tmp/gen
grep -o "checksum_method[a-z_]*() != [0-9]*" bindings/swift/Sources/SCP/Internal/ScpBindings.swift | sort > /tmp/c.txt
grep -o "checksum_method[a-z_]*() != [0-9]*" /tmp/gen/scp.swift | sort > /tmp/g.txt
diff /tmp/c.txt /tmp/g.txt   # any diff line = stale/incorrect committed checksum = CRITICAL
```
If only the changed methods differ and 100+ others match, it is NOT a tooling-version artifact — the committed checksums are simply wrong. Fix: re-run `bindings/swift/build-xcframework.sh` (clean regen) so the committed bindings come from final Rust state; never hand-edit checksum integers.

## Found
- commit 8bcd520c2 (#1543 Batch 4): identity_remove committed=10016 actual=20795; identity_remove_if_present committed=7918 actual=1563. event_log_checkpoint_by_did 25225 matched. All other ~125 checksums matched. CRITICAL — Swift SDK fatalError on init.

## RESOLVED
- commit a5b956a63 (#1543): canonical regen. Independently re-derived by building libscp_ffi_uniffi.dylib at HEAD (--features allow_in_memory_custody,testing) + uniffi-bindgen generate → checksums 20795 / 1563, byte-identical to committed guards (lines 15023/15026). Diff vs prior commit was EXACTLY the 2 checksum ints + 4 cosmetic `PyO3` backtick doc lines — no other drift. Verified clean. CRITICAL genuinely resolved.
