# Swift bridge parity runner

Long-lived executable that speaks the ADR-046 JSON-RPC parity protocol
over stdin/stdout, dispatching to the UniFFI Swift bindings.

Used by `test_bridge_parity.py` for the `uniffi-swift` bridge mode.

## Platform

**macOS only.** UniFFI Swift bindings ship as an `.xcframework` that
targets Apple platforms. The CI job for this runner pins
`runs-on: macos-latest`.

## Build

The Swift package depends on the in-tree `bindings/swift` package via a
relative path, so the xcframework must exist before `swift build`:

```sh
cd <repo-root>
bindings/swift/build-xcframework.sh --dev
cd bindings/python/tests/bridge_parity/helpers/swift_bridge_runner
swift build -c release
```

This produces `.build/release/swift-bridge-runner`.

## Smoke test

```sh
printf 'Content-Length: 83\r\n\r\n{"id":1,"op":"shutdown","bridgeMode":"uniffi-swift","args":{}}' | \
  .build/release/swift-bridge-runner
```

The runner writes a single `{"id":1,"ok":true,"result":{}}` frame and
exits 0.

## Wire protocol

See `../node_bridge_runner.ts` — all three runners use the identical
wire format and op dispatch table.
