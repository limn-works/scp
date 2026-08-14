# Kotlin bridge parity runner

Long-lived JVM process that speaks the ADR-046 JSON-RPC parity protocol
over stdin/stdout, dispatching to the UniFFI Kotlin bindings
(`uniffi.scp.*`).

Used by `test_bridge_parity.py` for the `uniffi-kotlin` bridge mode.

## Build

The runner is a standalone Gradle project that composite-builds against
`bindings/kotlin/scp-kt` via `includeBuild` in `settings.gradle.kts`.
UniFFI Kotlin bindings must already be generated:

```sh
cd <repo-root>
cargo build -p scp-ffi-uniffi --features testing
./scripts/generate-uniffi-kotlin.sh --skip-build --features=testing
```

Then build the runner's distribution. The runner does NOT ship its own
Gradle wrapper — it borrows the one under `bindings/kotlin/`:

```sh
cd bindings/python/tests/bridge_parity/helpers/kotlin_bridge_runner
../../../../../../bindings/kotlin/gradlew -p . installDist
```

This produces `build/install/kotlin-bridge-runner/bin/kotlin-bridge-runner`
which reads length-prefixed JSON-RPC frames on stdin.

## Smoke test

```sh
export LD_LIBRARY_PATH=<repo-root>/target/debug
printf 'Content-Length: 84\r\n\r\n{"id":1,"op":"shutdown","bridgeMode":"uniffi-kotlin","args":{}}' | \
  build/install/kotlin-bridge-runner/bin/kotlin-bridge-runner
```

The runner writes a single `{"id":1,"ok":true,"result":{}}` frame and
exits 0.

## Wire protocol

See `../node_bridge_runner.ts` — all three runners use the identical
wire format and op dispatch table.
