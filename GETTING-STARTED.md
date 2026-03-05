# Getting Started with SCP

Clone, build, and see encrypted messages flow in under 15 minutes.

## Prerequisites

### Toolchain (mise)

SCP uses [mise](https://mise.jdx.dev/) to manage all toolchain versions. Install mise, then from the repo root:

```sh
mise install
eval "$(mise env)"
```

This provisions:

| Tool | Version |
|---|---|
| Rust | stable (2024 edition) |
| Python | 3.12 |
| bun | 1.3.9 |
| JDK | zulu-17 |
| Kotlin | 2.x |
| Gradle | 8.x |
| cargo-nextest | latest |
| wasm-pack | latest |
| maturin | latest |

Rust, Python, and cargo-nextest are required. The rest are only needed if you are working on specific SDK bindings (TypeScript, Swift/Kotlin, WASM).

### Platform

macOS (ARM or Intel) and Linux are supported. Windows is not tested.

## Clone and Build

```sh
git clone https://github.com/limn/scp.git
cd scp
```

Build the entire workspace (15 crates):

```sh
cargo build --workspace
```

First build compiles all dependencies and takes 2-5 minutes depending on hardware. Subsequent builds are incremental and fast. A clean build produces no warnings under the project's strict clippy configuration.

## Run Tests

Tests use `cargo nextest`, not `cargo test`. The FFI crates link against Python's shared library at runtime, so you must set the library path.

### macOS

```sh
export DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
cargo nextest run --workspace
```

### Linux

```sh
export LD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
cargo nextest run --workspace
```

To match CI exactly (includes extra feature flags):

```sh
cargo nextest run --workspace --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing
```

A successful run prints a summary like:

```
test result: XX tests run, XX passed, 0 failed, 0 skipped
```

All tests should pass. If any fail, check that `mise install` completed and `eval "$(mise env)"` was run in the current shell.

## Run the Relay Examples

The relay examples demonstrate SCP's transport layer: a relay server routes opaque encrypted blobs by routing ID. Three examples live in `crates/scp-transport/examples/`.

### Option A: Interactive Chat (single terminal)

Start a relay, then run the interactive chat client.

**Terminal 1 -- start the relay:**

```sh
cargo run -p scp-relay
```

You should see:

```
starting scp-relay
relay listening addr=0.0.0.0:9000
```

**Terminal 2 -- run the chat client:**

```sh
cargo run -p scp-transport --example relay-chat
```

The client connects to `ws://127.0.0.1:9000/scp/v1`, subscribes to a default routing ID, and presents a prompt. Type a message and press Enter. The message is wrapped in an `OuterEnvelope`, sent to the relay, routed back to your subscription, and printed as a received message.

```
Connecting to ws://127.0.0.1:9000/scp/v1...
Subscribing to routing_id aaaa...aa...
Ready. Type a message and press Enter. Ctrl-C to quit.

> hello from SCP
< hello from SCP
>
```

Press Ctrl-C to stop the client, then Ctrl-C the relay.

### Option B: Send and Listen (two terminals)

This demonstrates a producer/consumer pair using separate binaries. Both default to port 19000, so start the relay on that port.

**Terminal 1 -- start the relay on port 19000:**

```sh
SCP_RELAY_BIND_ADDR=0.0.0.0:19000 cargo run -p scp-relay
```

**Terminal 2 -- start the listener:**

```sh
cargo run -p scp-transport --example relay-listen
```

You should see:

```
Connecting to ws://127.0.0.1:19000/scp/v1...
Subscribing to routing_id aaaa...aa...
Listening. Press Ctrl-C to stop.
```

**Terminal 3 -- send messages:**

```sh
cargo run -p scp-transport --example relay-send
```

The sender transmits five demo messages. The listener prints each one as it arrives:

```
[RECV] routing_id=aaaa...aa ttl=60s payload="Hey, this is a real SCP envelope sent through the SDK." (54 bytes)
[RECV] routing_id=aaaa...aa ttl=60s payload="OuterEnvelope wraps the payload, relay routes by routing_id." (60 bytes)
[RECV] routing_id=aaaa...aa ttl=60s payload="The relay is a dumb pipe -- it sees only opaque blobs." (54 bytes)
[RECV] routing_id=aaaa...aa ttl=60s payload="In production this payload would be MLS-encrypted ciphertext." (61 bytes)
[RECV] routing_id=aaaa...aa ttl=60s payload="Ship it." (8 bytes)
```

You can also send a single custom message:

```sh
cargo run -p scp-transport --example relay-send -- ws://127.0.0.1:19000/scp/v1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "your message here"
```

### What just happened

The relay (`scp-relay`) is a store-and-forward WebSocket server. It knows nothing about message contents -- it routes opaque blobs by routing ID. In production, payloads are MLS-encrypted ciphertext. The relay never sees plaintext.

The examples use `NativeRelayAdapter` from `scp-transport` and `OuterEnvelope` from `scp-core` -- the same primitives the full SDK uses.

## Next Steps

- **Architecture guide** -- How the crates fit together, key concepts, reading order: [`docs/guides/architecture.md`](docs/guides/architecture.md)
- **Protocol specification** -- Full protocol spec (modular, one file per topic): [`.docs/specs/`](.docs/specs/)
- **SDK bindings** -- Python, TypeScript, Swift, Kotlin, WASM: [`bindings/`](bindings/)
- **Architecture Decision Records** -- Why things are the way they are: [`.docs/adrs/`](.docs/adrs/)
