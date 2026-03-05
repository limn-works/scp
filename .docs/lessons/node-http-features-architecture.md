# Node HTTP Features Architecture (SCP-242 through SCP-249)

Patterns and decisions from the scp-node HTTP features implementation: local dev API and broadcast projection. Source: ADR-035 (`.docs/adrs/phase-2.md`), spec sections 18.10 and 18.11.

## NodeState Generic Over BlobStorage

`NodeState<B: BlobStorage>` uses a static generic parameter, not a trait object (`Arc<dyn BlobStorage>`). While the trait now uses `#[async_trait]` (which boxes futures, enabling dyn-compatibility), the generic approach is retained for zero-cost dispatch via `BlobStorageBackend` enum. The generic propagates through all handler functions: `health_handler::<B>`, `feed_handler::<B>`, etc.

When composing axum routers from generic handlers, the type parameter must be threaded through every route registration: `get(handler::<B>)`. This is mechanical but must be consistent -- missing a turbofish causes a type inference failure.

The `Arc<B>` instance lives on `NodeState` and is shared between `RelayServer` and `NodeState` via `Arc::clone`. This required changing `RelayServer::new` from taking owned `B` to `Arc<B>`.

## Two-Listener Separation

The dev API runs on a **separate localhost listener** (its own tokio task and `TcpListener`), not the public HTTPS port. Rationale: reverse proxy misconfiguration. A proxy forwarding `*` to the public port is common; sharing the port would expose the dev API through that proxy.

The dev listener is spawned as a detached `tokio::spawn` in `serve()`. It logs at INFO on bind but has no structured shutdown -- it terminates when the runtime drops. Known issue #224 notes that `serve()` currently double-binds (once for relay startup, once for the axum listener).

## Bearer Token Auth

Token format: `scp_local_token_<32 hex chars>` (16 random bytes from `OsRng`, hex-encoded). The `subtle` crate's `ConstantTimeEq` prevents timing side-channels on comparison. The middleware is axum `from_fn` middleware that clones the expected token into each invocation.

The token is never logged in full -- only the first 8 hex chars of the random portion are logged at INFO. Access the full token via `node.dev_token()`.

## Broadcast Projection Decryption Pipeline

1. HTTP request arrives at `/scp/broadcast/<routing_id_hex>/feed` or `.../messages/<blob_id_hex>`
2. `routing_id` parsed from hex, looked up in `projected_contexts` (RwLock<HashMap>)
3. Keys snapshot cloned from `ProjectedContext.keys` (releases the read lock before async I/O)
4. `BlobStorage::query()` or `::get()` fetches raw blobs
5. Each blob deserialized as `BroadcastEnvelope` (MessagePack via `rmp_serde`)
6. Epoch-matched `BroadcastKey` found in the keys map
7. `open_broadcast(key, &envelope)` performs AES-256-GCM decryption
8. Plaintext base64-encoded for JSON transport

Failed blobs are logged at `warn` and **skipped** (not a 500) on the feed endpoint. The per-message endpoint returns 500 on decryption failure since there's only one blob and skipping it means no response.

## Caching Strategy

**Feed endpoint** (`/feed`): `Cache-Control: public, max-age=30, stale-while-revalidate=300`. Short TTL because new messages appear frequently. ETag is the latest blob_id in the response.

**Per-message endpoint** (`/messages/<blob_id>`): `Cache-Control: public, immutable, max-age=31536000`. One-year immutable cache because broadcast messages are content-addressed and never change. ETag is the blob_id itself. Conditional GET via `If-None-Match` returns 304.

This is CDN-friendly by design -- the per-message endpoint is the workhorse for caching.

## Input Validation on Dev API

Context creation (`POST /scp/dev/v1/contexts`) validates:
- `id`: non-empty, ASCII hex only (`b.is_ascii_hexdigit()`), max 128 chars
- `name`: max 256 chars, no control characters
- Duplicate context IDs rejected with 409 Conflict

The hex-only constraint on context IDs prevents injection and ensures consistency with the rest of the protocol where context IDs are hex-encoded.

## Localhost Enforcement

`ApplicationNodeBuilder::local_api(addr)` panics at call time if `addr` is not loopback (`127.0.0.1` or `::1`). This is a compile-time-adjacent enforcement -- the panic is in the builder, not at runtime during `serve()`. The rationale: exposing the dev API on a non-loopback interface is always a security mistake, and a panic during setup is clearer than a runtime error.

## Known Pre-Existing Issues

- **#224**: `serve()` double-bind -- the relay binds first during `build()`, then `serve()` binds a second listener for axum on the same address.
- **#225**: Bridge secret transmitted as a query parameter in the internal WebSocket URL (`ws://localhost/?token=<hex>`). Acceptable for localhost-only, but query params may be logged by intermediaries.
