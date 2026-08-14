//! SSE (Server-Sent Events) transport for the MCP server.
//!
//! Implements the MCP SSE transport mode: an HTTP server that serves an SSE
//! endpoint for server-to-client messages and a POST endpoint for
//! client-to-server JSON-RPC requests. This transport is suitable for remote
//! and web-based MCP integrations.
//!
//! ## Endpoints
//!
//! - `GET /sse` -- SSE stream for server-to-client messages (responses,
//!   notifications). The server sends an initial `endpoint` event with the
//!   POST URL, then streams `message` events containing JSON-RPC responses.
//!   Each event carries a sequential `id:` field for wire framing and
//!   diagnostics only — it does not support resume (see below).
//! - `POST /message` -- Accepts JSON-RPC requests from the client. Responses
//!   are delivered via the SSE stream, not in the HTTP response body.
//!
//! ## Reconnection
//!
//! Reconnection is a full resync, not a resume. Every admission resets the
//! MCP session (see [`AppState::session_slot`] and [`sse_handler`]), so a
//! reconnecting client re-initializes, re-subscribes, and re-reads state;
//! any event broadcast before that reset belongs to the prior logical
//! session. Cross-session replay is therefore deliberately absent: the
//! standard SSE `Last-Event-ID` header is ignored — honoring it would stream
//! a previous session's decrypted JSON-RPC responses (member lists, tool
//! outputs, resource reads) to whichever client connects next. The server
//! emits a `retry:` field so clients respect a server-controlled
//! reconnection interval, and a client that falls behind the broadcast
//! channel has its stream terminated so it reconnects into a clean session
//! rather than silently missing events.
//!
//! ## Keep-alive
//!
//! The SSE stream sends periodic comment-only keep-alive frames (`: keepalive`)
//! to prevent intermediate proxies from closing idle connections.
//!
//! ## Shutdown
//!
//! [`run_sse`] accepts a [`ShutdownHandle`] that signals the server to stop
//! accepting new connections. Existing SSE streams drain naturally.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_util::sync::CancellationToken;

use scp_core::context::membership::ContextEventEnvelope;

use crate::protocol::{
    JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PARSE_ERROR, RequestId,
};
use crate::server::{ContextEventPump, ContextProvider, McpServer, McpServerForTransport};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default retry interval (milliseconds) sent to SSE clients.
const DEFAULT_RETRY_MS: u64 = 3000;

/// Configuration for the SSE transport server.
#[derive(Debug, Clone)]
pub struct SseConfig {
    /// The address to bind the HTTP server to (e.g., `127.0.0.1:3000`).
    pub bind_addr: SocketAddr,

    /// Capacity of the broadcast channel for SSE messages.
    /// Defaults to 256.
    pub channel_capacity: usize,

    /// Retry interval in milliseconds sent to clients via the `retry:` field.
    /// Clients should wait this long before reconnecting after a dropped
    /// connection. Defaults to 3000 (3 seconds).
    pub retry_ms: u64,

    /// Optional bearer token for authenticating SSE and message requests.
    /// When `Some(token)`, all requests to `/sse` and `/message` must include
    /// an `Authorization: Bearer <token>` header. Unauthenticated requests
    /// receive HTTP 401 Unauthorized. When `None`, no authentication is
    /// required (backwards compatible).
    pub auth_token: Option<String>,
}

impl SseConfig {
    /// Creates a new configuration with the given bind address.
    #[must_use]
    pub const fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            channel_capacity: 256,
            retry_ms: DEFAULT_RETRY_MS,
            auth_token: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the SSE transport.
#[derive(Debug, thiserror::Error)]
pub enum SseError {
    /// An I/O error occurred starting or running the HTTP server.
    #[error("SSE server error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Shutdown handle
// ---------------------------------------------------------------------------

/// Handle for gracefully shutting down a running SSE server.
///
/// Dropping the handle does **not** shut down the server. Call
/// [`shutdown`](Self::shutdown) explicitly. Existing SSE streams drain
/// naturally after shutdown is signaled.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    token: CancellationToken,
}

impl ShutdownHandle {
    /// Creates a new shutdown handle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    /// Signals the SSE server to stop accepting new connections.
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// Returns `true` if shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.token.is_cancelled()
    }
}

impl Default for ShutdownHandle {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// The server→client push fabric for an SSE session.
///
/// Notifications share the SSE event-ID sequence with request responses. The
/// ids exist for wire framing and diagnostics only: reconnection is a full
/// resync into a freshly reset session (see the module docs), so there is no
/// replay machinery and no resume path for the ids to serve.
#[derive(Clone)]
pub(crate) struct McpNotifier {
    /// Broadcast sender for SSE messages to connected clients.
    tx: broadcast::Sender<(u64, String)>,
    /// Monotonically increasing event ID counter.
    ///
    /// `fetch_add` makes every assigned id unique, which is all the two
    /// consumers — SSE `id:` framing and synthetic request ids for incoming
    /// notifications — require. Two concurrent broadcasts may publish out of
    /// id order; nothing observes or depends on wire-order ids because
    /// resume does not exist.
    next_event_id: Arc<AtomicU64>,
}

impl McpNotifier {
    /// Creates the push fabric for an SSE server built from `config`.
    fn new(config: &SseConfig) -> Self {
        let (tx, _rx) = broadcast::channel(config.channel_capacity);
        Self {
            tx,
            next_event_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Broadcasts a JSON payload to all connected SSE clients. Returns the
    /// assigned event ID.
    fn broadcast(&self, data: String) -> u64 {
        let id = self.next_event_id.fetch_add(1, Ordering::SeqCst);
        let _ = self.tx.send((id, data));
        id
    }

    /// Sends a JSON-RPC notification to all connected SSE clients.
    ///
    /// Returns the number of connected clients the notification was
    /// broadcast to, or 0 if serialization fails or nobody is connected.
    /// A return of 0 with nobody connected is not an error: the transport is
    /// single-session and every admission resets the session, so a later
    /// client starts from a fresh handshake and re-reads current state
    /// rather than depending on notifications sent before it attached.
    fn notify(&self, notification: &JsonRpcNotification) -> usize {
        match serde_json::to_string(notification) {
            Ok(json) => {
                self.broadcast(json);
                self.tx.receiver_count()
            }
            Err(e) => {
                tracing::error!("failed to serialize MCP notification: {e}");
                0
            }
        }
    }

    /// Reserves the next event ID in the shared sequence.
    fn next_id(&self) -> u64 {
        self.next_event_id.fetch_add(1, Ordering::SeqCst)
    }
}

/// Shared state between the SSE endpoint and the POST endpoint.
pub(crate) struct AppState<P: ContextProvider> {
    /// The MCP server, protected by a mutex for concurrent access.
    server: Mutex<McpServer<P>>,
    /// The server→client push fabric, shared with any external event pump.
    notifier: McpNotifier,
    /// Retry interval in milliseconds sent to SSE clients.
    retry_ms: u64,
    /// Admits exactly one live SSE session at a time.
    ///
    /// An [`McpServer`] *is* one MCP session: it holds one `initialized` flag,
    /// one set of negotiated client capabilities, and one resource-subscription
    /// registry. Serving two concurrent clients from it would silently share
    /// all three — client B would inherit A's handshake, receive A's JSON-RPC
    /// responses off the shared broadcast, see updates for A's subscriptions,
    /// and cancel them with its own `resources/unsubscribe`.
    ///
    /// Rather than pretend to multiplex, the endpoint is structurally
    /// single-session: the second concurrent `GET /sse` is refused with
    /// `409 Conflict`. When the first client's stream is dropped, the session
    /// state is reset and only *then* is the permit released (the reset task
    /// carries the permit — see [`SessionGuard`]), so the next client is never
    /// admitted while a stale reset is still pending.
    session_slot: Arc<tokio::sync::Semaphore>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Builds the router and, when an event source is supplied, the pump task
/// driving it.
///
/// The caller owns the returned [`tokio::task::JoinHandle`] so the pump can be
/// stopped when the server stops. Without that, the pump would outlive the
/// server it feeds and keep the whole [`AppState`] alive until the runtime's
/// broadcast sender is dropped.
///
/// This is deliberately crate-private: every caller must own that handle, and a
/// public wrapper that discarded it (as the former `sse_router` did) would leak
/// the pump by construction. [`run_sse`] is the supported entry point.
fn router_with_pump<P: ContextProvider + 'static>(
    server: McpServer<P>,
    config: &SseConfig,
    pump: Option<ContextEventPump>,
) -> (Router, Option<tokio::task::JoinHandle<()>>) {
    let state = Arc::new(AppState {
        server: Mutex::new(server),
        notifier: McpNotifier::new(config),
        retry_ms: config.retry_ms,
        session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
    });

    let pump = pump.map(|pump| tokio::spawn(pump_events(Arc::clone(&state), pump.into_receiver())));

    let router = Router::new()
        .route("/sse", get(sse_handler::<P>))
        .route("/message", post(message_handler::<P>))
        .with_state(state);

    let router = if let Some(ref token) = config.auth_token {
        let expected = token.clone();
        router.layer(middleware::from_fn(move |req, next| {
            bearer_auth_middleware(req, next, expected.clone())
        }))
    } else {
        router
    };

    (router, pump)
}

/// Middleware that validates bearer token authentication.
///
/// Checks the `Authorization: Bearer <token>` header on incoming requests.
/// Returns HTTP 401 Unauthorized if the header is missing, malformed, or
/// contains the wrong token.
async fn bearer_auth_middleware(
    req: Request<Body>,
    next: Next,
    expected_token: String,
) -> impl IntoResponse {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(value) if value.len() > 7 && value[..7].eq_ignore_ascii_case("bearer ") => {
            let provided = &value[7..];
            if bool::from(provided.as_bytes().ct_eq(expected_token.as_bytes())) {
                next.run(req).await.into_response()
            } else {
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

/// Runs the MCP server as an SSE HTTP server.
///
/// Binds to the configured address and serves until the [`ShutdownHandle`] is
/// triggered or the process is terminated.
///
/// # Resource subscriptions
///
/// `server` is the single [`McpServerForTransport`] bundle
/// [`McpServer::with_optional_event_source`](crate::server::McpServer::with_optional_event_source)
/// produces: a wired server *and* its [`ContextEventPump`] as one value, or an
/// unwired server alone. A wired server advertises `resources.subscribe: true`;
/// its pump turns each [`ContextEvent`] into `notifications/resources/updated`
/// for the subscribed resources it invalidates. An unwired server
/// ([`McpServer::new`](crate::server::McpServer::new)) advertises
/// `resources.subscribe: false`, rejects `resources/subscribe`, and has no pump.
///
/// The server's advertisement and its pump are one value, consumed atomically —
/// a wired server cannot be transported without its pump, so there is no runtime
/// pairing check to perform: the mismatch is unconstructable by type.
///
/// # Sessions
///
/// The endpoint serves one MCP session at a time; a second concurrent
/// `GET /sse` is refused with `409 Conflict`. See [`AppState::session_slot`].
///
/// # Errors
///
/// Returns [`SseError::Io`] if the server cannot bind or encounters an I/O
/// error.
pub async fn run_sse<P: ContextProvider + 'static>(
    server: McpServerForTransport<P>,
    config: SseConfig,
    shutdown: ShutdownHandle,
) -> Result<(), SseError> {
    // `Some(pump)` exactly when the server is wired — the bundle guarantees it,
    // so no pairing check is needed here.
    let (server, pump) = server.into_parts();

    let (router, pump) = router_with_pump(server, &config, pump);
    // Hold the pump under a guard that aborts it on EVERY exit from this future:
    // a bind error, graceful shutdown, *and* the cancellation-drop when a bridge
    // aborts the task running `run_sse`. A bare `JoinHandle` dropped without
    // `abort()` only detaches the task, which — holding an `Arc<AppState>` —
    // would outlive the server and pin the whole session alive.
    let _pump_guard = pump.map(crate::stdio::AbortOnDrop);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!("MCP SSE server listening on {}", config.bind_addr);

    let token = shutdown.token.clone();
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            token.cancelled().await;
            tracing::info!("MCP SSE server shutting down");
        })
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// SSE endpoint handler. Streams server-to-client messages.
///
/// Sends an initial `endpoint` event containing the POST URL for the client
/// to use, then streams live `message` events with JSON-RPC responses.
///
/// Each `message` event carries a sequential `id:` field (framing and
/// diagnostics only) and the stream includes a `retry:` directive so clients
/// use a server-controlled reconnection interval. The standard SSE
/// `Last-Event-ID` request header is deliberately ignored: admission resets
/// the session, so anything a resume could replay predates the reset and
/// belongs to the prior logical session — honoring the header would hand one
/// client's buffered decrypted responses to the next (see the module docs).
async fn sse_handler<P: ContextProvider + 'static>(
    State(state): State<Arc<AppState<P>>>,
) -> axum::response::Response {
    // One session at a time. Without this the second client would inherit the
    // first client's completed handshake and resource subscriptions, and would
    // receive the first client's JSON-RPC responses off the shared broadcast.
    //
    // Admission note: any process that can reach the bind address can claim
    // (or contend for) this single slot — with `SseConfig::auth_token` unset
    // there is no authentication in front of it. An unauthenticated local
    // process can therefore deny the legitimate client outright by looping
    // connect->disconnect to seize the slot on each release (or simply by
    // holding it): a single-session availability denial. That is the accepted
    // cost of the deliberate single-session design — the attacker gains denial,
    // never another session's decrypted content. Hardened deployments set
    // `auth_token`, which the bearer middleware enforces before a request can
    // touch the slot.
    let Ok(permit) = Arc::clone(&state.session_slot).try_acquire_owned() else {
        tracing::warn!("MCP SSE: refusing a second concurrent session");
        return (
            StatusCode::CONFLICT,
            "an MCP session is already active on this endpoint",
        )
            .into_response();
    };

    // Every session begins from a clean slate by sequencing, not scheduling
    // luck. The previous guard's `Drop` can only *spawn* its reset (`Drop` is
    // synchronous), and although that spawned task holds the session permit
    // until the reset completes (see `SessionGuard`), resetting here makes
    // admission itself the guarantee: a freshly admitted client can never
    // inherit another session's handshake or subscriptions, nor lose its own
    // to a stale reset that was scheduled but had not yet run.
    state.server.lock().await.reset_session();

    let endpoint_event = Event::default()
        .event("endpoint")
        .data("/message")
        .retry(Duration::from_millis(state.retry_ms));

    let rx = state.notifier.tx.subscribe();

    // A client that falls behind the broadcast channel has lost events that
    // nothing can reconstruct. Rather than skipping the gap silently — a
    // client believing it is current while it is not — END the stream. The
    // client observes the disconnect, reconnects (honoring `retry:`), is
    // admitted into a clean session (admission resets session state, above),
    // re-initializes, re-subscribes, and re-reads capability-filtered state:
    // a full resync by construction. "Never fall silent" is satisfied by an
    // explicit signal instead of replay.
    let message_stream = BroadcastStream::new(rx).map_while(|result| match result {
        Ok((id, data)) => Some(Ok::<_, Infallible>(
            Event::default()
                .event("message")
                .id(id.to_string())
                .data(data),
        )),
        Err(BroadcastStreamRecvError::Lagged(skipped)) => {
            // Deliberate tradeoff: a context co-member flooding events past
            // `channel_capacity` can push this receiver into `Lagged`, forcing
            // the victim's stream to terminate and reconnect-resync. That cost
            // is bounded by the client's `retry_ms` reconnect interval,
            // self-healing (the client re-reads current state on readmission),
            // and non-escalating (no amplification, no accumulated state) — the
            // correct "never fall silent" choice over the deleted silent-drop,
            // which left the victim believing it was current while it had in
            // fact missed events.
            tracing::warn!(
                skipped,
                "MCP SSE client lagged; terminating its stream to force a clean-session resync"
            );
            None
        }
    });

    let initial = tokio_stream::once(Ok(endpoint_event));
    let stream = initial.chain(message_stream);

    // Hold a session guard for the lifetime of the stream. When the client
    // disconnects the stream is dropped, dropping the guard, which resets the
    // session (handshake state + resource subscriptions) and frees the session
    // slot — the next client must re-handshake and re-subscribe rather than
    // inherit the previous session's registry.
    let guard = SessionGuard {
        state: Arc::clone(&state),
        permit: Some(permit),
    };
    let stream = stream.map(move |event| {
        let _keep_alive = &guard;
        event
    });

    Sse::new(stream)
        .keep_alive(
            KeepAlive::default()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response()
}

/// POST endpoint handler. Receives JSON-RPC requests from the client.
///
/// Dispatches the request to the MCP server and sends the response via the
/// SSE broadcast channel. Returns `202 Accepted` to the HTTP client since
/// the actual response is delivered via SSE.
///
/// Requires a live session (`GET /sse`): the response goes out on the SSE
/// broadcast, so accepting a request with no session attached would drop the
/// response unheard.
///
/// The response is computed *and* broadcast inside one `state.server` critical
/// section. That lock is the one `sse_handler`'s `reset_session` and the next
/// admission also take, so broadcasting under it orders the send strictly
/// before any session reset or next-client subscribe — precisely to prevent
/// cross-principal delivery. Were the broadcast performed after releasing the
/// lock, an in-flight response computed for the current principal could be sent
/// after the next client has been admitted and subscribed during a
/// disconnect->reset->readmit window, delivering this principal's decrypted
/// result (member lists, tool outputs, resource reads) to a *different*, later
/// client.
async fn message_handler<P: ContextProvider + 'static>(
    State(state): State<Arc<AppState<P>>>,
    body: String,
) -> impl IntoResponse {
    // The permit is held by `SessionGuard` for the lifetime of the SSE stream,
    // so a full slot means no client is attached.
    if state.session_slot.available_permits() > 0 {
        return StatusCode::CONFLICT;
    }

    let trimmed = body.trim();
    if trimmed.is_empty() {
        return StatusCode::BAD_REQUEST;
    }

    // Every response is computed AND broadcast inside a single `state.server`
    // critical section. That lock is the one `sse_handler`'s `reset_session`
    // and the next admission also take, so a send ordered under it lands before
    // any reset/readmit — or not at all, dropped when no receiver exists yet.
    // Broadcasting after releasing the lock, "for throughput", reopens the
    // cross-principal window: an in-flight response computed for the current
    // principal could otherwise be sent after the next client has been admitted
    // and subscribed, delivering this principal's decrypted result to a
    // different, later client. `broadcast` is synchronous, so holding the tokio
    // mutex across it crosses no `.await`.
    match parse_sse_incoming(trimmed) {
        Ok(SseIncoming::Request(req)) => {
            let mut server = state.server.lock().await;
            if let Some(resp) = server.handle_request(&req)
                && let Ok(json) = serde_json::to_string(&resp)
            {
                state.notifier.broadcast(json);
            }
        }
        Ok(SseIncoming::Notification(notif)) => {
            let synthetic_id = state.notifier.next_id();
            let synthetic = JsonRpcRequest {
                jsonrpc: notif.jsonrpc,
                method: notif.method,
                params: notif.params,
                id: RequestId::Number(synthetic_id.cast_signed()),
            };
            // Notifications produce no response; nothing to broadcast.
            let mut server = state.server.lock().await;
            server.handle_request(&synthetic);
        }
        Err(err_response) => {
            // A parse error echoes only the caller's own malformed input, but
            // it is still a server->client message on the shared broadcast.
            // Order it under the server lock like every other response so the
            // discipline is uniform: message_handler never broadcasts outside
            // the lock that reset_session and the next admission serialize on.
            let _server = state.server.lock().await;
            if let Ok(json) = serde_json::to_string(&err_response) {
                state.notifier.broadcast(json);
            }
        }
    }

    StatusCode::ACCEPTED
}

// ---------------------------------------------------------------------------
// Event pump
// ---------------------------------------------------------------------------

/// Forwards runtime context events to connected clients as MCP notifications.
async fn pump_events<P: ContextProvider + 'static>(
    state: Arc<AppState<P>>,
    mut events: broadcast::Receiver<ContextEventEnvelope>,
) {
    loop {
        let ContextEventEnvelope { context_id, event } = match events.recv().await {
            Ok(v) => v,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                // The dropped events are gone; nothing can reconstruct which
                // resources they touched. Over-notify — one
                // resources/list_changed plus one tools/list_changed (the
                // capability-filtered tool list may also have shifted) plus one
                // resources/updated per still-authorized subscription — so a
                // lagged client re-reads, exactly as the pump promises. Never
                // fall silent.
                tracing::warn!("MCP SSE event pump lagged, {skipped} events dropped");
                // Compute AND broadcast the resync under the server lock, for
                // the same cross-principal ordering reason as `message_handler`:
                // a resync filtered to the current session's subscriptions must
                // not be pushed to a later, different admission. The lock is the
                // one reset_session and the next admission serialize on; `notify`
                // is synchronous, so holding it across the broadcast crosses no
                // `.await`.
                let server = state.server.lock().await;
                for notification in &server.lagged_resync_notifications() {
                    state.notifier.notify(notification);
                }
                // Release only after every resync notification is broadcast —
                // the whole loop above runs under the lock, on purpose.
                drop(server);
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => return,
        };

        // Contention trade-off, kept deliberately: the session mutex is held
        // across BOTH the provider re-authorization calls
        // (`validate_resource_access`, `active_context_ids`), which on the
        // UniFFI bridge are `block_in_place` actor round-trips, AND the
        // broadcast — so a burst of events briefly serializes POST handlers
        // behind the pump. Holding the lock across the broadcast is required,
        // not incidental: releasing it before emitting would (a) let
        // authorization run against a *snapshot* of the subscription registry
        // that a concurrent unsubscribe / session reset has already retired —
        // the stale-delivery class this transport exists to kill — and (b)
        // reopen the cross-principal window `message_handler` closes, where a
        // notification filtered for the current session is delivered to a later
        // admission. Correctness over throughput; the same reasoning covers the
        // lagged-resync arm above. `notify` is synchronous, so no `.await` is
        // crossed while the lock is held.
        let server = state.server.lock().await;
        for notification in &server.notifications_for_event(&context_id, &event) {
            state.notifier.notify(notification);
        }
    }
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

/// Resets the MCP session when the SSE client disconnects.
///
/// Held alive by the SSE response stream; dropped when the client goes away.
/// Dropping it schedules the session reset (handshake state + resource
/// subscriptions) and moves the single-session permit into that reset task, so
/// the slot is released only *after* `reset_session()` completes — the next
/// client cannot be admitted while the reset is still pending, and therefore
/// cannot have its own freshly registered state wiped by it.
struct SessionGuard<P: ContextProvider + 'static> {
    state: Arc<AppState<P>>,
    /// The single-session permit. Moved into the spawned reset task on drop —
    /// released only after `reset_session()` has run. `Option` solely so
    /// `Drop` (which gets `&mut self`) can move it out; it is `Some` for the
    /// guard's entire lifetime.
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl<P: ContextProvider + 'static> Drop for SessionGuard<P> {
    fn drop(&mut self) {
        let permit = self.permit.take();
        // `Drop` is synchronous and the reset needs the async server mutex, so
        // hand the work — carrying the permit — to the runtime: the session
        // slot frees only once the reset has completed. Outside a runtime
        // (e.g. a test that drops the stream after the runtime ends) there is
        // no task to run; releasing the permit here is still correct because
        // admission itself resets the session first (see `sse_handler`), so a
        // later client can never inherit this session's state.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            drop(permit);
            return;
        };
        let state = Arc::clone(&self.state);
        handle.spawn(async move {
            state.server.lock().await.reset_session();
            drop(permit);
        });
    }
}

// ---------------------------------------------------------------------------
// Incoming message parsing (same logic as stdio)
// ---------------------------------------------------------------------------

/// Raw incoming JSON-RPC message.
#[derive(serde::Deserialize)]
struct RawSseIncoming {
    #[allow(dead_code)]
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
    id: Option<serde_json::Value>,
}

#[derive(Debug)]
enum SseIncoming {
    Request(JsonRpcRequest),
    Notification(JsonRpcNotification),
}

fn parse_sse_incoming(body: &str) -> Result<SseIncoming, Box<JsonRpcResponse>> {
    let raw: RawSseIncoming = serde_json::from_str(body).map_err(|e| {
        Box::new(JsonRpcResponse::error(
            RequestId::Number(0),
            JsonRpcError {
                code: PARSE_ERROR,
                message: format!("failed to parse JSON-RPC message: {e}"),
                data: None,
            },
        ))
    })?;

    match raw.id {
        Some(id_val) => {
            let id: RequestId = serde_json::from_value(id_val).map_err(|e| {
                Box::new(JsonRpcResponse::error(
                    RequestId::Number(0),
                    JsonRpcError {
                        code: PARSE_ERROR,
                        message: format!("invalid request id: {e}"),
                        data: None,
                    },
                ))
            })?;
            Ok(SseIncoming::Request(JsonRpcRequest {
                jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
                method: raw.method,
                params: raw.params,
                id,
            }))
        }
        None => Ok(SseIncoming::Notification(JsonRpcNotification {
            jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
            method: raw.method,
            params: raw.params,
        })),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::protocol::{METHOD_INITIALIZE, METHOD_INITIALIZED, METHOD_PING};
    use crate::server::{ContextOutletInfo, MemberInfo};
    use scp_core::context::membership::ContextEvent;

    // -- Mock provider (same shape as stdio tests) ----------------------------

    struct MockProvider {
        contexts: Vec<String>,
        agent_did: String,
    }

    impl Default for MockProvider {
        fn default() -> Self {
            Self {
                contexts: vec!["ctx_a".to_owned()],
                agent_did: "did:dht:test".to_owned(),
            }
        }
    }

    impl ContextProvider for MockProvider {
        fn active_context_ids(&self) -> Vec<String> {
            self.contexts.clone()
        }
        fn agent_role(&self, _context_id: &str) -> Option<String> {
            Some("admin".to_owned())
        }
        fn agent_did(&self) -> &str {
            &self.agent_did
        }
        fn context_tools(&self, _context_id: &str) -> Vec<ContextOutletInfo> {
            Vec::new()
        }
        fn validate_capability(&self, _context_id: &str, _tool_name: &str) -> Result<(), String> {
            Ok(())
        }
        fn invoke_outlet(
            &self,
            _context_id: &str,
            _outlet_id: &str,
            _arguments: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({"status": "ok"}))
        }
        fn validate_resource_access(
            &self,
            _context_id: &str,
            _resource: crate::server::ResourceKind,
        ) -> Result<(), String> {
            Ok(())
        }
        fn context_members(&self, _context_id: &str) -> Vec<MemberInfo> {
            Vec::new()
        }
        fn context_events(&self, _context_id: &str) -> serde_json::Value {
            serde_json::json!([])
        }
    }

    // -- Helper: create shared state for tests --------------------------------

    fn test_config() -> SseConfig {
        let mut config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        config.channel_capacity = 16;
        config
    }

    /// Shared state with the single-session slot ALREADY CLAIMED, standing in
    /// for a live `GET /sse` client. `message_handler` refuses requests with no
    /// session attached, since their responses would otherwise be broadcast
    /// with no client listening and silently dropped.
    fn test_state() -> Arc<AppState<MockProvider>> {
        let state = Arc::new(AppState {
            server: Mutex::new(McpServer::new(MockProvider::default())),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        });
        state
            .session_slot
            .try_acquire()
            .expect("fresh state must have a free session slot")
            .forget();
        state
    }

    // -- parse_sse_incoming ---------------------------------------------------

    #[test]
    fn parse_sse_incoming_request() {
        let body = r#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
        match parse_sse_incoming(body).unwrap() {
            SseIncoming::Request(req) => {
                assert_eq!(req.method, "ping");
                assert_eq!(req.id, RequestId::Number(1));
            }
            SseIncoming::Notification(_) => panic!("expected request"),
        }
    }

    #[test]
    fn parse_sse_incoming_notification() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        match parse_sse_incoming(body).unwrap() {
            SseIncoming::Notification(notif) => {
                assert_eq!(notif.method, "notifications/initialized");
            }
            SseIncoming::Request(_) => panic!("expected notification"),
        }
    }

    #[test]
    fn parse_sse_incoming_invalid_json() {
        let err = parse_sse_incoming("bad json").unwrap_err();
        assert!(err.error.is_some());
        assert_eq!(err.error.as_ref().unwrap().code, PARSE_ERROR);
    }

    // -- Router integration tests ---------------------------------------------

    #[tokio::test]
    async fn router_builds_successfully() {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        let (_router, pump) = router_with_pump(server, &config, None);
        assert!(pump.is_none(), "no event source means no pump");
    }

    #[tokio::test]
    async fn message_handler_processes_initialize() {
        let state = test_state();
        let mut rx = state.notifier.tx.subscribe();

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            },
            "id": 1
        })
        .to_string();

        let response = match parse_sse_incoming(&body).unwrap() {
            SseIncoming::Request(req) => {
                let mut srv = state.server.lock().await;
                srv.handle_request(&req)
            }
            SseIncoming::Notification(_) => None,
        };

        assert!(response.is_some());
        let resp = response.unwrap();
        assert!(resp.result.is_some());
        assert_eq!(resp.id, RequestId::Number(1));

        let json = serde_json::to_string(&resp).unwrap();
        state.notifier.broadcast(json.clone());

        let (_id, received) = rx.recv().await.unwrap();
        assert_eq!(received, json);
    }

    #[tokio::test]
    async fn message_handler_processes_ping() {
        let state = test_state();

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 42
        })
        .to_string();

        let response = match parse_sse_incoming(&body).unwrap() {
            SseIncoming::Request(req) => {
                let mut srv = state.server.lock().await;
                srv.handle_request(&req)
            }
            SseIncoming::Notification(_) => None,
        };

        let resp = response.unwrap();
        assert!(resp.result.is_some());
        assert_eq!(resp.id, RequestId::Number(42));
    }

    #[tokio::test]
    async fn message_handler_handles_notification() {
        let state = test_state();

        let init_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            },
            "id": 0
        })
        .to_string();
        if let SseIncoming::Request(req) = parse_sse_incoming(&init_body).unwrap() {
            let mut srv = state.server.lock().await;
            srv.handle_request(&req);
        }

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZED
        })
        .to_string();

        let result = match parse_sse_incoming(&body).unwrap() {
            SseIncoming::Request(req) => {
                let mut srv = state.server.lock().await;
                srv.handle_request(&req)
            }
            SseIncoming::Notification(notif) => {
                let synthetic_id = state.notifier.next_id();
                let synthetic = JsonRpcRequest {
                    jsonrpc: notif.jsonrpc,
                    method: notif.method,
                    params: notif.params,
                    id: RequestId::Number(synthetic_id.cast_signed()),
                };
                let mut srv = state.server.lock().await;
                srv.handle_request(&synthetic);
                None
            }
        };

        assert!(result.is_none());
    }

    #[test]
    fn sse_config_defaults() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let config = SseConfig::new(addr);
        assert_eq!(config.bind_addr, addr);
        assert_eq!(config.channel_capacity, 256);
        assert_eq!(config.retry_ms, DEFAULT_RETRY_MS);
        assert!(config.auth_token.is_none());
    }

    #[tokio::test]
    async fn send_notification_broadcasts_to_receivers() {
        let state = test_state();
        let mut rx = state.notifier.tx.subscribe();

        let notif = McpServer::<MockProvider>::tools_list_changed_notification();
        let count = state.notifier.notify(&notif);
        assert_eq!(count, 1);

        let (_id, received) = rx.recv().await.unwrap();
        let parsed: JsonRpcNotification = serde_json::from_str(&received).unwrap();
        assert_eq!(parsed.method, "notifications/tools/list_changed");
    }

    #[tokio::test]
    async fn send_notification_returns_zero_with_no_receivers() {
        // No SSE client attached, so no receivers exist.
        let state = test_state();

        let notif = McpServer::<MockProvider>::tools_list_changed_notification();
        let count = state.notifier.notify(&notif);
        assert_eq!(count, 0);
    }

    // -- End-to-end subscription delivery -------------------------------------

    /// Builds an initialized server with a wired event source, subscribed to
    /// `uri`.
    fn subscribed_server(
        uri: &str,
        rx: broadcast::Receiver<ContextEventEnvelope>,
    ) -> (McpServer<MockProvider>, ContextEventPump) {
        let (mut server, pump) = McpServer::with_event_source(MockProvider::default(), rx);

        let init = JsonRpcRequest {
            jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
            method: crate::protocol::METHOD_INITIALIZE.to_owned(),
            params: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            })),
            id: RequestId::Number(1),
        };
        assert!(server.handle_request(&init).unwrap().error.is_none());

        let sub = JsonRpcRequest {
            jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
            method: crate::protocol::METHOD_RESOURCES_SUBSCRIBE.to_owned(),
            params: Some(serde_json::json!({ "uri": uri })),
            id: RequestId::Number(2),
        };
        assert!(server.handle_request(&sub).unwrap().error.is_none());

        (server, pump)
    }

    /// Drives the full delivery chain that `resources/subscribe` promises:
    /// runtime event -> broadcast channel -> pump -> subscription filter ->
    /// `notifications/resources/updated` on the SSE stream.
    ///
    /// This is the test that would have failed against the old no-op
    /// implementation, which accepted the subscription and then delivered
    /// nothing (issue #1341).
    #[tokio::test]
    async fn subscribe_then_event_delivers_resources_updated() {
        let (event_tx, event_rx) = broadcast::channel::<ContextEventEnvelope>(16);

        // A client initializes and subscribes to the context's event stream.
        let (server, pump_source) = subscribed_server("scp://ctx_a/events", event_rx);

        let state = Arc::new(AppState {
            server: Mutex::new(server),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        });

        // A client attaches to the SSE stream.
        let mut client = state.notifier.tx.subscribe();

        let pump = tokio::spawn(pump_events(Arc::clone(&state), pump_source.into_receiver()));

        // The runtime emits a context event.
        event_tx
            .send(ContextEventEnvelope::new(
                "ctx_a".to_owned(),
                ContextEvent::ContentKeysRotated { reason: None },
            ))
            .unwrap();

        let (_id, payload) = tokio::time::timeout(Duration::from_secs(5), client.recv())
            .await
            .expect("notification must arrive")
            .expect("broadcast channel must stay open");

        let notif: JsonRpcNotification = serde_json::from_str(&payload).unwrap();
        assert_eq!(notif.method, crate::protocol::METHOD_RESOURCES_UPDATED);
        assert_eq!(notif.params.unwrap()["uri"], "scp://ctx_a/events");

        pump.abort();
    }

    /// The same chain must stay silent for a resource nobody subscribed to.
    #[tokio::test]
    async fn event_without_subscription_delivers_nothing() {
        let (event_tx, event_rx) = broadcast::channel::<ContextEventEnvelope>(16);

        let (server, pump_source) = McpServer::with_event_source(MockProvider::default(), event_rx);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        });

        let mut client = state.notifier.tx.subscribe();
        let pump = tokio::spawn(pump_events(Arc::clone(&state), pump_source.into_receiver()));

        event_tx
            .send(ContextEventEnvelope::new(
                "ctx_a".to_owned(),
                ContextEvent::ContentKeysRotated { reason: None },
            ))
            .unwrap();

        // Nothing subscribed, so nothing is pushed.
        let got = tokio::time::timeout(Duration::from_millis(200), client.recv()).await;
        assert!(got.is_err(), "unsubscribed resource must not notify");

        pump.abort();
    }

    // -- Broadcast with event IDs ---------------------------------------------

    #[tokio::test]
    async fn broadcast_assigns_sequential_ids() {
        let state = test_state();
        let mut rx = state.notifier.tx.subscribe();

        let id1 = state.notifier.broadcast("msg-1".to_owned());
        let id2 = state.notifier.broadcast("msg-2".to_owned());

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);

        let (recv_id1, recv_data1) = rx.recv().await.unwrap();
        let (recv_id2, recv_data2) = rx.recv().await.unwrap();
        assert_eq!(recv_id1, 1);
        assert_eq!(recv_data1, "msg-1");
        assert_eq!(recv_id2, 2);
        assert_eq!(recv_data2, "msg-2");
    }

    // -- Shutdown handle ------------------------------------------------------

    #[test]
    fn shutdown_handle_signals_correctly() {
        let handle = ShutdownHandle::new();
        assert!(!handle.is_shutdown());
        handle.shutdown();
        assert!(handle.is_shutdown());
    }

    #[test]
    fn shutdown_handle_default_is_not_shutdown() {
        let handle = ShutdownHandle::default();
        assert!(!handle.is_shutdown());
    }

    // -- run_sse with shutdown ------------------------------------------------

    #[tokio::test]
    async fn run_sse_shuts_down_on_signal() {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        let handle = ShutdownHandle::new();

        let run_handle = handle.clone();
        let bundle = McpServerForTransport::Unwired(server);
        let task = tokio::spawn(async move { run_sse(bundle, config, run_handle).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.shutdown();

        let result = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert!(result.is_ok(), "server should shut down within timeout");
        assert!(result.unwrap().unwrap().is_ok());
    }

    // -- Auth middleware -------------------------------------------------------

    #[tokio::test]
    async fn router_with_auth_builds_successfully() {
        let server = McpServer::new(MockProvider::default());
        let mut config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        config.auth_token = Some("secret-token".to_owned());
        let (_router, pump) = router_with_pump(server, &config, None);
        assert!(pump.is_none(), "no event source means no pump");
    }

    #[tokio::test]
    async fn router_without_auth_builds_successfully() {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        assert!(config.auth_token.is_none());
        let (_router, pump) = router_with_pump(server, &config, None);
        assert!(pump.is_none(), "no event source means no pump");
    }

    #[test]
    fn sse_config_with_auth_token() {
        let mut config = SseConfig::new("127.0.0.1:3000".parse().unwrap());
        config.auth_token = Some("my-secret".to_owned());
        assert_eq!(config.auth_token.as_deref(), Some("my-secret"));
    }

    // -- Auth middleware integration tests ------------------------------------

    /// Helper: build an authenticated router (`auth_token` = "test-secret").
    fn auth_router() -> Router {
        let server = McpServer::new(MockProvider::default());
        let mut config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        config.auth_token = Some("test-secret".to_owned());
        router_with_pump(server, &config, None).0
    }

    /// Helper: build an unauthenticated router (`auth_token` = None).
    fn noauth_router() -> Router {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        router_with_pump(server, &config, None).0
    }

    // -- Single-session admission --------------------------------------------

    /// An `McpServer` *is* one MCP session — one `initialized` flag, one
    /// negotiated capability set, one subscription registry — and every
    /// server→client message goes out on one shared broadcast. Admitting a
    /// second concurrent client would silently share all of that: B would
    /// inherit A's handshake, receive A's JSON-RPC responses, see updates for
    /// A's subscriptions, and cancel them with its own `resources/unsubscribe`.
    ///
    /// The endpoint therefore refuses the second session rather than
    /// pretending to multiplex.
    #[tokio::test]
    async fn second_concurrent_sse_session_is_refused() {
        use tower::ServiceExt;

        let router = noauth_router();

        // First client attaches and holds its stream open.
        let first = router
            .clone()
            .oneshot(Request::builder().uri("/sse").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        // Second concurrent client is refused while the first is live.
        let second = router
            .clone()
            .oneshot(Request::builder().uri("/sse").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            StatusCode::CONFLICT,
            "a second concurrent MCP session must be refused, not silently shared"
        );

        // Once the first stream is dropped the slot frees for the next client.
        drop(first);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let third = router
            .oneshot(Request::builder().uri("/sse").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            third.status(),
            StatusCode::OK,
            "the session slot must be released when the client disconnects"
        );
    }

    /// Helper: send a request through the router and return the status code.
    async fn request_status(router: Router, req: Request<Body>) -> StatusCode {
        use tower::ServiceExt;

        let response = router.oneshot(req).await.unwrap();
        response.status()
    }

    #[tokio::test]
    async fn auth_valid_bearer_sse_accepted() {
        let router = auth_router();
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer test-secret")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_valid_bearer_post_accepted() {
        let router = auth_router();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 1
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("/message")
            .header("Authorization", "Bearer test-secret")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let status = request_status(router, req).await;
        // Authentication passed (not 401); the request is then refused because
        // no SSE session is attached to deliver the response on.
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn auth_missing_bearer_sse_rejected() {
        let router = auth_router();
        let req = Request::builder().uri("/sse").body(Body::empty()).unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_missing_bearer_post_rejected() {
        let router = auth_router();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 1
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("/message")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_wrong_bearer_sse_rejected() {
        let router = auth_router();
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_wrong_bearer_post_rejected() {
        let router = auth_router();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 1
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("/message")
            .header("Authorization", "Bearer wrong-token")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_empty_bearer_rejected() {
        let router = auth_router();
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_malformed_header_rejected() {
        let router = auth_router();
        // "Basic" scheme instead of "Bearer"
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_bearer_without_space_rejected() {
        let router = auth_router();
        // Missing space after "Bearer"
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearertest-secret")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn noauth_allows_requests_without_header() {
        let router = noauth_router();
        // SSE endpoint should work without any auth header when auth is disabled
        let req = Request::builder().uri("/sse").body(Body::empty()).unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn noauth_post_allows_requests_without_header() {
        let router = noauth_router();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_PING,
            "id": 1
        })
        .to_string();

        let req = Request::builder()
            .method("POST")
            .uri("/message")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let status = request_status(router, req).await;
        // No auth configured, so the request reaches the handler and is refused
        // only because no SSE session is attached.
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn auth_token_prefix_not_accepted() {
        let router = auth_router();
        // Token is "test-secret" but we send "test-secret-extended" -- should
        // fail because constant-time comparison requires exact match.
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer test-secret-extended")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_token_substring_not_accepted() {
        let router = auth_router();
        // Token is "test-secret" but we send "test-secre" (substring)
        let req = Request::builder()
            .uri("/sse")
            .header("Authorization", "Bearer test-secre")
            .body(Body::empty())
            .unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // -- Synthetic request IDs ------------------------------------------------

    #[tokio::test]
    async fn synthetic_notification_ids_are_unique() {
        let state = test_state();

        // Send two notifications and verify the counter advances
        let init_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            },
            "id": 0
        })
        .to_string();
        if let SseIncoming::Request(req) = parse_sse_incoming(&init_body).unwrap() {
            let mut srv = state.server.lock().await;
            srv.handle_request(&req);
        }

        // First notification uses next_event_id (starts at 1)
        let id1 = state.notifier.next_event_id.load(Ordering::SeqCst);
        let notif_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZED
        })
        .to_string();
        if let SseIncoming::Notification(notif) = parse_sse_incoming(&notif_body).unwrap() {
            let synthetic_id = state.notifier.next_id();
            assert_eq!(synthetic_id, id1);

            // Verify the ID is correctly assigned
            let request = JsonRpcRequest {
                jsonrpc: notif.jsonrpc,
                method: notif.method,
                params: notif.params,
                id: RequestId::Number(synthetic_id.cast_signed()),
            };
            assert_eq!(request.id, RequestId::Number(id1.cast_signed()));
        }

        // Second call produces a different ID
        let id2 = state.notifier.next_event_id.fetch_add(1, Ordering::SeqCst);
        assert_ne!(id1, id2);
    }

    // -- Session reset sequencing ---------------------------------------------

    /// A session admitted immediately after the previous guard's drop must not
    /// lose its handshake or subscriptions to that guard's asynchronously
    /// spawned `reset_session`.
    ///
    /// Guards against the admission race where `SessionGuard::drop` freed the
    /// permit synchronously (in field order) while only *spawning* the reset:
    /// the next client could be admitted, initialize, and subscribe before the
    /// spawned reset ran — which then silently wiped the new session's state.
    /// Two mechanisms close it: admission resets the session first thing, and
    /// the dropped guard's permit now rides its reset task, freeing the slot
    /// only after `reset_session()` completes.
    #[tokio::test]
    async fn session_admitted_after_previous_drop_keeps_its_subscription() {
        let (_event_tx, event_rx) = broadcast::channel::<ContextEventEnvelope>(16);
        // Wired server: `resources/subscribe` must be accepted for the second
        // session's registration to exist at all.
        let (server, _pump) = McpServer::with_event_source(MockProvider::default(), event_rx);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        });

        // First client attaches through the real handler, then disconnects,
        // dropping its stream and with it the `SessionGuard`.
        let first = sse_handler(State(Arc::clone(&state))).await;
        assert_eq!(first.status(), StatusCode::OK);
        drop(first);

        // Admission may briefly 409 while the dropped guard's reset task still
        // holds the permit; the slot must free once the reset completes.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let second = loop {
            let resp = sse_handler(State(Arc::clone(&state))).await;
            if resp.status() == StatusCode::OK {
                break resp;
            }
            assert_eq!(resp.status(), StatusCode::CONFLICT);
            assert!(
                std::time::Instant::now() < deadline,
                "the session slot never freed after the previous guard dropped"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };

        // The second session immediately handshakes and subscribes through the
        // real POST path — exactly the window the old race wiped.
        for body in [
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": METHOD_INITIALIZE,
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "test" }
                },
                "id": 1
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": crate::protocol::METHOD_RESOURCES_SUBSCRIBE,
                "params": { "uri": "scp://ctx_a/events" },
                "id": 2
            }),
        ] {
            let status = message_handler(State(Arc::clone(&state)), body.to_string())
                .await
                .into_response()
                .status();
            assert_eq!(status, StatusCode::ACCEPTED);
        }
        assert_eq!(state.server.lock().await.subscription_count(), 1);

        // Give any stale scheduled reset every chance to run; the second
        // session's registration must survive it.
        tokio::time::sleep(Duration::from_millis(100)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            state.server.lock().await.subscription_count(),
            1,
            "a stale session reset wiped the newly admitted session's subscription"
        );
        drop(second);
    }

    // -- No cross-session replay (leak regression) ----------------------------

    /// A newly admitted session must receive NOTHING from a prior session,
    /// even when it presents `Last-Event-ID: 0` — the strongest possible
    /// replay request. The removed replay machinery streamed the previous
    /// client's buffered decrypted JSON-RPC responses (member lists, tool
    /// outputs, resource reads) to whichever client connected next; admission
    /// resets the session, so anything replayable predates the reset and
    /// belongs to the prior logical session. This test fails if replay is
    /// ever served again.
    #[tokio::test]
    async fn new_admission_never_receives_prior_session_messages() {
        use tower::ServiceExt;

        let router = noauth_router();

        // Client A attaches and completes an initialize round-trip; its
        // JSON-RPC response goes out on the SSE broadcast.
        let first = router
            .clone()
            .oneshot(Request::builder().uri("/sse").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let init_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "client-a" }
            },
            "id": 1
        })
        .to_string();
        let post = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/message")
                    .header("content-type", "application/json")
                    .body(Body::from(init_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post.status(), StatusCode::ACCEPTED);

        // A disconnects without reading its response.
        drop(first);

        // Client B is admitted (polling past the reset-in-flight 409 window)
        // and presents `Last-Event-ID: 0`, requesting everything ever
        // broadcast.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let second = loop {
            let resp = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/sse")
                        .header("last-event-id", "0")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            if resp.status() == StatusCode::OK {
                break resp;
            }
            assert_eq!(resp.status(), StatusCode::CONFLICT);
            assert!(
                std::time::Instant::now() < deadline,
                "the session slot never freed after client A disconnected"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };

        // Read B's stream for a bounded window: it must carry the endpoint
        // event and NO `message` frames — in particular, none of A's
        // initialize response.
        let mut body = second.into_body().into_data_stream();
        let mut seen = String::new();
        let read_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while let Ok(Some(Ok(bytes))) = tokio::time::timeout_at(read_deadline, body.next()).await {
            seen.push_str(&String::from_utf8_lossy(&bytes));
        }
        assert!(
            seen.contains("event: endpoint"),
            "the fresh session must receive its endpoint event; stream was:\n{seen}"
        );
        assert!(
            !seen.contains("event: message"),
            "a fresh admission replayed a prior session's messages; stream was:\n{seen}"
        );
        assert!(
            !seen.contains("protocolVersion"),
            "client A's initialize response leaked to client B; stream was:\n{seen}"
        );
    }

    // -- Response broadcast is ordered under the server lock ------------------

    /// `message_handler` must broadcast its response *while holding the
    /// `state.server` lock*, never after releasing it. That lock is the one
    /// `sse_handler`'s `reset_session` and the next admission's re-subscribe
    /// serialize on, so ordering the broadcast under it is what prevents a
    /// response computed for the current principal from being delivered, during
    /// a disconnect->reset->readmit window, to a later, different client (the
    /// live-response cross-principal leak).
    ///
    /// The observable seam: hold the server lock (standing in for a reset /
    /// concurrent admission that holds it), then drive a POST whose response is
    /// produced by `message_handler` itself — a malformed body, the one message
    /// that the pre-fix code broadcast *without ever taking the lock*. While the
    /// lock is held, a correct handler cannot broadcast; a handler that
    /// broadcasts lock-free (the bug) delivers immediately and this test fails.
    ///
    /// What it proves: no `message_handler` broadcast escapes the server-lock
    /// critical section. What it does not attempt: a fully deterministic 3-way
    /// reset race — the request-response arm shares the *same* single critical
    /// section as this arm by construction (see `message_handler`), so the
    /// ordering this locks down covers it too.
    #[tokio::test]
    async fn response_broadcast_is_serialized_under_the_server_lock() {
        let state = test_state();
        let mut rx = state.notifier.tx.subscribe();

        // Stand in for the reset task / next admission holding the server lock.
        let guard = state.server.lock().await;

        // A POST arrives concurrently. Its response must be broadcast under the
        // server lock; spawn the handler so it can park on the lock we hold.
        let handler = tokio::spawn(message_handler(
            State(Arc::clone(&state)),
            "not valid json".to_owned(),
        ));

        // Give the handler time to run and block on the lock. A handler that
        // broadcasts without the lock would already have delivered by now.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "message_handler broadcast a response while another party held the \
             server lock — the cross-principal ordering that lock provides is \
             defeated, so an in-flight response could reach a later client"
        );

        // Releasing the lock lets the handler acquire it and broadcast under it.
        drop(guard);
        let status = handler.await.unwrap().into_response().status();
        assert_eq!(status, StatusCode::ACCEPTED);

        let (_id, payload) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the response must be delivered once the server lock is free")
            .expect("broadcast channel must stay open");
        assert!(
            payload.contains("failed to parse"),
            "expected the parse-error response once the lock freed; got:\n{payload}"
        );
    }

    // -- Wire lag terminates the stream ---------------------------------------

    /// A client that falls behind the broadcast channel must have its stream
    /// TERMINATED, not silently continued past the gap. Termination is the
    /// resync signal: the client observes the disconnect, reconnects, is
    /// admitted into a freshly reset session, re-initializes, re-subscribes,
    /// and re-reads state. Under the old behavior the lag error was dropped
    /// in a `filter_map` and the client kept streaming, silently missing
    /// events.
    #[tokio::test]
    async fn wire_lag_terminates_the_stream() {
        let state = Arc::new(AppState {
            server: Mutex::new(McpServer::new(MockProvider::default())),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        });

        // A client attaches; the handler subscribes its broadcast receiver.
        let response = sse_handler(State(Arc::clone(&state))).await;
        assert_eq!(response.status(), StatusCode::OK);

        // With the stream unpolled, drive the channel far past its capacity
        // (`test_config` uses 16) so the receiver is deterministically lagged.
        for i in 0..64 {
            state.notifier.broadcast(format!("event-{i}"));
        }

        // Poll the body: after the endpoint event, the first broadcast poll
        // observes the lag and must END the stream rather than resume past it.
        let mut body = response.into_body().into_data_stream();
        let mut seen = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut terminated = false;
        loop {
            match tokio::time::timeout_at(deadline, body.next()).await {
                Ok(Some(Ok(bytes))) => seen.push_str(&String::from_utf8_lossy(&bytes)),
                Ok(Some(Err(_)) | None) => {
                    terminated = true;
                    break;
                }
                Err(_) => break, // window closed with the stream still open
            }
        }
        assert!(
            terminated,
            "a lagged SSE stream must terminate so the client resyncs into a \
             clean session; it stayed open. Frames seen:\n{seen}"
        );
        // None of the lagged events may be delivered as if the client were
        // current.
        assert!(
            !seen.contains("event: message"),
            "a lagged stream resumed past its gap; frames seen:\n{seen}"
        );

        // Termination completes the recovery loop: dropping the stream drops
        // the session guard, whose reset task frees the slot for readmission.
        drop(body);
        let free_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while state.session_slot.available_permits() == 0 {
            assert!(
                std::time::Instant::now() < free_deadline,
                "the session slot never freed after the lagged stream terminated"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // -- Cancel-abort teardown ------------------------------------------------

    /// The SSE twin of the stdio pump-abort test: aborting the task running
    /// `run_sse` (the drop a bridge's shutdown `select!` performs) must abort
    /// the event pump, not detach it. The pump holds the only receiver on the
    /// event channel, so its death is observable as `receiver_count` falling
    /// to zero; a detached pump would hold that receiver forever.
    #[tokio::test]
    async fn aborting_run_sse_tears_down_the_pump() {
        let (event_tx, event_rx) = broadcast::channel::<ContextEventEnvelope>(16);
        let (server, pump) = McpServer::with_event_source(MockProvider::default(), event_rx);
        let bundle = McpServerForTransport::Wired(server, pump);
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());

        let task = tokio::spawn(run_sse(bundle, config, ShutdownHandle::new()));

        // Let the server bind and spawn its pump; the pump task now owns the
        // channel's only receiver.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished(), "run_sse exited before it was aborted");
        assert_eq!(event_tx.receiver_count(), 1);

        // Abort the server task — the cancellation-drop path. Awaiting the
        // aborted task guarantees the `run_sse` future was dropped, so its
        // `AbortOnDrop` pump guard has run.
        task.abort();
        let _ = task.await;

        // Task abortion completes asynchronously; poll until the pump's
        // receiver is gone.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while event_tx.receiver_count() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the pump outlived run_sse — it was detached, not aborted"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(event_tx.receiver_count(), 0);
    }
}
