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
//!   POST URL, `/message?sessionId=<id>`, where `<id>` is a random value minted
//!   for that admission. It then streams `message` events containing JSON-RPC
//!   responses.
//!   Each event carries a sequential `id:` field for wire framing and
//!   diagnostics only — it does not support resume (see below).
//! - `POST /message?sessionId=<id>` -- Accepts JSON-RPC requests from the
//!   client whose SSE stream is still live under that `sessionId`, and refuses
//!   every other POST with `409 Conflict`. Responses are delivered via the SSE
//!   stream, not in the HTTP response body.
//!
//! ## Reconnection
//!
//! Reconnection is a full resync, not a resume. When an SSE stream is
//! dropped, the server clears that session's handshake, negotiated client
//! capabilities and resource subscriptions, and admits the next `GET /sse`
//! only after that reset. A reconnecting client therefore re-initializes,
//! re-subscribes, and re-reads state;
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
//! accepting new connections and to end every open SSE stream. Graceful
//! shutdown waits for in-flight responses, and an SSE response stays in flight
//! until its stream ends, so a stream that ignored the signal would keep the
//! server running.
//!
//! See ADR-015 in `.docs/adrs/phase-3.md` for the full design.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Query, State};
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

use scp_core::context::membership::ContextEvent;

use crate::protocol::{
    JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, PARSE_ERROR, RequestId,
};
use crate::server::{ContextEventPump, ContextProvider, McpServer, McpServerForTransport};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default retry interval (milliseconds) sent to SSE clients.
const DEFAULT_RETRY_MS: u64 = 3000;

/// How long a new `GET /sse` waits for the session it evicted to release the
/// slot before it gives up with `409 Conflict`.
///
/// Eviction ends the old stream at its next poll, and hyper drops the body,
/// and with it the session permit, as soon as the stream ends. hyper polls
/// the body only while it can buffer output for the socket, so an old
/// connection whose buffers are full can hold the slot past this bound.
const EVICTION_WAIT: Duration = Duration::from_secs(5);

/// Configuration for the SSE transport server.
///
/// `Debug` is implemented by hand so that formatting a config with `{:?}`
/// prints `auth_token` as `<redacted>`: the token is a live credential, and a
/// log line that carried it would let any reader of the log claim the session.
#[derive(Clone)]
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

    /// Bearer token every request to `/sse` and `/message` must present in an
    /// `Authorization: Bearer <token>` header. A request without it, or with
    /// any other token, receives HTTP 401 Unauthorized before it can reach the
    /// single session slot.
    ///
    /// The field is a `String`, not an `Option`, so the transport has no
    /// unauthenticated mode. Without the token, any process that can reach
    /// `bind_addr` could claim the session and then read
    /// `scp://{ctx}/members` and drive `tools/call` as the agent identity the
    /// server was started for.
    pub auth_token: String,
}

impl std::fmt::Debug for SseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SseConfig")
            .field("bind_addr", &self.bind_addr)
            .field("channel_capacity", &self.channel_capacity)
            .field("retry_ms", &self.retry_ms)
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

impl SseConfig {
    /// Creates a new configuration with the given bind address and a fresh
    /// 256-bit bearer token drawn from the operating system's CSPRNG.
    ///
    /// The caller hands [`auth_token`](Self::auth_token) to the MCP client it
    /// intends to serve, or overwrites the field with a token that client
    /// already holds.
    #[must_use]
    pub fn new(bind_addr: SocketAddr) -> Self {
        let mut token = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
        Self {
            bind_addr,
            channel_capacity: 256,
            retry_ms: DEFAULT_RETRY_MS,
            auth_token: hex::encode(token),
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
/// [`shutdown`](Self::shutdown) explicitly. Signaling shutdown stops the
/// listener and ends every open SSE stream, so [`run_sse`] returns even while
/// a client is attached.
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

    /// Signals the SSE server to stop accepting new connections and to end
    /// every open SSE stream.
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
pub(crate) struct McpNotifier {
    /// Broadcast sender for SSE messages to connected clients.
    ///
    /// **Shared across sequential sessions, not minted per session.** This
    /// sender lives on [`AppState`] for the server's whole lifetime; each
    /// admitted session subscribes a fresh receiver, but they all draw from
    /// this one sender. Cross-session non-leakage therefore does *not* come
    /// from channel identity — it comes from two facts that hold together,
    /// both serialized on the `state.server` mutex:
    /// 1. every server→client emission's **broadcast is serialized inside** that
    ///    mutex's critical section, and every principal-content-bearing emission
    ///    is also *computed* under it (see [`message_handler`] and
    ///    [`pump_events`]), and
    /// 2. [`reset_session`](McpServer::reset_session) runs under the *same*
    ///    mutex at admission (see [`sse_handler`]).
    ///
    /// A POST parked on the lock that acquires it just after a reset finds
    /// its `sessionId` no longer live (see [`AppState::live_session`]) and is
    /// refused before dispatch, so no prior session's decrypted data (member
    /// lists, tool outputs, resource reads) can cross to the next client on
    /// this shared channel.
    ///
    /// **Load-bearing:** this safety holds only while `reset_session` stays
    /// atomic w.r.t. the server lock *and* emission never moves outside it. If
    /// either changes, the shared channel becomes a cross-principal exposure
    /// vector, and the fix at that point is per-session channel identity — mint
    /// the channel at admission, drop it at reset. [`Self::broadcast`] and
    /// [`Self::notify`] take the lock's guard, so an emission outside the
    /// lock does not compile.
    tx: broadcast::Sender<(u64, String)>,
    /// Monotonically increasing event ID counter.
    ///
    /// `fetch_add` makes every assigned id unique, which is all the two
    /// consumers — SSE `id:` framing and synthetic request ids for incoming
    /// notifications — require. Two concurrent broadcasts may publish out of
    /// id order; nothing observes or depends on wire-order ids because
    /// resume does not exist.
    next_event_id: AtomicU64,
}

impl McpNotifier {
    /// Creates the push fabric for an SSE server built from `config`.
    fn new(config: &SseConfig) -> Self {
        let (tx, _rx) = broadcast::channel(config.channel_capacity);
        Self {
            tx,
            next_event_id: AtomicU64::new(1),
        }
    }

    /// Broadcasts a JSON payload to all connected SSE clients. Returns the
    /// assigned event ID.
    ///
    /// `_held` is the guard of the `state.server` lock. Requiring it makes a
    /// broadcast after the caller released that lock fail to compile, which
    /// keeps every emission inside the critical section described on
    /// [`Self::tx`].
    fn broadcast<P: ContextProvider>(
        &self,
        _held: &tokio::sync::MutexGuard<'_, McpServer<P>>,
        data: String,
    ) -> u64 {
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
    ///
    /// `held` is the guard of the `state.server` lock, as for
    /// [`Self::broadcast`].
    fn notify<P: ContextProvider>(
        &self,
        held: &tokio::sync::MutexGuard<'_, McpServer<P>>,
        notification: &JsonRpcNotification,
    ) -> usize {
        match serde_json::to_string(notification) {
            Ok(json) => {
                self.broadcast(held, json);
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
    /// The server→client push fabric. The POST handler and the event pump both
    /// reach it through this `AppState`; nothing holds a separate copy.
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
    /// single-session: a new `GET /sse` evicts the live session (see
    /// [`Self::session_evict`]) and is admitted only after that session's
    /// stream has been dropped. When a stream is dropped, the session state is
    /// reset and only *then* is the permit released (the reset task carries
    /// the permit — see [`SessionGuard`]), so the next client is never
    /// admitted while a stale reset is still pending, and never while the
    /// previous stream's broadcast receiver still exists.
    session_slot: Arc<tokio::sync::Semaphore>,
    /// Ends the live session's stream when cancelled.
    ///
    /// A peer that vanishes without a FIN or RST leaves its stream open: the
    /// 15 s keep-alive writes land in the kernel send buffer and succeed until
    /// the TCP retransmission timeout, minutes later. Without eviction that
    /// dead stream would hold the slot for the whole period and refuse every
    /// reconnect. Every request here has passed the bearer check, so the
    /// newest admission is the token holder reconnecting and takes the slot.
    session_evict: std::sync::Mutex<CancellationToken>,
    /// The server's shutdown signal. Every session's eviction token is a child
    /// of it, so a shutdown ends every live stream. Axum's graceful shutdown
    /// waits for in-flight responses, and an SSE response is in flight until
    /// its stream ends: without this link one attached client would keep
    /// [`run_sse`] from returning, and keep the pump and this state alive.
    shutdown: CancellationToken,
    /// The `sessionId` of the live SSE stream, or `None` when no stream is
    /// attached.
    ///
    /// Admission writes it while holding `state.server`, after the reset. A
    /// dropped [`SessionGuard`] clears it synchronously, before the permit
    /// moves into the reset task, so the interval between a stream ending and
    /// its reset running has no live session. [`message_handler`] compares the
    /// POST's `sessionId` against it while holding `state.server`, so a POST
    /// from an evicted or disconnected client, and a POST that arrives after
    /// its stream is gone, is refused before it can run against the session.
    live_session: std::sync::Mutex<Option<String>>,
}

impl<P: ContextProvider> AppState<P> {
    /// Whether `presented` names the live SSE session.
    fn is_live_session(&self, presented: Option<&str>) -> bool {
        let live = self
            .live_session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        matches!((live.as_deref(), presented), (Some(live), Some(presented)) if live == presented)
    }
}

/// Mints a fresh 128-bit `sessionId` for one SSE admission.
fn mint_session_id() -> String {
    let mut id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    hex::encode(id)
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
    shutdown: CancellationToken,
) -> (Router, Option<tokio::task::JoinHandle<()>>) {
    let state = Arc::new(AppState {
        server: Mutex::new(server),
        notifier: McpNotifier::new(config),
        retry_ms: config.retry_ms,
        session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        session_evict: std::sync::Mutex::new(CancellationToken::new()),
        shutdown,
        live_session: std::sync::Mutex::new(None),
    });

    let pump = pump.map(|pump| tokio::spawn(pump_events(Arc::clone(&state), pump.into_receiver())));

    let router = Router::new()
        .route("/sse", get(sse_handler::<P>))
        .route("/message", post(message_handler::<P>))
        .with_state(state);

    let expected = config.auth_token.clone();
    let router = router.layer(middleware::from_fn(move |req, next| {
        bearer_auth_middleware(req, next, expected.clone())
    }));

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
/// The endpoint serves one MCP session at a time; a new `GET /sse` evicts the
/// live session and takes its place. The server resets the evicted session's
/// handshake and subscriptions before it admits the new stream, so the new
/// client starts with neither.
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

    // Every session's eviction token descends from `server_token`. The drop
    // guard cancels it on EVERY exit from this future, including the
    // cancellation-drop when a bridge aborts the task running `run_sse`. axum
    // serves each connection on its own spawned task, which dropping `serve`
    // does not stop, so without this an attached SSE stream would outlive the
    // server: still sending keep-alives, still holding its subscriptions, with
    // no pump left to serve them.
    let server_token = shutdown.token.child_token();
    let _sessions_guard = server_token.clone().drop_guard();
    let (router, pump) = router_with_pump(server, &config, pump, server_token);
    // Hold the pump under a guard that aborts it on every exit from this future,
    // for the same reason: a bare `JoinHandle` dropped without `abort()` only
    // detaches the task, which — holding an `Arc<AppState>` — would outlive the
    // server.
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
    // Admission note: the bearer middleware that `router_with_pump` always
    // installs rejects a request without `SseConfig::auth_token` before it
    // reaches this slot. A process that holds the token owns the session: it
    // can read `scp://{ctx}/members` and drive `tools/call` as the agent
    // identity. The token is therefore the only thing that separates the
    // intended client from any other process that can reach the bind address.
    //
    // A busy slot is evicted, never waited out: a peer that vanished without
    // closing its connection would otherwise hold the slot until TCP gives up
    // (see `AppState::session_evict`). The new admission waits for the
    // evicted stream to drop, which frees the permit only after the reset and
    // after the old broadcast receiver is gone.
    //
    // Last admission wins. Under one lock each admission cancels the stored
    // token and stores its own, so the stored token always belongs to the
    // newest claimant: the live session, or an admission still waiting for
    // the permit. A newer admission therefore cancels a waiting one, which
    // gives up, instead of cancelling a session that has already ended and
    // then losing the permit to the older waiter.
    let (free, evict) = {
        let mut current = state
            .session_evict
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        current.cancel();
        *current = state.shutdown.child_token();
        (
            Arc::clone(&state.session_slot).try_acquire_owned().ok(),
            current.clone(),
        )
    };
    let permit = if let Some(permit) = free {
        permit
    } else {
        tracing::info!("MCP SSE: evicting the live session for a new admission");
        let waited = tokio::time::timeout(EVICTION_WAIT, async {
            tokio::select! {
                permit = Arc::clone(&state.session_slot).acquire_owned() => permit.ok(),
                () = evict.cancelled() => None,
            }
        })
        .await;
        let Ok(Some(permit)) = waited else {
            tracing::warn!("MCP SSE: admission superseded or the evicted session kept the slot");
            return (
                StatusCode::CONFLICT,
                "an MCP session is already active on this endpoint",
            )
                .into_response();
        };
        permit
    };

    // Every session begins from a clean slate by sequencing, not scheduling
    // luck. The previous guard's `Drop` can only *spawn* its reset (`Drop` is
    // synchronous), and although that spawned task holds the session permit
    // until the reset completes (see `SessionGuard`), resetting here makes
    // admission itself the guarantee: a freshly admitted client can never
    // inherit another session's handshake or subscriptions, nor lose its own
    // to a stale reset that was scheduled but had not yet run.
    //
    // This reset is also the second half of the shared-broadcast-channel
    // invariant documented on `McpNotifier::tx`: because it runs under the same
    // `state.server` mutex that every emission serializes on, and post-reset
    // `handle_request` is init-gated (returns only a "not initialized" error
    // with no principal content until re-`initialize`), the broadcast channel
    // shared across sessions never leaks one principal's decrypted responses to
    // the next.
    //
    // The new `sessionId` goes live under the same lock, after the reset, and
    // the broadcast receiver is subscribed there too: from this point a POST
    // is dispatched only if it names this admission.
    let session_id = mint_session_id();
    let mut server = state.server.lock().await;
    server.reset_session();
    *state
        .live_session
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(session_id.clone());
    let rx = state.notifier.tx.subscribe();
    // Released only once the session is live and its receiver subscribed.
    drop(server);

    let endpoint_event = Event::default()
        .event("endpoint")
        .data(format!("/message?sessionId={session_id}"))
        .retry(Duration::from_millis(state.retry_ms));

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

    // `None` ends the stream: the content side sends it after its last event
    // (a `Lagged` receiver ends early), the eviction side sends it when a
    // newer admission cancels this session or the server shuts down.
    let initial = tokio_stream::once(Ok(endpoint_event));
    let content = initial
        .chain(message_stream)
        .map(Some)
        .chain(tokio_stream::once(None));
    let evicted = tokio_stream::once(())
        .then(move |()| evict.clone().cancelled_owned())
        .map(|()| None);
    let stream = content.merge(evicted).map_while(|frame| frame);

    // Hold a session guard for the lifetime of the stream. When the client
    // disconnects the stream is dropped, dropping the guard, which resets the
    // session (handshake state + resource subscriptions) and frees the session
    // slot — the next client must re-handshake and re-subscribe rather than
    // inherit the previous session's registry.
    let guard = SessionGuard {
        state: Arc::clone(&state),
        permit: Some(permit),
        session_id,
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
/// Requires the POST's `sessionId` query parameter to name the live SSE
/// session (see [`AppState::live_session`]). The response goes out on the SSE
/// broadcast, so a request from a client whose stream is gone would run
/// against the session and have its response dropped unheard, and a request
/// from an evicted client would run against the next client's session and
/// have its response delivered to that client. Both are refused with
/// `409 Conflict` before dispatch.
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
///
/// Every arm, the parse-error arm included, parses, computes and broadcasts
/// after the lock is taken and the `sessionId` checked.
async fn message_handler<P: ContextProvider + 'static>(
    State(state): State<Arc<AppState<P>>>,
    Query(query): Query<MessageQuery>,
    body: String,
) -> impl IntoResponse {
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
    let mut server = state.server.lock().await;

    // Checked under the lock admission writes the live `sessionId` under, so
    // the POST runs against the session it names or not at all.
    if !state.is_live_session(query.session_id.as_deref()) {
        return StatusCode::CONFLICT;
    }

    let trimmed = body.trim();
    if trimmed.is_empty() {
        return StatusCode::BAD_REQUEST;
    }

    match parse_sse_incoming(trimmed) {
        Ok(SseIncoming::Request(req)) => {
            if let Some(resp) = server.handle_request(&req)
                && let Ok(json) = serde_json::to_string(&resp)
            {
                state.notifier.broadcast(&server, json);
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
            server.handle_request(&synthetic);
        }
        Err(err_response) => {
            // A parse error echoes only the caller's own malformed input, but
            // it is still a server->client message on the shared broadcast, so
            // it goes out under the server lock like every other response.
            if let Ok(json) = serde_json::to_string(&err_response) {
                state.notifier.broadcast(&server, json);
            }
        }
    }
    // A `tools/call` queues the notifications its outlet run causes. They go
    // out after its response, under the same lock.
    for notification in &server.take_pending_notifications() {
        state.notifier.notify(&server, notification);
    }
    // Released only after the broadcast, for the ordering described above.
    drop(server);

    StatusCode::ACCEPTED
}

/// Query parameters of `POST /message`.
#[derive(serde::Deserialize)]
struct MessageQuery {
    /// The `sessionId` the `endpoint` event handed this client.
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Event pump
// ---------------------------------------------------------------------------

/// Forwards runtime context events to connected clients as MCP notifications.
async fn pump_events<P: ContextProvider + 'static>(
    state: Arc<AppState<P>>,
    mut events: broadcast::Receiver<(String, ContextEvent)>,
) {
    loop {
        let (context_id, event) = match events.recv().await {
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
                    state.notifier.notify(&server, notification);
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
            state.notifier.notify(&server, notification);
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
    /// The `sessionId` this stream's admission made live.
    session_id: String,
}

impl<P: ContextProvider + 'static> Drop for SessionGuard<P> {
    fn drop(&mut self) {
        // Retire the `sessionId` now, synchronously: the reset below runs
        // later, and until it does the permit is still held, so a POST in that
        // interval must find no live session rather than run against this one.
        {
            let mut live = self
                .state
                .live_session
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if live.as_deref() == Some(self.session_id.as_str()) {
                *live = None;
            }
        }
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
    use crate::server::TransportBundle;
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
        fn active_context_ids(&self) -> Result<Vec<String>, String> {
            Ok(self.contexts.clone())
        }
        fn agent_role(&self, _context_id: &str) -> Result<Option<String>, String> {
            Ok(Some("admin".to_owned()))
        }
        fn agent_did(&self) -> &str {
            &self.agent_did
        }
        fn context_tools(&self, _context_id: &str) -> Result<Vec<ContextOutletInfo>, String> {
            Ok(Vec::new())
        }
        fn validate_capability(
            &self,
            _context_id: &str,
            _tool_name: &str,
            _check: crate::server::CapabilityCheck,
        ) -> Result<(), crate::server::AccessRefusal> {
            Ok(())
        }
        fn invoke_outlet(
            &self,
            _context_id: &str,
            _outlet_id: &str,
            _arguments: serde_json::Value,
        ) -> Result<serde_json::Value, crate::server::OutletInvokeError> {
            Ok(serde_json::json!({"status": "ok"}))
        }
        fn validate_resource_access(
            &self,
            _context_id: &str,
            _resource: crate::server::ResourceKind,
        ) -> Result<(), crate::server::AccessRefusal> {
            Ok(())
        }
        fn context_members(&self, _context_id: &str) -> Result<Vec<MemberInfo>, String> {
            Ok(Vec::new())
        }
        fn context_events(&self, _context_id: &str) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!([]))
        }
    }

    // -- Helper: create shared state for tests --------------------------------

    fn test_config() -> SseConfig {
        let mut config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        config.channel_capacity = 16;
        config
    }

    /// The `sessionId` [`test_state`] makes live.
    const TEST_SESSION: &str = "test-session";

    /// Shared state with the single-session slot ALREADY CLAIMED and
    /// [`TEST_SESSION`] live, standing in for a live `GET /sse` client.
    /// `message_handler` refuses a POST that does not name the live session,
    /// since its response would otherwise be broadcast to no client, or to a
    /// different one.
    fn test_state() -> Arc<AppState<MockProvider>> {
        let state = Arc::new(AppState {
            server: Mutex::new(McpServer::new(MockProvider::default())),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            session_evict: std::sync::Mutex::new(CancellationToken::new()),
            shutdown: CancellationToken::new(),
            live_session: std::sync::Mutex::new(Some(TEST_SESSION.to_owned())),
        });
        state
            .session_slot
            .try_acquire()
            .expect("fresh state must have a free session slot")
            .forget();
        state
    }

    /// The `POST /message` query naming session `id`.
    fn session(id: &str) -> Query<MessageQuery> {
        Query(MessageQuery {
            session_id: Some(id.to_owned()),
        })
    }

    /// Reads an admitted session's stream up to its `endpoint` event and
    /// returns the `sessionId` that event names, with the rest of the stream.
    /// Holding the returned stream keeps the session attached.
    async fn session_id_of(
        response: axum::response::Response,
    ) -> (String, axum::body::BodyDataStream) {
        const KEY: &str = "sessionId=";
        let mut body = response.into_body().into_data_stream();
        let mut seen = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(start) = seen.find(KEY) {
                let rest = &seen[start + KEY.len()..];
                if let Some(end) = rest.find(['\r', '\n']) {
                    return (rest[..end].to_owned(), body);
                }
            }
            let bytes = tokio::time::timeout_at(deadline, body.next())
                .await
                .expect("the session never sent its endpoint event")
                .expect("the session stream ended before its endpoint event")
                .expect("the session stream failed");
            seen.push_str(&String::from_utf8_lossy(&bytes));
        }
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
        let (_router, pump) = router_with_pump(server, &config, None, CancellationToken::new());
        assert!(pump.is_none(), "no event source means no pump");
    }

    /// Posts `body` through the shipped [`message_handler`] as the live
    /// session, and returns the HTTP status it answers.
    async fn post(state: &Arc<AppState<MockProvider>>, body: serde_json::Value) -> StatusCode {
        message_handler(
            State(Arc::clone(state)),
            session(TEST_SESSION),
            body.to_string(),
        )
        .await
        .into_response()
        .status()
    }

    fn initialize_body(id: i64) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": METHOD_INITIALIZE,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test" }
            },
            "id": id
        })
    }

    /// Reads the next broadcast frame as a JSON-RPC response.
    async fn next_response(
        rx: &mut tokio::sync::broadcast::Receiver<(u64, String)>,
    ) -> JsonRpcResponse {
        let (_id, json) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("message_handler broadcast no response")
            .expect("the broadcast channel closed");
        serde_json::from_str(&json).expect("the broadcast frame is not a JSON-RPC response")
    }

    fn nothing_broadcast(rx: &mut tokio::sync::broadcast::Receiver<(u64, String)>) -> bool {
        matches!(
            rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        )
    }

    #[tokio::test]
    async fn message_handler_processes_initialize() {
        let state = test_state();
        let mut rx = state.notifier.tx.subscribe();

        assert_eq!(post(&state, initialize_body(1)).await, StatusCode::ACCEPTED);

        let resp = next_response(&mut rx).await;
        assert!(resp.error.is_none(), "initialize failed: {:?}", resp.error);
        assert!(resp.result.is_some());
        assert_eq!(resp.id, RequestId::Number(1));
        assert!(state.server.lock().await.is_initialized());
    }

    #[tokio::test]
    async fn message_handler_processes_ping() {
        let state = test_state();
        let mut rx = state.notifier.tx.subscribe();

        let ping = serde_json::json!({ "jsonrpc": "2.0", "method": METHOD_PING, "id": 42 });
        assert_eq!(post(&state, ping).await, StatusCode::ACCEPTED);

        let resp = next_response(&mut rx).await;
        assert!(resp.result.is_some());
        assert_eq!(resp.id, RequestId::Number(42));
    }

    /// A notification puts nothing on the stream, even when the server
    /// answers its synthetic request with an error: before `initialize`, the
    /// server rejects every method but `initialize` and `ping`, and
    /// `message_handler` must discard that rejection.
    #[tokio::test]
    async fn message_handler_handles_notification() {
        let state = test_state();
        let mut rx = state.notifier.tx.subscribe();
        let initialized = serde_json::json!({ "jsonrpc": "2.0", "method": METHOD_INITIALIZED });

        assert_eq!(
            post(&state, initialized.clone()).await,
            StatusCode::ACCEPTED
        );
        assert!(
            nothing_broadcast(&mut rx),
            "a notification must not put the server's rejection on the stream"
        );

        assert_eq!(post(&state, initialize_body(0)).await, StatusCode::ACCEPTED);
        next_response(&mut rx).await;
        assert_eq!(post(&state, initialized).await, StatusCode::ACCEPTED);
        assert!(
            nothing_broadcast(&mut rx),
            "a notification must not put a response on the stream"
        );
    }

    #[test]
    fn sse_config_defaults() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let config = SseConfig::new(addr);
        assert_eq!(config.bind_addr, addr);
        assert_eq!(config.channel_capacity, 256);
        assert_eq!(config.retry_ms, DEFAULT_RETRY_MS);
        // 32 random bytes, hex-encoded.
        assert_eq!(config.auth_token.len(), 64);
        assert!(config.auth_token.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn sse_config_draws_a_distinct_token_per_config() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        assert_ne!(
            SseConfig::new(addr).auth_token,
            SseConfig::new(addr).auth_token,
            "two servers must never share a bearer token"
        );
    }

    #[test]
    fn sse_config_debug_redacts_the_bearer_token() {
        let config = SseConfig::new("127.0.0.1:3000".parse().unwrap());
        let printed = format!("{config:?}");
        assert!(
            !printed.contains(&config.auth_token),
            "Debug output carried the bearer token: {printed}"
        );
        assert!(printed.contains("auth_token: \"<redacted>\""), "{printed}");
        assert!(printed.contains("127.0.0.1:3000"), "{printed}");
    }

    #[tokio::test]
    async fn send_notification_broadcasts_to_receivers() {
        let state = test_state();
        let mut rx = state.notifier.tx.subscribe();

        let notif = McpServer::<MockProvider>::tools_list_changed_notification();
        let count = state.notifier.notify(&state.server.lock().await, &notif);
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
        let count = state.notifier.notify(&state.server.lock().await, &notif);
        assert_eq!(count, 0);
    }

    // -- End-to-end subscription delivery -------------------------------------

    /// Builds an initialized server with a wired event source, subscribed to
    /// `uri`.
    fn subscribed_server(
        uri: &str,
        rx: broadcast::Receiver<(String, ContextEvent)>,
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
    /// nothing.
    #[tokio::test]
    async fn subscribe_then_event_delivers_resources_updated() {
        let (event_tx, event_rx) = broadcast::channel::<(String, ContextEvent)>(16);

        // A client initializes and subscribes to the context's event stream.
        let (server, pump_source) = subscribed_server("scp://ctx_a/events", event_rx);

        let state = Arc::new(AppState {
            server: Mutex::new(server),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            session_evict: std::sync::Mutex::new(CancellationToken::new()),
            shutdown: CancellationToken::new(),
            live_session: std::sync::Mutex::new(None),
        });

        // A client attaches to the SSE stream.
        let mut client = state.notifier.tx.subscribe();

        let pump = tokio::spawn(pump_events(Arc::clone(&state), pump_source.into_receiver()));

        // The runtime emits a context event.
        event_tx
            .send((
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
        let (event_tx, event_rx) = broadcast::channel::<(String, ContextEvent)>(16);

        let (server, pump_source) = McpServer::with_event_source(MockProvider::default(), event_rx);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            session_evict: std::sync::Mutex::new(CancellationToken::new()),
            shutdown: CancellationToken::new(),
            live_session: std::sync::Mutex::new(None),
        });

        let mut client = state.notifier.tx.subscribe();
        let pump = tokio::spawn(pump_events(Arc::clone(&state), pump_source.into_receiver()));

        event_tx
            .send((
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

        let held = state.server.lock().await;
        let id1 = state.notifier.broadcast(&held, "msg-1".to_owned());
        let id2 = state.notifier.broadcast(&held, "msg-2".to_owned());
        drop(held);

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
        let bundle = McpServerForTransport(TransportBundle::Unwired(server));
        let task = tokio::spawn(async move { run_sse(bundle, config, run_handle).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.shutdown();

        let result = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert!(result.is_ok(), "server should shut down within timeout");
        assert!(result.unwrap().unwrap().is_ok());
    }

    /// Shutdown must end an attached session's stream. Axum's graceful
    /// shutdown waits for in-flight responses, and an SSE response is in
    /// flight until its stream ends, so a stream that ignored the signal would
    /// keep `run_sse` from returning and keep the pump running against a
    /// server its host believes has stopped.
    #[tokio::test]
    async fn run_sse_shuts_down_with_a_session_attached() {
        let (event_tx, event_rx) = broadcast::channel::<(String, ContextEvent)>(16);
        let (server, pump) = McpServer::with_event_source(MockProvider::default(), event_rx);
        let bundle = McpServerForTransport(TransportBundle::Wired(server, pump));
        // Reserve a free port, then hand it to `run_sse`, which binds its own
        // listener and does not report the port it bound.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut config = SseConfig::new(addr);
        config.auth_token = "shutdown-secret".to_owned();
        let handle = ShutdownHandle::new();
        let task = tokio::spawn(run_sse(bundle, config, handle.clone()));

        // Attach a session over a real connection; its endpoint event proves
        // the response stream is open.
        let conn = attach_session(addr, "shutdown-secret").await;
        assert_pump_consumes(&event_tx).await;

        handle.shutdown();

        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("run_sse must return while a session is attached");
        assert!(result.unwrap().is_ok());
        // `run_sse` returning drops its `AbortOnDrop` pump guard, and task
        // abortion completes asynchronously; poll until the pump's receiver
        // is gone.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while event_tx.receiver_count() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the pump must stop when run_sse returns"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        drop(conn);
    }

    /// Proves a spawned pump is draining `event_tx`: sends one event and waits
    /// until no receiver still holds it queued. The pump's receiver exists from
    /// `McpServer::with_event_source` whether or not anything spawns the pump,
    /// so `receiver_count()` cannot tell a running pump from an unspawned one;
    /// an unspawned receiver leaves the event queued and fails this check.
    async fn assert_pump_consumes(event_tx: &broadcast::Sender<(String, ContextEvent)>) {
        event_tx
            .send((
                "ctx_a".to_owned(),
                ContextEvent::ContentKeysRotated { reason: None },
            ))
            .expect("the pump's receiver must exist");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !event_tx.is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "the pump must be running: its event stayed queued"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Connects to the `run_sse` server at `addr`, opens `GET /sse` with
    /// `Connection: close`, and returns the connection once the session's
    /// `endpoint` event has arrived.
    async fn attach_session(addr: SocketAddr, token: &str) -> tokio::net::TcpStream {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut conn = None;
        for _ in 0..100 {
            if let Ok(stream) = tokio::net::TcpStream::connect(addr).await {
                conn = Some(stream);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut conn = conn.expect("run_sse never started listening");
        conn.write_all(
            format!(
                "GET /sse HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\
                 Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        tokio::time::timeout(Duration::from_secs(5), async {
            while !String::from_utf8_lossy(&seen).contains("event: endpoint") {
                let n = conn.read(&mut buf).await.unwrap();
                assert!(n > 0, "the SSE connection closed before its endpoint event");
                seen.extend_from_slice(&buf[..n]);
            }
        })
        .await
        .expect("the SSE session never received its endpoint event");
        conn
    }

    // -- Auth middleware -------------------------------------------------------

    #[tokio::test]
    async fn router_with_auth_builds_successfully() {
        let server = McpServer::new(MockProvider::default());
        let mut config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        config.auth_token = "secret-token".to_owned();
        let (_router, pump) = router_with_pump(server, &config, None, CancellationToken::new());
        assert!(pump.is_none(), "no event source means no pump");
    }

    // -- Auth middleware integration tests ------------------------------------

    /// Helper: build an authenticated router (`auth_token` = "test-secret").
    fn auth_router() -> Router {
        let server = McpServer::new(MockProvider::default());
        let mut config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        config.auth_token = "test-secret".to_owned();
        router_with_pump(server, &config, None, CancellationToken::new()).0
    }

    /// Helper: a request builder that presents the token `auth_router`
    /// expects.
    fn authed() -> axum::http::request::Builder {
        Request::builder().header("Authorization", "Bearer test-secret")
    }

    // -- Single-session admission --------------------------------------------

    /// An `McpServer` *is* one MCP session — one `initialized` flag, one
    /// negotiated capability set, one subscription registry — and every
    /// server→client message goes out on one shared broadcast. Two live
    /// clients would silently share all of that, so a new `GET /sse` evicts
    /// the live session instead of multiplexing.
    ///
    /// The first client here stands in for a peer that vanished without a
    /// FIN or RST: something keeps polling its body and no write ever fails,
    /// so only eviction can end it. Refusing the reconnect instead would lock
    /// the token holder out until TCP gave up on the dead connection.
    #[tokio::test]
    async fn new_sse_admission_evicts_the_live_session() {
        use tower::ServiceExt;

        let router = auth_router();

        let first = router
            .clone()
            .oneshot(authed().uri("/sse").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let (first_id, mut first_body) = session_id_of(first).await;
        // Drain the first body the way hyper does for a connection whose
        // writes keep succeeding.
        let drained =
            tokio::spawn(async move { while let Some(Ok(_)) = first_body.next().await {} });

        let second = tokio::time::timeout(
            Duration::from_secs(10),
            router
                .clone()
                .oneshot(authed().uri("/sse").body(Body::empty()).unwrap()),
        )
        .await
        .expect("admission must not hang on the evicted session")
        .unwrap();
        assert_eq!(
            second.status(),
            StatusCode::OK,
            "a reconnect must evict the stale session, not be refused"
        );
        tokio::time::timeout(Duration::from_secs(5), drained)
            .await
            .expect("the evicted session's stream must end")
            .unwrap();

        let (second_id, second) = session_id_of(second).await;
        assert_ne!(
            first_id, second_id,
            "each admission mints its own sessionId"
        );

        // The evicted client can still reach the server, but its POSTs must not
        // run against the session that replaced it: they would cancel the new
        // client's subscriptions and put its own responses on the new client's
        // stream.
        let post = |id: String| {
            let ping = serde_json::json!({"jsonrpc": "2.0", "method": "ping", "id": 1}).to_string();
            router.clone().oneshot(
                authed()
                    .method("POST")
                    .uri(format!("/message?sessionId={id}"))
                    .body(Body::from(ping))
                    .unwrap(),
            )
        };
        assert_eq!(
            post(first_id).await.unwrap().status(),
            StatusCode::CONFLICT,
            "a POST from the evicted session must be refused"
        );
        // The new session owns the slot: a POST naming it is accepted into it.
        assert_eq!(
            post(second_id).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
        drop(second);
    }

    /// A POST that reaches the server lock after its stream has dropped, but
    /// before the dropped guard's reset task has run, must be refused. The
    /// reset task still holds the session permit in that interval, so the
    /// permit count alone would report a client attached, and the POST would
    /// run against the session and return `202 Accepted` for a response no
    /// receiver exists to deliver.
    #[tokio::test]
    async fn post_after_its_stream_dropped_is_refused_while_the_reset_is_pending() {
        let state = Arc::new(AppState {
            server: Mutex::new(McpServer::new(MockProvider::default())),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            session_evict: std::sync::Mutex::new(CancellationToken::new()),
            shutdown: CancellationToken::new(),
            live_session: std::sync::Mutex::new(None),
        });
        let admitted = sse_handler(State(Arc::clone(&state))).await;
        assert_eq!(admitted.status(), StatusCode::OK);
        let (id, stream) = session_id_of(admitted).await;

        // Hold the server lock and queue the POST on it while the stream is
        // still attached, so the POST acquires the lock before the reset task
        // the stream's drop spawns (tokio's mutex is FIFO).
        let lock = state.server.lock().await;
        let ping = serde_json::json!({"jsonrpc": "2.0", "method": METHOD_PING, "id": 1});
        let handler = tokio::spawn(message_handler(
            State(Arc::clone(&state)),
            session(&id),
            ping.to_string(),
        ));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        drop(stream);
        assert_eq!(
            state.session_slot.available_permits(),
            0,
            "the pending reset task must still hold the permit"
        );

        drop(lock);
        let status = handler.await.unwrap().into_response().status();
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a POST whose stream is gone must be refused, not accepted and dropped"
        );
    }

    /// The newest admission wins when admissions queue behind a session that
    /// has not yet released the slot. Admission B arrives first and waits;
    /// admission C arrives while B is still waiting. C must supersede B, not
    /// cancel the already-cancelled token of the live session and then time
    /// out behind B.
    #[tokio::test]
    async fn newest_of_two_waiting_admissions_takes_the_slot() {
        use tower::ServiceExt;

        let router = auth_router();

        // A holds the slot. Its body is never polled, so its stream cannot
        // observe eviction and A keeps the permit until it is dropped.
        let first = router
            .clone()
            .oneshot(authed().uri("/sse").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let admit = |router: Router| {
            tokio::spawn(async move {
                router
                    .oneshot(authed().uri("/sse").body(Body::empty()).unwrap())
                    .await
                    .unwrap()
            })
        };
        let second = admit(router.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let third = admit(router.clone());

        // C's arrival supersedes B, which gives up without waiting for A.
        let second = tokio::time::timeout(Duration::from_secs(2), second)
            .await
            .expect("a superseded admission must give up at once")
            .unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);

        // A's stream ends; C takes the slot well inside EVICTION_WAIT.
        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(2), third)
            .await
            .expect("the newest admission must take the freed slot")
            .unwrap();
        assert_eq!(
            third.status(),
            StatusCode::OK,
            "the newest admission must win the slot"
        );
        drop(third);
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

    /// The configuration every bridge builds (`SseConfig::new` on a loopback
    /// address, no field overwritten) must reject a request that carries no
    /// bearer token. Before the token became mandatory, `SseConfig::new` left
    /// authentication off, no bridge turned it on, and any local process could
    /// claim the session and act as the agent identity.
    #[tokio::test]
    async fn default_config_rejects_unauthenticated_sse() {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        let router = router_with_pump(server, &config, None, CancellationToken::new()).0;
        let req = Request::builder().uri("/sse").body(Body::empty()).unwrap();

        let status = request_status(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn default_config_rejects_unauthenticated_post() {
        let server = McpServer::new(MockProvider::default());
        let config = SseConfig::new("127.0.0.1:0".parse().unwrap());
        let router = router_with_pump(server, &config, None, CancellationToken::new()).0;
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

    /// `message_handler` draws each notification's synthetic request id from
    /// the event-id counter, so two notifications take two distinct ids and
    /// broadcast nothing.
    #[tokio::test]
    async fn synthetic_notification_ids_are_unique() {
        let state = test_state();
        let mut rx = state.notifier.tx.subscribe();
        assert_eq!(post(&state, initialize_body(0)).await, StatusCode::ACCEPTED);
        next_response(&mut rx).await;

        let before = state.notifier.next_event_id.load(Ordering::SeqCst);
        let initialized = serde_json::json!({ "jsonrpc": "2.0", "method": METHOD_INITIALIZED });
        for _ in 0..2 {
            assert_eq!(
                post(&state, initialized.clone()).await,
                StatusCode::ACCEPTED
            );
        }
        assert_eq!(
            state.notifier.next_event_id.load(Ordering::SeqCst),
            before + 2,
            "each notification must draw exactly one fresh id"
        );
        assert!(nothing_broadcast(&mut rx));
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
        let (_event_tx, event_rx) = broadcast::channel::<(String, ContextEvent)>(16);
        // Wired server: `resources/subscribe` must be accepted for the second
        // session's registration to exist at all.
        let (server, _pump) = McpServer::with_event_source(MockProvider::default(), event_rx);
        let state = Arc::new(AppState {
            server: Mutex::new(server),
            notifier: McpNotifier::new(&test_config()),
            retry_ms: DEFAULT_RETRY_MS,
            session_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            session_evict: std::sync::Mutex::new(CancellationToken::new()),
            shutdown: CancellationToken::new(),
            live_session: std::sync::Mutex::new(None),
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
        let (second_id, second) = session_id_of(second).await;

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
            let status = message_handler(
                State(Arc::clone(&state)),
                session(&second_id),
                body.to_string(),
            )
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

        let router = auth_router();

        // Client A attaches and completes an initialize round-trip; its
        // JSON-RPC response goes out on the SSE broadcast.
        let first = router
            .clone()
            .oneshot(authed().uri("/sse").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let (first_id, first) = session_id_of(first).await;

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
                authed()
                    .method("POST")
                    .uri(format!("/message?sessionId={first_id}"))
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
                    authed()
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

    /// `message_handler` broadcasts the notifications a `tools/call` queued,
    /// after the call's response. Without the drain, a subscriber to
    /// `scp://{ctx}/events` would not learn that the call appended to the log.
    #[tokio::test]
    async fn post_handler_sends_the_notifications_a_tools_call_queued() {
        let (_event_tx, event_rx) = broadcast::channel::<(String, ContextEvent)>(16);
        let (server, _pump) = subscribed_server("scp://ctx_a/events", event_rx);
        let state = test_state();
        *state.server.lock().await = server;
        let mut rx = state.notifier.tx.subscribe();

        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "ctx_a/send_message", "arguments": {"content": "hi"}},
            "id": 3
        });
        let status = message_handler(
            State(Arc::clone(&state)),
            session(TEST_SESSION),
            call.to_string(),
        )
        .await
        .into_response()
        .status();
        assert_eq!(status, StatusCode::ACCEPTED);

        let (_id, response) = rx.try_recv().expect("the call's response goes out first");
        assert!(response.contains("\"id\":3"), "{response}");
        let (_id, notification) = rx
            .try_recv()
            .expect("the queued notification follows the response");
        assert!(
            notification.contains("notifications/resources/updated")
                && notification.contains("scp://ctx_a/events"),
            "{notification}"
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
    /// What it proves: a `message_handler` that broadcasts before it takes the
    /// server lock turns this test red. It cannot catch a handler that takes
    /// the lock, releases it, and then broadcasts, because that handler also
    /// parks on the lock this test holds. That second ordering fails to
    /// compile instead: [`McpNotifier::broadcast`] and [`McpNotifier::notify`]
    /// take the lock's guard, so neither can run after the guard is dropped.
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
            session(TEST_SESSION),
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
            session_evict: std::sync::Mutex::new(CancellationToken::new()),
            shutdown: CancellationToken::new(),
            live_session: std::sync::Mutex::new(None),
        });

        // A client attaches; the handler subscribes its broadcast receiver.
        let response = sse_handler(State(Arc::clone(&state))).await;
        assert_eq!(response.status(), StatusCode::OK);

        // With the stream unpolled, drive the channel far past its capacity
        // (`test_config` uses 16) so the receiver is deterministically lagged.
        let held = state.server.lock().await;
        for i in 0..64 {
            state.notifier.broadcast(&held, format!("event-{i}"));
        }
        drop(held);

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
    /// the event pump, not detach it, and must end every attached session's
    /// stream. The pump holds the only receiver on the event channel, so its
    /// death is observable as `receiver_count` falling to zero; a detached pump
    /// would hold that receiver forever. axum serves each connection on its own
    /// task, which the abort does not stop, so an attached stream ends only if
    /// the abort cancels it: otherwise it would keep its subscriptions with no
    /// pump left to serve them.
    #[tokio::test]
    async fn aborting_run_sse_tears_down_the_pump() {
        use tokio::io::AsyncReadExt;

        let (event_tx, event_rx) = broadcast::channel::<(String, ContextEvent)>(16);
        let (server, pump) = McpServer::with_event_source(MockProvider::default(), event_rx);
        let bundle = McpServerForTransport(TransportBundle::Wired(server, pump));
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut config = SseConfig::new(addr);
        config.auth_token = "abort-secret".to_owned();

        let task = tokio::spawn(run_sse(bundle, config, ShutdownHandle::new()));
        // `Connection: close`, so the connection closes once the stream ends.
        let mut conn = attach_session(addr, "abort-secret").await;
        assert!(!task.is_finished(), "run_sse exited before it was aborted");
        assert_pump_consumes(&event_tx).await;

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

        // The attached session's stream must end, closing the connection.
        let mut buf = [0u8; 1024];
        tokio::time::timeout(Duration::from_secs(5), async {
            while conn.read(&mut buf).await.unwrap_or(0) > 0 {}
        })
        .await
        .expect("an attached SSE stream outlived the aborted run_sse");
    }
}
