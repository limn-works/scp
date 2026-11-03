//! Relay-side UDP/DTLS listener for constrained devices.
//!
//! [`UdpDtlsListener`] binds a UDP socket, accepts DTLS sessions, and
//! dispatches incoming `MessagePack` datagrams (PUBLISH, QUERY, DELETE) to
//! the shared blob storage backend. No subscription state is maintained for
//! UDP clients -- constrained devices poll via QUERY (section 10.16.1 point 6).
//!
//! # DTLS Session Management
//!
//! The listener tracks concurrent DTLS sessions by remote `SocketAddr`. Each
//! session holds an OpenSSL DTLS stream for encrypted communication. When a
//! new client's initial datagram arrives on the main socket, the listener
//! creates a new connected UDP socket for that client and performs the DTLS
//! accept handshake. All subsequent datagrams from that client are routed
//! through the per-client DTLS session.
//!
//! # Graceful Shutdown
//!
//! The listener respects a [`CancellationToken`] for cooperative shutdown.
//! When cancelled, the accept loop exits and all active sessions are allowed
//! to drain naturally.
//!
//! See ADR-037 in `.docs/adrs/phase-2.md` for the transport binding design.
//! See SCP-262 in `.docs/prds/transport-expansion.json` for the story.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use openssl::ssl::{SslContext, SslMethod};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::dtls::AsyncDtlsSession;
use crate::native::node_proof;
use crate::native::public_records;
use crate::native::server::RelayConfig;
use crate::native::storage::BlobStorage;
use crate::native::storage::QueryCursor;
use crate::relay::push_gate;
use crate::relay::rate_limit::{self, ConnectionTracker, PublishRateLimiter};
use scp_relay_client::{BlobLifetime, ClientMessage, DEFAULT_QUERY_LIMIT, RelayMessage};

/// Configuration for the UDP/DTLS listener.
///
/// Controls the bind address, session management parameters, and rate
/// limiting. The listener shares a [`RelayConfig`] for blob size, TTL, and
/// query limit enforcement.
#[derive(Debug, Clone)]
pub struct UdpDtlsListenerConfig {
    /// Address to bind the UDP socket to.
    pub bind_addr: SocketAddr,

    /// Maximum concurrent DTLS sessions (default: 256).
    ///
    /// Constrained device relays typically handle fewer concurrent clients
    /// than WebSocket/QUIC relays, but must still bound memory usage.
    pub max_sessions: usize,

    /// Maximum concurrent sessions per IP address (default: 10).
    ///
    /// Prevents a single IP from exhausting the entire session table.
    /// Shares the cross-transport connection budget when a shared
    /// `ConnectionTracker` is provided.
    pub max_sessions_per_ip: usize,

    /// Session inactivity timeout (default: 300 seconds / 5 minutes).
    ///
    /// Sessions that have not sent a datagram within this duration are
    /// evicted to free memory. Constrained devices reconnect cheaply via
    /// DTLS session resumption (section 10.16.1 point 3).
    pub session_timeout: Duration,

    /// Maximum datagrams per second per IP address (default: 50).
    ///
    /// Lower than the WebSocket publish rate limit because UDP is
    /// connectionless and easier to spoof.
    pub rate_limit_per_ip: u32,

    /// Receive buffer size in bytes (default: 65535).
    ///
    /// Maximum UDP datagram size. Practical payloads are constrained by
    /// path MTU (~1200 bytes for most networks).
    pub recv_buffer_size: usize,

    /// Interval for session cleanup task (default: 30 seconds).
    pub cleanup_interval: Duration,
}

impl Default for UdpDtlsListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 9443)),
            max_sessions: 256,
            max_sessions_per_ip: 10,
            session_timeout: Duration::from_mins(5),
            rate_limit_per_ip: 50,
            recv_buffer_size: 65535,
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

/// State for a single DTLS session with a remote client.
///
/// Keyed by `SocketAddr` in the session map. The remote address is the
/// the `HashMap` key, not stored redundantly here.
struct DtlsSession {
    /// Last time a datagram was received from this client.
    last_activity: Instant,

    /// The async DTLS session for encrypted communication.
    ///
    /// Wrapped in `Arc` so that the per-client recv loop can hold a reference
    /// without keeping the session map's `RwLock` held during blocking
    /// DTLS operations.
    dtls: Arc<AsyncDtlsSession>,
}

/// The relay-side UDP/DTLS listener.
///
/// Accepts DTLS datagrams from constrained devices and dispatches
/// PUBLISH/QUERY/DELETE operations to the shared blob storage backend.
/// No subscription state is maintained -- constrained devices poll via
/// QUERY at configurable intervals (section 10.16.1 point 6).
///
/// # Construction
///
/// Use [`UdpDtlsListener::new`] to create a listener with a shared storage
/// backend. Call [`start`](UdpDtlsListener::start) to bind the socket and
/// begin accepting datagrams.
///
/// # Examples
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use scp_transport::udp::listener::{UdpDtlsListener, UdpDtlsListenerConfig};
/// use scp_transport::native::server::RelayConfig;
/// use scp_transport::native::storage::InMemoryBlobStorage;
/// use scp_transport::relay::rate_limit::{self, PublishRateLimiter};
/// use scp_transport::relay::push_gate::{LiveRelayUrl, PushReservation};
///
/// let config = UdpDtlsListenerConfig::default();
/// let relay_url = LiveRelayUrl::new(PushReservation::new("wss://relay.example")?);
/// let relay_config = RelayConfig::defaults(relay_url);
/// let storage = Arc::new(InMemoryBlobStorage::new());
/// let rate_limiter = PublishRateLimiter::new(100);
/// let conn_tracker = rate_limit::new_connection_tracker();
/// let listener = UdpDtlsListener::new(
///     config, relay_config, storage, rate_limiter, conn_tracker,
/// );
///
/// let (handle, addr) = listener.start().await?;
/// // ... listener is now accepting DTLS datagrams on `addr` ...
/// handle.shutdown();
/// ```
pub struct UdpDtlsListener<S: BlobStorage> {
    /// Listener-specific configuration.
    config: UdpDtlsListenerConfig,

    /// Shared relay configuration for blob size, TTL, and query limits.
    relay_config: RelayConfig,

    /// Shared blob storage backend (same instance as WebSocket/QUIC handlers).
    storage: Arc<S>,

    /// OpenSSL SSL context configured for DTLS server mode.
    ssl_ctx: SslContext,

    /// Shared publish rate limiter (same instance as WebSocket/QUIC handlers).
    publish_rate_limiter: PublishRateLimiter,

    /// Shared connection tracker (same instance as WebSocket/QUIC handlers).
    connection_tracker: ConnectionTracker,
}

/// Handle for gracefully shutting down the UDP/DTLS listener.
///
/// Call [`shutdown`](Self::shutdown) to signal the listener to stop
/// accepting new datagrams. In-flight operations drain naturally.
#[derive(Debug, Clone)]
pub struct UdpDtlsShutdownHandle {
    token: CancellationToken,
}

impl UdpDtlsShutdownHandle {
    /// Signals the UDP/DTLS listener to stop accepting datagrams.
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// Returns `true` if shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.token.is_cancelled()
    }
}

impl<S: BlobStorage + 'static> UdpDtlsListener<S> {
    /// Creates a new UDP/DTLS listener.
    ///
    /// The listener shares the blob storage backend with other relay
    /// transport handlers (WebSocket, QUIC). The `relay_config` enforces
    /// consistent blob size, TTL, and query limit constraints across all
    /// transports.
    ///
    /// # Errors
    ///
    /// Returns an error string if the OpenSSL DTLS server context cannot be
    /// initialized.
    pub fn new(
        config: UdpDtlsListenerConfig,
        relay_config: RelayConfig,
        storage: Arc<S>,
        publish_rate_limiter: PublishRateLimiter,
        connection_tracker: ConnectionTracker,
    ) -> Result<Self, String> {
        let ssl_ctx = build_dtls_server_context()
            .map_err(|e| format!("failed to build DTLS server context: {e}"))?;

        Ok(Self {
            config,
            relay_config,
            storage,
            ssl_ctx,
            publish_rate_limiter,
            connection_tracker,
        })
    }

    /// Starts the UDP/DTLS listener and returns a shutdown handle and bound address.
    ///
    /// Binds the UDP socket, spawns the datagram receive loop and session
    /// cleanup task, and returns immediately.
    ///
    /// # Errors
    ///
    /// Returns an error string if the UDP socket cannot be bound.
    #[allow(clippy::unused_async)] // Async for API consistency with other listeners.
    pub async fn start(&self) -> Result<(UdpDtlsShutdownHandle, SocketAddr), String> {
        // Bind with SO_REUSEPORT so per-client DTLS sockets can share the
        // same local address. The kernel routes datagrams from connected
        // clients to their respective connected sockets.
        let socket = create_listener_socket(self.config.bind_addr)?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| format!("failed to get local address: {e}"))?;

        info!(
            bind_addr = %local_addr,
            max_sessions = self.config.max_sessions,
            session_timeout_secs = self.config.session_timeout.as_secs(),
            "UDP/DTLS listener started"
        );

        let token = CancellationToken::new();
        let socket = Arc::new(socket);

        let sessions: Arc<RwLock<HashMap<SocketAddr, DtlsSession>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Spawn session cleanup task.
        {
            let sessions = Arc::clone(&sessions);
            let timeout = self.config.session_timeout;
            let interval = self.config.cleanup_interval;
            let cleanup_conn_tracker = Arc::clone(&self.connection_tracker);
            let cleanup_token = token.clone();

            tokio::spawn(async move {
                session_cleanup_task(
                    sessions,
                    cleanup_conn_tracker,
                    timeout,
                    interval,
                    cleanup_token,
                )
                .await;
            });
        }

        // Spawn the main datagram receive loop.
        {
            let socket = Arc::clone(&socket);
            let sessions = Arc::clone(&sessions);
            let storage = Arc::clone(&self.storage);
            let relay_config = self.relay_config.clone();
            let listener_config = self.config.clone();
            let rate_limiter = self.publish_rate_limiter.clone();
            let conn_tracker = Arc::clone(&self.connection_tracker);
            let recv_token = token.clone();
            let ssl_ctx = self.ssl_ctx.clone();

            tokio::spawn(async move {
                datagram_recv_loop(
                    socket,
                    sessions,
                    storage,
                    relay_config,
                    listener_config,
                    rate_limiter,
                    conn_tracker,
                    recv_token,
                    ssl_ctx,
                )
                .await;
            });
        }

        Ok((UdpDtlsShutdownHandle { token }, local_addr))
    }
}

// ---------------------------------------------------------------------------
// Datagram receive loop (split into receive + dispatch for clippy line count)
// ---------------------------------------------------------------------------

/// Shared context passed to the dispatch function so that `datagram_recv_loop`
/// stays under the 100-line clippy threshold.
struct DispatchCtx<S: BlobStorage> {
    socket: Arc<UdpSocket>,
    sessions: Arc<RwLock<HashMap<SocketAddr, DtlsSession>>>,
    storage: Arc<S>,
    relay_config: RelayConfig,
    listener_config: UdpDtlsListenerConfig,
    rate_limiter: PublishRateLimiter,
    conn_tracker: ConnectionTracker,
    ssl_ctx: SslContext,
    /// Atomic counter for sessions currently in DTLS handshake but not yet
    /// inserted into `sessions`. Prevents TOCTOU on the global session limit:
    /// we increment before the handshake and decrement on failure.
    pending_sessions: Arc<AtomicUsize>,
}

/// Main datagram receive loop.
///
/// Receives UDP datagrams on the main socket. For new clients, the listener
/// creates a per-client connected UDP socket and performs a DTLS accept
/// handshake. For existing clients with established DTLS sessions, incoming
/// datagrams are forwarded to the per-client DTLS session for decryption.
///
/// Since DTLS sessions use their own per-client connected sockets, the main
/// socket only handles initial `ClientHello` messages from new clients.
/// Established sessions receive datagrams directly on their connected sockets.
#[allow(clippy::too_many_arguments)]
async fn datagram_recv_loop<S: BlobStorage + 'static>(
    socket: Arc<UdpSocket>,
    sessions: Arc<RwLock<HashMap<SocketAddr, DtlsSession>>>,
    storage: Arc<S>,
    relay_config: RelayConfig,
    listener_config: UdpDtlsListenerConfig,
    rate_limiter: PublishRateLimiter,
    conn_tracker: ConnectionTracker,
    token: CancellationToken,
    ssl_ctx: SslContext,
) {
    let ctx = DispatchCtx {
        socket,
        sessions,
        storage,
        relay_config,
        listener_config,
        rate_limiter,
        conn_tracker,
        ssl_ctx,
        pending_sessions: Arc::new(AtomicUsize::new(0)),
    };

    let mut buf = vec![0u8; ctx.listener_config.recv_buffer_size];

    loop {
        let recv_result = tokio::select! {
            biased;
            () = token.cancelled() => {
                info!("UDP/DTLS listener shutting down");
                break;
            }
            result = ctx.socket.recv_from(&mut buf) => result,
        };

        let (n, remote_addr) = match recv_result {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "UDP recv_from failed");
                continue;
            }
        };

        let datagram = buf[..n].to_vec();
        dispatch_datagram(&ctx, datagram, remote_addr).await;
    }
}

/// Processes a single received datagram: rate-limiting, DTLS session
/// management, decryption, deserialization, validation, and handler dispatch.
async fn dispatch_datagram<S: BlobStorage + 'static>(
    ctx: &DispatchCtx<S>,
    datagram: Vec<u8>,
    remote_addr: SocketAddr,
) {
    // Rate-limit per IP (shared across all transports).
    if !ctx.rate_limiter.check(remote_addr.ip()).await {
        debug!(remote = %remote_addr, "UDP rate limit exceeded, dropping datagram");
        return;
    }

    // Check if we have an existing DTLS session for this client.
    let has_session = ctx.sessions.read().await.contains_key(&remote_addr);

    if !has_session {
        // New client -- attempt DTLS accept. `handle_new_client` checks the
        // session limit and inserts the session under a single write lock,
        // preventing TOCTOU on the limit check.
        if !handle_new_client(ctx, datagram, remote_addr).await {
            return;
        }
        // After successful DTLS accept, the session is now running its own
        // receive loop on the per-client socket. The initial datagram was
        // part of the DTLS handshake and has been consumed.
        return;
    }

    // For existing sessions: the per-client DTLS session handles its own
    // datagrams on its connected socket. If we receive a datagram for an
    // existing session on the main socket, it may be a retransmitted
    // handshake message or a stale packet -- drop it.
    debug!(
        remote = %remote_addr,
        "received datagram on main socket for existing DTLS session, ignoring"
    );
}

/// Handles a new client connection: creates a per-client socket on the same
/// local address (via `SO_REUSEPORT`), performs DTLS accept, and spawns a
/// per-client receive loop.
///
/// # DTLS Server Socket Strategy
///
/// The standard DTLS server pattern for multiplexing multiple clients on a
/// single port requires per-client sockets bound to the **same** local
/// address as the main listener socket, using `SO_REUSEPORT`. The kernel
/// routes datagrams from a connected client to the connected socket (which
/// has higher routing priority than the unconnected main socket).
///
/// The initial `ClientHello` was already consumed from the main socket.
/// DTLS has built-in retransmission: the client will retransmit the
/// `ClientHello` after a timeout (typically 1 second). The retransmitted
/// `ClientHello` is routed by the kernel to the per-client connected
/// socket, allowing the DTLS accept to proceed.
///
/// Returns `true` if the DTLS session was successfully established.
async fn handle_new_client<S: BlobStorage + 'static>(
    ctx: &DispatchCtx<S>,
    _initial_datagram: Vec<u8>,
    remote_addr: SocketAddr,
) -> bool {
    // Check global session limit using atomic counter to avoid TOCTOU.
    // We include pending (mid-handshake) sessions in the count so that
    // concurrent handshakes cannot exceed the limit.
    {
        let current_sessions = ctx.sessions.read().await.len();
        let pending = ctx.pending_sessions.load(Ordering::Acquire);
        if current_sessions + pending >= ctx.listener_config.max_sessions {
            warn!(
                remote = %remote_addr,
                active_sessions = current_sessions,
                pending_sessions = pending,
                max = ctx.listener_config.max_sessions,
                "max DTLS sessions reached, rejecting new client"
            );
            // Silent drop: do not send plaintext error responses before DTLS
            // is established. Responding in cleartext leaks protocol identity
            // and internal state to unauthenticated peers (SEC-002).
            return false;
        }
    }
    // Reserve a slot before the DTLS handshake. Decrement on failure.
    ctx.pending_sessions.fetch_add(1, Ordering::AcqRel);

    // Check per-IP connection budget (shared across WS/QUIC/UDP).
    // Uses atomic check+increment under a single write lock (no TOCTOU).
    if let Err(e) = rate_limit::register_connection(
        &ctx.conn_tracker,
        remote_addr.ip(),
        ctx.listener_config.max_sessions_per_ip,
        None,
    )
    .await
    {
        ctx.pending_sessions.fetch_sub(1, Ordering::AcqRel);
        warn!(
            remote = %remote_addr,
            current = e.current,
            max = e.max,
            "per-IP connection limit exceeded, rejecting new client"
        );
        // Silent drop: do not send plaintext error responses before DTLS
        // is established (SEC-002).
        return false;
    }

    // Create a per-client connected UDP socket on the same local address
    // using SO_REUSEPORT. The kernel routes datagrams from this specific
    // client to the connected socket rather than the main listener socket.
    let local_addr = match ctx.socket.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!(error = %e, "failed to get listener local address");
            ctx.pending_sessions.fetch_sub(1, Ordering::AcqRel);
            rate_limit::unregister_connection(&ctx.conn_tracker, remote_addr.ip()).await;
            return false;
        }
    };

    let client_socket = match create_reuse_port_socket(local_addr, remote_addr) {
        Ok(s) => s,
        Err(e) => {
            warn!(remote = %remote_addr, error = %e, "failed to create per-client socket");
            ctx.pending_sessions.fetch_sub(1, Ordering::AcqRel);
            rate_limit::unregister_connection(&ctx.conn_tracker, remote_addr.ip()).await;
            return false;
        }
    };

    let ssl_ctx = ctx.ssl_ctx.clone();

    // Perform DTLS accept on the per-client socket (blocking).
    // The client will retransmit the ClientHello (DTLS retransmission),
    // which is now routed to this connected socket by the kernel.
    let dtls = match AsyncDtlsSession::accept(ssl_ctx, client_socket).await {
        Ok(session) => session,
        Err(e) => {
            debug!(remote = %remote_addr, error = %e, "DTLS accept failed for new client");
            // Release the pending slot and per-IP registration on failure.
            ctx.pending_sessions.fetch_sub(1, Ordering::AcqRel);
            rate_limit::unregister_connection(&ctx.conn_tracker, remote_addr.ip()).await;
            return false;
        }
    };

    debug!(remote = %remote_addr, "DTLS session accepted");

    // Store the session and spawn the recv loop.
    let session = DtlsSession {
        last_activity: Instant::now(),
        dtls: Arc::new(dtls),
    };

    ctx.sessions.write().await.insert(remote_addr, session);
    // Handshake succeeded — release the pending slot (session is now tracked).
    ctx.pending_sessions.fetch_sub(1, Ordering::AcqRel);

    // Spawn a per-client receive loop that reads from the DTLS session.
    let sessions = Arc::clone(&ctx.sessions);
    let storage = Arc::clone(&ctx.storage);
    let relay_config = ctx.relay_config.clone();
    let rate_limiter = ctx.rate_limiter.clone();
    let conn_tracker = Arc::clone(&ctx.conn_tracker);
    tokio::spawn(async move {
        per_client_recv_loop(
            remote_addr,
            sessions,
            storage,
            relay_config,
            rate_limiter,
            conn_tracker,
        )
        .await;
    });

    true
}

/// Sets `SO_REUSEPORT` on a socket (Unix only; no-op on Windows).
///
/// `SO_REUSEPORT` allows multiple sockets to bind to the same address:port.
/// The kernel routes datagrams to connected sockets when available (more
/// specific match), enabling per-client DTLS multiplexing.
fn set_reuse_port(socket: &socket2::Socket) -> Result<(), std::io::Error> {
    #[cfg(not(windows))]
    {
        socket.set_reuse_port(true)?;
    }
    #[cfg(windows)]
    {
        let _ = socket;
    }
    Ok(())
}

/// Creates the main listener `tokio::net::UdpSocket` with `SO_REUSEPORT`.
///
/// `SO_REUSEPORT` is required so that per-client DTLS sockets can be bound
/// to the same local address. Without it, the per-client bind would fail
/// with `EADDRINUSE`.
fn create_listener_socket(bind_addr: SocketAddr) -> Result<UdpSocket, String> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if bind_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("failed to create listener socket: {e}"))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| format!("failed to set SO_REUSEADDR on listener: {e}"))?;

    set_reuse_port(&socket).map_err(|e| format!("failed to set SO_REUSEPORT on listener: {e}"))?;

    socket
        .set_nonblocking(true)
        .map_err(|e| format!("failed to set non-blocking on listener: {e}"))?;

    socket
        .bind(&bind_addr.into())
        .map_err(|e| format!("failed to bind listener socket to {bind_addr}: {e}"))?;

    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
        .map_err(|e| format!("failed to convert to tokio UdpSocket: {e}"))
}

/// Creates a `std::net::UdpSocket` bound to the same local address as the
/// listener (via `SO_REUSEPORT`) and connected to the given remote address.
///
/// The kernel routes datagrams from the connected remote to this socket
/// instead of the main listener socket, enabling per-client DTLS sessions
/// on a shared port.
fn create_reuse_port_socket(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Result<std::net::UdpSocket, String> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if local_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("failed to create socket: {e}"))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| format!("failed to set SO_REUSEADDR: {e}"))?;

    // SO_REUSEPORT is required on macOS/Linux to bind multiple sockets to
    // the same address. The kernel routes packets from connected clients to
    // their respective connected sockets.
    set_reuse_port(&socket).map_err(|e| format!("failed to set SO_REUSEPORT: {e}"))?;

    socket
        .bind(&local_addr.into())
        .map_err(|e| format!("failed to bind per-client socket to {local_addr}: {e}"))?;

    socket
        .connect(&remote_addr.into())
        .map_err(|e| format!("failed to connect per-client socket to {remote_addr}: {e}"))?;

    Ok(socket.into())
}

/// Per-client receive loop: reads DTLS-decrypted datagrams from the client's
/// DTLS session and dispatches operations.
///
/// The DTLS session `Arc` is extracted from the session map under a brief read
/// lock, then the lock is dropped before the blocking `recv()` call. This
/// prevents read-lock starvation of write operations (session insert, cleanup).
#[allow(clippy::too_many_arguments)]
async fn per_client_recv_loop<S: BlobStorage + 'static>(
    remote_addr: SocketAddr,
    sessions: Arc<RwLock<HashMap<SocketAddr, DtlsSession>>>,
    storage: Arc<S>,
    relay_config: RelayConfig,
    rate_limiter: PublishRateLimiter,
    conn_tracker: ConnectionTracker,
) {
    // Extract the DTLS session Arc once — it remains valid for the session's
    // lifetime. The session map read lock is released immediately.
    let session_map = sessions.read().await;
    let Some(session) = session_map.get(&remote_addr) else {
        drop(session_map);
        debug!(remote = %remote_addr, "DTLS session removed before recv loop started");
        rate_limit::unregister_connection(&conn_tracker, remote_addr.ip()).await;
        return;
    };
    let dtls = Arc::clone(&session.dtls);
    drop(session_map);

    loop {
        // Read a decrypted datagram. No session map lock is held during this
        // potentially long-blocking call.
        let recv_result = dtls.recv().await;

        let datagram = match recv_result {
            Ok(data) => data,
            Err(e) => {
                debug!(remote = %remote_addr, error = %e, "DTLS recv failed, closing session");
                sessions.write().await.remove(&remote_addr);
                rate_limit::unregister_connection(&conn_tracker, remote_addr.ip()).await;
                break;
            }
        };

        // Update last activity timestamp.
        {
            let mut session_map = sessions.write().await;
            if let Some(session) = session_map.get_mut(&remote_addr) {
                session.last_activity = Instant::now();
            }
        }

        // Rate-limit publishes per IP (shared across all transports).
        // Applied here in addition to `dispatch_datagram` (which only covers
        // the initial datagram on the main socket) so that established
        // sessions are also rate-limited.
        if !rate_limiter.check(remote_addr.ip()).await {
            debug!(remote = %remote_addr, "UDP per-client rate limit exceeded, dropping datagram");
            continue;
        }

        // Deserialize the client message.
        // `ClientMessage::from_bytes` rejects payloads exceeding `MAX_MESSAGE_SIZE`
        // before invoking the MessagePack deserializer, preventing allocation bombs.
        let client_msg: ClientMessage = match ClientMessage::from_bytes(&datagram) {
            Ok(msg) => msg,
            Err(e) => {
                debug!(remote = %remote_addr, "failed to deserialize UDP datagram");
                let err = public_records::decode_refusal(&e);
                send_dtls_response(&sessions, &remote_addr, &err).await;
                continue;
            }
        };

        // Validate the message.
        if let Err(e) = client_msg.validate() {
            debug!(remote = %remote_addr, error = %e, "ClientMessage validation failed");
            let err = RelayMessage::Err {
                ref_id: extract_ref_id(&client_msg),
                code: e.code(),
                msg: "request validation failed".to_owned(),
            };
            send_dtls_response(&sessions, &remote_addr, &err).await;
            continue;
        }

        // Dispatch to the appropriate handler.
        dispatch_client_message(
            &sessions,
            &storage,
            &relay_config,
            client_msg,
            remote_addr,
            &rate_limiter,
        )
        .await;
    }
}

/// Routes a validated `ClientMessage` to the appropriate handler.
#[allow(clippy::too_many_arguments)]
async fn dispatch_client_message<S: BlobStorage + 'static>(
    sessions: &Arc<RwLock<HashMap<SocketAddr, DtlsSession>>>,
    storage: &Arc<S>,
    relay_config: &RelayConfig,
    msg: ClientMessage,
    remote_addr: SocketAddr,
    rate_limiter: &PublishRateLimiter,
) {
    match msg {
        ClientMessage::Publish {
            ref_id,
            routing_id,
            recipient_hint,
            lifetime,
            blob,
        } => {
            handle_udp_publish(
                ref_id,
                routing_id,
                recipient_hint,
                lifetime,
                &blob,
                sessions,
                &remote_addr,
                storage,
                relay_config,
            )
            .await;
        }
        ClientMessage::Query {
            ref_id,
            routing_id,
            since,
            after_blob,
            limit,
            proof_nonce,
        } => {
            handle_udp_query(
                ref_id,
                routing_id,
                since,
                after_blob,
                limit,
                proof_nonce,
                sessions,
                &remote_addr,
                storage,
                relay_config,
            )
            .await;
        }
        ClientMessage::Delete { ref_id, blob_id } => {
            handle_udp_delete(
                ref_id,
                blob_id,
                sessions,
                &remote_addr,
                storage,
                relay_config,
                rate_limiter,
            )
            .await;
        }
        ClientMessage::Subscribe { ref_id, .. } => {
            let err = RelayMessage::Err {
                ref_id,
                code: 405,
                msg: "SUBSCRIBE is not supported over UDP/DTLS -- \
                      constrained devices should poll via QUERY \
                      (see spec section 10.16.1 point 6)"
                    .to_string(),
            };
            send_dtls_response(sessions, &remote_addr, &err).await;
        }
        ClientMessage::Unsubscribe { ref_id, .. } => {
            let err = RelayMessage::Err {
                ref_id,
                code: 405,
                msg: "UNSUBSCRIBE is not supported over UDP/DTLS -- \
                      no subscriptions exist to unsubscribe from"
                    .to_string(),
            };
            send_dtls_response(sessions, &remote_addr, &err).await;
        }
        ClientMessage::Ping { ts } => {
            send_dtls_response(sessions, &remote_addr, &RelayMessage::Pong { ts }).await;
        }
        ClientMessage::Ack { .. } => { /* fire-and-forget */ }
        ClientMessage::BridgeRegister { ref_id, .. } | ClientMessage::BridgeData { ref_id, .. } => {
            let err = RelayMessage::Err {
                ref_id,
                code: 405,
                msg: "BRIDGE operations are not supported over UDP/DTLS".to_string(),
            };
            send_dtls_response(sessions, &remote_addr, &err).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Operation handlers
// ---------------------------------------------------------------------------

/// Handles a PUBLISH operation over UDP/DTLS through the public-record
/// admission every transport shares (§9.10.12).
#[allow(clippy::too_many_arguments)]
async fn handle_udp_publish<S: BlobStorage>(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    lifetime: BlobLifetime,
    blob: &[u8],
    sessions: &Arc<RwLock<HashMap<SocketAddr, DtlsSession>>>,
    remote_addr: &SocketAddr,
    storage: &Arc<S>,
    config: &RelayConfig,
) {
    // Validate blob size.
    if blob.is_empty() || blob.len() > config.max_blob_size {
        let err = RelayMessage::Err {
            ref_id,
            code: 413,
            msg: format!(
                "blob must be 1-{} bytes, got {}",
                config.max_blob_size,
                blob.len()
            ),
        };
        send_dtls_response(sessions, remote_addr, &err).await;
        return;
    }

    // Push interception (§10.7.1, ADR-004 "Push registration interception"),
    // the same gate every relay transport runs: a PUBLISH to the reserved push
    // routing ID is answered here and never reaches storage or a subscriber.
    if let Some(reply) = push_gate::gate_publish(
        &config.relay_url,
        &config.push,
        &routing_id,
        blob,
        scp_clock::Clock::now_secs(&scp_clock::SystemClock),
    )
    .await
    .reply(ref_id.as_deref())
    {
        send_dtls_response(sessions, remote_addr, &reply).await;
        return;
    }

    // UDP/DTLS has no subscriptions, so a stored blob is only answered and
    // woken.
    let reply = match public_records::admit_publish(
        &config.public_records,
        storage.as_ref(),
        routing_id,
        recipient_hint,
        lifetime,
        blob,
    )
    .await
    {
        Ok(stored) => RelayMessage::Ok {
            ref_id,
            blob_id: Some(stored.blob_id),
        },
        Err(refusal) => {
            let (code, msg) = refusal.into_parts();
            send_dtls_response(
                sessions,
                remote_addr,
                &RelayMessage::Err { ref_id, code, msg },
            )
            .await;
            return;
        }
    };
    send_dtls_response(sessions, remote_addr, &reply).await;

    // Queue the wakes for the stored blob after the publisher is answered; it
    // never waits (§10.7.1 step 5, PUSH-008).
    crate::relay::push_dispatch::notify(&config.push, &routing_id);
}

/// Handles a QUERY operation over UDP/DTLS.
///
/// Retrieves matching blobs and sends each as a separate datagram followed
/// by a `query_complete` event datagram.
#[allow(clippy::too_many_arguments)]
async fn handle_udp_query<S: BlobStorage>(
    ref_id: Option<String>,
    routing_id: [u8; 32],
    since: Option<u64>,
    after_blob: Option<[u8; 32]>,
    limit: Option<u32>,
    proof_nonce: Option<[u8; 32]>,
    sessions: &Arc<RwLock<HashMap<SocketAddr, DtlsSession>>>,
    remote_addr: &SocketAddr,
    storage: &Arc<S>,
    config: &RelayConfig,
) {
    let effective_limit = limit.unwrap_or(DEFAULT_QUERY_LIMIT);

    if effective_limit == 0 || effective_limit > config.max_query_limit {
        let err = RelayMessage::Err {
            ref_id,
            code: 400,
            msg: format!(
                "limit must be 1-{}, got {}",
                config.max_query_limit, effective_limit
            ),
        };
        send_dtls_response(sessions, remote_addr, &err).await;
        return;
    }

    let Some(cursor) = QueryCursor::from_wire(since, after_blob) else {
        let err = RelayMessage::Err {
            ref_id,
            code: scp_relay_client::code::MISSING_FIELD,
            msg: "after_blob requires since".to_string(),
        };
        send_dtls_response(sessions, remote_addr, &err).await;
        return;
    };

    let blobs = match public_records::query_blobs(
        &config.relay_url,
        storage.as_ref(),
        routing_id,
        cursor,
        effective_limit,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            debug!(remote = %remote_addr, error = %e, "UDP: blob query failed");
            let err = RelayMessage::Err {
                ref_id,
                code: 500,
                msg: "internal error".to_owned(),
            };
            send_dtls_response(sessions, remote_addr, &err).await;
            return;
        }
    };

    // The proof covers the blobs in the order they are sent below.
    let proof_query = node_proof::proof_query(proof_nonce, routing_id, since, after_blob, limit);
    let complete =
        node_proof::query_complete(&config.node_proofs, ref_id, proof_query.as_ref(), &blobs);
    for stored in blobs {
        send_dtls_response(sessions, remote_addr, &public_records::blob_message(stored)).await;
    }
    send_dtls_response(sessions, remote_addr, &complete).await;
}

/// Handles a DELETE operation over UDP/DTLS: `4041` for a retained record
/// (§9.10.12), `5000` when storage fails, `OK` otherwise.
async fn handle_udp_delete<S: BlobStorage>(
    ref_id: Option<String>,
    blob_id: [u8; 32],
    sessions: &Arc<RwLock<HashMap<SocketAddr, DtlsSession>>>,
    remote_addr: &SocketAddr,
    storage: &Arc<S>,
    config: &RelayConfig,
    rate_limiter: &PublishRateLimiter,
) {
    let reply = match public_records::delete_blob(
        &config.public_records,
        storage.as_ref(),
        &blob_id,
        rate_limiter,
        remote_addr.ip(),
    )
    .await
    {
        Ok(()) => RelayMessage::Ok {
            ref_id,
            blob_id: None,
        },
        Err(refusal) => {
            let (code, msg) = refusal.into_parts();
            RelayMessage::Err { ref_id, code, msg }
        }
    };
    send_dtls_response(sessions, remote_addr, &reply).await;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serializes a `RelayMessage` and sends it as an encrypted DTLS datagram
/// via the client's DTLS session.
///
/// The session map read lock is released before the blocking DTLS send to
/// prevent lock starvation of write operations.
async fn send_dtls_response(
    sessions: &Arc<RwLock<HashMap<SocketAddr, DtlsSession>>>,
    remote_addr: &SocketAddr,
    msg: &RelayMessage,
) {
    let data = match rmp_serde::to_vec_named(msg) {
        Ok(d) => d,
        Err(e) => {
            warn!(remote = %remote_addr, error = %e, "failed to serialize RelayMessage");
            return;
        }
    };

    // Extract DTLS session Arc under brief read lock, then drop the lock
    // before the potentially blocking send operation.
    let session_map = sessions.read().await;
    let Some(session) = session_map.get(remote_addr) else {
        drop(session_map);
        warn!(remote = %remote_addr, "no DTLS session found for response");
        return;
    };
    let dtls = Arc::clone(&session.dtls);
    drop(session_map);

    if let Err(e) = dtls.send(data).await {
        warn!(remote = %remote_addr, error = %e, "failed to send DTLS response");
    }
}

/// Extracts the `ref_id` from a `ClientMessage` for error responses.
fn extract_ref_id(msg: &ClientMessage) -> Option<String> {
    match msg {
        ClientMessage::Publish { ref_id, .. }
        | ClientMessage::Subscribe { ref_id, .. }
        | ClientMessage::Unsubscribe { ref_id, .. }
        | ClientMessage::Query { ref_id, .. }
        | ClientMessage::Delete { ref_id, .. }
        | ClientMessage::BridgeRegister { ref_id, .. }
        | ClientMessage::BridgeData { ref_id, .. } => ref_id.clone(),
        ClientMessage::Ping { .. } | ClientMessage::Ack { .. } => None,
    }
}

/// Background task that periodically evicts inactive DTLS sessions.
///
/// When sessions are evicted, their per-IP connection count is decremented
/// in the shared `ConnectionTracker` to free the cross-transport budget.
async fn session_cleanup_task(
    sessions: Arc<RwLock<HashMap<SocketAddr, DtlsSession>>>,
    conn_tracker: ConnectionTracker,
    timeout: Duration,
    interval: Duration,
    token: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);

    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {}
        }

        let now = Instant::now();

        // Evict idle DTLS sessions and collect their IPs for connection
        // tracker cleanup. The sessions write lock is dropped before
        // acquiring the connection tracker lock to prevent deadlock.
        let evicted_ips: Vec<std::net::IpAddr> = {
            let mut session_map = sessions.write().await;
            let before = session_map.len();
            let mut ips = Vec::new();

            session_map.retain(|addr, session| {
                let elapsed = now.duration_since(session.last_activity);
                if elapsed > timeout {
                    debug!(remote = %addr, idle_secs = elapsed.as_secs(), "evicting idle DTLS session");
                    ips.push(addr.ip());
                    false
                } else {
                    true
                }
            });

            let evicted = before - session_map.len();
            if evicted > 0 {
                debug!(
                    evicted,
                    remaining = session_map.len(),
                    "session cleanup complete"
                );
            }

            ips
        };
        // Sessions write lock dropped.

        // Unregister evicted sessions from the shared connection tracker.
        for ip in evicted_ips {
            rate_limit::unregister_connection(&conn_tracker, ip).await;
        }
    }
}

/// Builds an OpenSSL SSL context configured for DTLS server mode.
///
/// Uses ECDSA P-256 for the self-signed certificate. Ed25519 is not compatible
/// with DTLSv1.2 cipher suites (no shared cipher negotiation possible).
fn build_dtls_server_context() -> Result<SslContext, openssl::error::ErrorStack> {
    let mut builder = SslContext::builder(SslMethod::dtls())?;

    // Enforce DTLS 1.2 minimum — disables DTLSv1.0 (spec §9.13, §10.16.1).
    builder.set_min_proto_version(Some(openssl::ssl::SslVersion::DTLS1_2))?;
    // Restrict to AEAD cipher suites with forward secrecy (ECDHE + AES-GCM).
    // This is the DTLS 1.2 equivalent of TLS 1.3's mandatory cipher suites.
    builder.set_cipher_list("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")?;
    // Prefer server cipher order to ensure strongest suite is selected
    // regardless of client preference ordering.
    builder.set_options(openssl::ssl::SslOptions::CIPHER_SERVER_PREFERENCE);

    // Disable client certificate verification -- relay authentication happens
    // at the protocol layer inside the MLS-encrypted envelope (section 9.13),
    // not at the transport layer. This is consistent with the native relay
    // model (ADR-004) where relays are untrusted.
    builder.set_verify(openssl::ssl::SslVerifyMode::NONE);

    // Generate a temporary ECDSA P-256 self-signed certificate for transport
    // encryption. The relay does not authenticate at the TLS layer per section
    // 9.13 — the certificate is only used for DTLS record-layer encryption.
    let ec_group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let ec_key = openssl::ec::EcKey::generate(&ec_group)?;
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key)?;

    let mut x509_builder = openssl::x509::X509::builder()?;
    x509_builder.set_pubkey(&pkey)?;

    // Generate a random 128-bit serial number (CRYPTO-006a). X.509 requires
    // a unique serial per issuer; a random 16-byte value provides sufficient
    // collision resistance for self-signed transport-layer certificates.
    let serial_bytes: [u8; 16] = rand::thread_rng().r#gen();
    let serial_bn = openssl::bn::BigNum::from_slice(&serial_bytes)?;
    let serial_asn1 = serial_bn.to_asn1_integer()?;
    x509_builder.set_serial_number(&serial_asn1)?;

    let mut name = openssl::x509::X509Name::builder()?;
    name.append_entry_by_text("CN", "scp-relay-dtls")?;
    let name = name.build();
    x509_builder.set_subject_name(&name)?;
    x509_builder.set_issuer_name(&name)?;

    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(365)?;
    x509_builder.set_not_before(&not_before)?;
    x509_builder.set_not_after(&not_after)?;
    x509_builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;
    let cert = x509_builder.build();

    builder.set_private_key(&pkey)?;
    builder.set_certificate(&cert)?;

    Ok(builder.build())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::native::storage::InMemoryBlobStorage;
    use crate::udp::dtls::AsyncDtlsSession;
    use openssl::ssl::{SslMethod, SslVerifyMode};

    /// Helper: create a test listener and return the bound address and shutdown handle.
    async fn start_test_listener() -> (UdpDtlsShutdownHandle, SocketAddr, Arc<InMemoryBlobStorage>)
    {
        start_test_listener_with_relay_config(RelayConfig::defaults(
            crate::relay::push_gate::test_relay_url(),
        ))
        .await
    }

    /// Helper: create a test listener with a custom `RelayConfig`.
    async fn start_test_listener_with_relay_config(
        relay_config: RelayConfig,
    ) -> (UdpDtlsShutdownHandle, SocketAddr, Arc<InMemoryBlobStorage>) {
        let storage = Arc::new(InMemoryBlobStorage::new());
        let listener_config = UdpDtlsListenerConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            max_sessions: 10,
            session_timeout: Duration::from_mins(1),
            rate_limit_per_ip: 100,
            cleanup_interval: Duration::from_millis(100),
            ..UdpDtlsListenerConfig::default()
        };
        let listener = UdpDtlsListener::new(
            listener_config,
            relay_config,
            Arc::clone(&storage),
            PublishRateLimiter::new(100),
            rate_limit::new_connection_tracker(),
        )
        .unwrap();
        let (handle, addr) = listener.start().await.unwrap();
        (handle, addr, storage)
    }

    /// Helper: build a client DTLS context (no certificate verification).
    ///
    /// Matches production cipher settings: DTLS 1.2 minimum, ECDHE-ECDSA-AES-GCM only.
    fn build_test_client_ctx() -> SslContext {
        let mut builder = SslContext::builder(SslMethod::dtls()).unwrap();
        builder.set_verify(SslVerifyMode::NONE);
        builder
            .set_min_proto_version(Some(openssl::ssl::SslVersion::DTLS1_2))
            .unwrap();
        builder
            .set_cipher_list("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256")
            .unwrap();
        builder.build()
    }

    /// Per-attempt DTLS handshake read timeout for the test client.
    ///
    /// Production clients use [`AsyncDtlsSession::connect`] with a 10 s read
    /// timeout (`DTLS_RECV_TIMEOUT`) — generous for high-latency constrained
    /// links. Loopback tests are the opposite regime and need a shorter,
    /// fail-fast timeout, but it cannot be made arbitrarily short.
    ///
    /// The listener deliberately discards the first `ClientHello` (consumed on
    /// the main socket) and relies on the client's DTLS retransmission to drive
    /// the handshake on the per-client connected socket. OpenSSL's blocking
    /// DTLS handshake only retransmits *after* a blocking `recv` returns: with a
    /// plain `UdpSocket` it cannot fire its retransmission timer mid-`recv`, so
    /// the client's first `recv` necessarily blocks for the **full** read
    /// timeout before the retransmission is sent and the server responds. The
    /// read timeout is therefore a hard floor on handshake latency, and it MUST
    /// exceed OpenSSL's ~1 s DTLS1.2 initial retransmission interval — set it
    /// below that and the `recv` times out and OpenSSL aborts the handshake with
    /// "a nonblocking read call would have blocked" before any retransmission
    /// happens, so *every* attempt fails (verified empirically: 400 ms fails
    /// every time; 1.05 s succeeds in ~1.05 s; 1.5 s succeeds in ~1.5 s).
    ///
    /// 1.5 s keeps a comfortable margin over the ~1 s floor to absorb scheduling
    /// jitter under heavy CI parallelism, while bounding the cost of a misrouted
    /// attempt (one that blocks the full timeout, then fails) so the retry below
    /// can land on the correct socket within a couple of seconds instead of the
    /// ~150 s a single 10 s-timeout attempt could compound to. The production
    /// timeout is unchanged.
    const TEST_DTLS_RECV_TIMEOUT: Duration = Duration::from_millis(1500);

    /// Hard ceiling on a single handshake attempt.
    ///
    /// `TEST_DTLS_RECV_TIMEOUT` bounds an individual blocking `recv`, but a
    /// misrouted handshake may chain several reads via OpenSSL's DTLS
    /// retransmission timer. This wall-clock ceiling (comfortably above the
    /// `TEST_DTLS_RECV_TIMEOUT` floor) lets the retry loop abandon a stuck
    /// attempt and move on. The orphaned `spawn_blocking` thread cannot be
    /// cancelled and finishes on its own read timeout; we simply stop awaiting
    /// it.
    const TEST_DTLS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);

    /// Number of handshake attempts before giving up.
    ///
    /// Eight attempts with capped exponential backoff tolerate repeated
    /// reuseport misrouting under the heavy parallelism of the full CI test run
    /// (the workspace suite plus the transport suite at high thread counts),
    /// where the loopback routing race is far more frequent than in isolation.
    const TEST_DTLS_MAX_ATTEMPTS: u32 = 8;

    /// Helper: create a DTLS client connected to the given server address.
    ///
    /// Retries the full handshake to absorb kernel UDP routing races on
    /// localhost: when many test listeners run concurrently, the `SO_REUSEPORT`
    /// reuseport group that the listener uses for per-client DTLS multiplexing
    /// can deliver a retransmitted `ClientHello` to the wrong socket. Each
    /// attempt uses a short read timeout (`TEST_DTLS_RECV_TIMEOUT`) and a hard
    /// wall-clock ceiling (`TEST_DTLS_ATTEMPT_TIMEOUT`) so a misrouted attempt
    /// fails fast and is retried, rather than blocking on the production 10 s
    /// timeout. Backoff is capped exponential to avoid hammering the listener.
    async fn create_dtls_client(server_addr: SocketAddr) -> AsyncDtlsSession {
        let mut last_err: Option<String> = None;
        for attempt in 0..TEST_DTLS_MAX_ATTEMPTS {
            let client_ctx = build_test_client_ctx();
            let handshake = AsyncDtlsSession::connect_with_timeout(
                client_ctx,
                server_addr,
                TEST_DTLS_RECV_TIMEOUT,
            );
            match tokio::time::timeout(TEST_DTLS_ATTEMPT_TIMEOUT, handshake).await {
                Ok(Ok(session)) => return session,
                Ok(Err(e)) => last_err = Some(e.to_string()),
                Err(_) => last_err = Some("handshake attempt exceeded ceiling".to_string()),
            }
            if attempt + 1 < TEST_DTLS_MAX_ATTEMPTS {
                // Capped exponential backoff: 50, 100, 200, 400, 800, 800, ...
                let backoff = Duration::from_millis(50u64 << attempt.min(4));
                tokio::time::sleep(backoff).await;
            }
        }
        panic!(
            "DTLS handshake failed after {TEST_DTLS_MAX_ATTEMPTS} attempts: {}",
            last_err.unwrap_or_else(|| "unknown error".to_string())
        )
    }

    /// Helper: send a `ClientMessage` and receive the response via DTLS.
    async fn send_and_recv(client: &AsyncDtlsSession, msg: &ClientMessage) -> RelayMessage {
        send_bytes_and_recv(client, rmp_serde::to_vec_named(msg).unwrap()).await
    }

    /// Helper: send raw frame bytes and receive the response via DTLS.
    async fn send_bytes_and_recv(client: &AsyncDtlsSession, data: Vec<u8>) -> RelayMessage {
        client.send(data).await.unwrap();

        let response_data = tokio::time::timeout(Duration::from_secs(5), client.recv())
            .await
            .expect("recv should complete within 5s")
            .expect("recv should succeed");

        rmp_serde::from_slice(&response_data).unwrap()
    }

    /// Helper: receive a `RelayMessage` via DTLS.
    async fn recv_msg(client: &AsyncDtlsSession) -> RelayMessage {
        let data = tokio::time::timeout(Duration::from_secs(5), client.recv())
            .await
            .expect("recv should complete within 5s")
            .expect("recv should succeed");

        rmp_serde::from_slice(&data).unwrap()
    }

    #[test]
    fn listener_config_defaults_are_sane() {
        let config = UdpDtlsListenerConfig::default();
        assert_eq!(config.max_sessions, 256);
        assert_eq!(config.max_sessions_per_ip, 10);
        assert_eq!(config.session_timeout, Duration::from_mins(5));
        assert_eq!(config.rate_limit_per_ip, 50);
        assert_eq!(config.recv_buffer_size, 65535);
        assert_eq!(config.cleanup_interval, Duration::from_secs(30));
    }

    #[test]
    fn listener_creation_succeeds() {
        let storage = Arc::new(InMemoryBlobStorage::new());
        let config = UdpDtlsListenerConfig::default();
        let relay_config = RelayConfig::defaults(crate::relay::push_gate::test_relay_url());
        let listener = UdpDtlsListener::new(
            config,
            relay_config,
            storage,
            PublishRateLimiter::new(100),
            rate_limit::new_connection_tracker(),
        );
        assert!(listener.is_ok());
    }

    #[tokio::test]
    async fn publish_and_query_roundtrip() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let routing_id = [0xAA; 32];
        let blob_data = vec![0x01, 0x02, 0x03, 0x04];

        // PUBLISH
        let publish_msg = ClientMessage::Publish {
            ref_id: Some("pub-1".to_string()),
            routing_id,
            recipient_hint: None,
            lifetime: BlobLifetime::Ttl(scp_relay_client::PublishTtl::of::<3600>()),
            blob: blob_data.clone(),
        };

        let response = send_and_recv(&client, &publish_msg).await;
        match &response {
            RelayMessage::Ok {
                ref_id,
                blob_id: Some(_),
            } => {
                assert_eq!(ref_id.as_deref(), Some("pub-1"));
            }
            other => panic!("expected Ok with blob_id, got: {other:?}"),
        }

        // QUERY
        let query_msg = ClientMessage::Query {
            proof_nonce: None,
            ref_id: Some("qry-1".to_string()),
            routing_id,
            since: None,
            after_blob: None,
            limit: None,
        };

        let data = rmp_serde::to_vec_named(&query_msg).unwrap();
        client.send(data).await.unwrap();

        // Expect: one BLOB datagram + one query_complete EVENT.
        let blob_response = recv_msg(&client).await;
        match &blob_response {
            RelayMessage::Blob {
                routing_id: rid,
                blob,
                ..
            } => {
                assert_eq!(rid, &[0xAA; 32]);
                assert_eq!(blob, &blob_data);
            }
            other => panic!("expected Blob, got: {other:?}"),
        }

        let event_response = recv_msg(&client).await;
        match &event_response {
            RelayMessage::Event {
                ref_id, event_type, ..
            } => {
                assert_eq!(ref_id.as_deref(), Some("qry-1"));
                assert_eq!(event_type, "query_complete");
            }
            other => panic!("expected query_complete Event, got: {other:?}"),
        }

        handle.shutdown();
    }

    #[tokio::test]
    async fn delete_returns_ok() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let delete_msg = ClientMessage::Delete {
            ref_id: Some("del-1".to_string()),
            blob_id: [0xBB; 32],
        };

        let response = send_and_recv(&client, &delete_msg).await;
        match &response {
            RelayMessage::Ok {
                ref_id,
                blob_id: None,
            } => {
                assert_eq!(ref_id.as_deref(), Some("del-1"));
            }
            other => panic!("expected Ok without blob_id, got: {other:?}"),
        }

        handle.shutdown();
    }

    #[tokio::test]
    async fn subscribe_returns_error() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let subscribe_msg = ClientMessage::Subscribe {
            ref_id: Some("sub-1".to_string()),
            routing_id: [0xCC; 32],
            since: None,
        };

        let response = send_and_recv(&client, &subscribe_msg).await;
        match &response {
            RelayMessage::Err { ref_id, code, msg } => {
                assert_eq!(ref_id.as_deref(), Some("sub-1"));
                assert_eq!(*code, 405);
                assert!(
                    msg.contains("SUBSCRIBE"),
                    "error should mention SUBSCRIBE: {msg}"
                );
                assert!(msg.contains("QUERY"), "error should guide to QUERY: {msg}");
            }
            other => panic!("expected Err, got: {other:?}"),
        }

        handle.shutdown();
    }

    #[tokio::test]
    async fn unsubscribe_returns_error() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let unsubscribe_msg = ClientMessage::Unsubscribe {
            ref_id: Some("unsub-1".to_string()),
            routing_id: [0xDD; 32],
        };

        let response = send_and_recv(&client, &unsubscribe_msg).await;
        match &response {
            RelayMessage::Err { ref_id, code, .. } => {
                assert_eq!(ref_id.as_deref(), Some("unsub-1"));
                assert_eq!(*code, 405);
            }
            other => panic!("expected Err, got: {other:?}"),
        }

        handle.shutdown();
    }

    #[tokio::test]
    async fn ping_returns_pong() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let ping_msg = ClientMessage::Ping { ts: 1_234_567_890 };
        let response = send_and_recv(&client, &ping_msg).await;

        match &response {
            RelayMessage::Pong { ts } => {
                assert_eq!(*ts, 1_234_567_890);
            }
            other => panic!("expected Pong, got: {other:?}"),
        }

        handle.shutdown();
    }

    #[tokio::test]
    async fn publish_oversized_blob_returns_error() {
        let small_relay_config = RelayConfig {
            max_blob_size: 1024,
            ..RelayConfig::defaults(crate::relay::push_gate::test_relay_url())
        };
        let (handle, addr, _storage) =
            start_test_listener_with_relay_config(small_relay_config).await;
        let client = create_dtls_client(addr).await;

        let oversized_blob = vec![0xFF; 1025];
        let publish_msg = ClientMessage::Publish {
            ref_id: Some("big-1".to_string()),
            routing_id: [0xEE; 32],
            recipient_hint: None,
            lifetime: BlobLifetime::Ttl(scp_relay_client::PublishTtl::of::<3600>()),
            blob: oversized_blob,
        };

        let response = send_and_recv(&client, &publish_msg).await;
        match &response {
            RelayMessage::Err { ref_id, code, .. } => {
                assert_eq!(ref_id.as_deref(), Some("big-1"));
                assert_eq!(*code, 413);
            }
            other => panic!("expected Err for oversized blob, got: {other:?}"),
        }

        handle.shutdown();
    }

    #[tokio::test]
    async fn publish_invalid_ttl_returns_error() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let frame =
            crate::native::public_records::publish_frame_with_ttl("ttl-0", [0xFF; 32], 0, &[0x01])
                .unwrap();

        let response = send_bytes_and_recv(&client, frame).await;
        match &response {
            RelayMessage::Err { ref_id, code, .. } => {
                assert_eq!(ref_id.as_deref(), Some("ttl-0"));
                assert_eq!(*code, scp_relay_client::code::TTL_TOO_LONG);
            }
            other => panic!("expected Err for invalid TTL, got: {other:?}"),
        }

        handle.shutdown();
    }

    #[tokio::test]
    async fn query_empty_returns_only_complete_event() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let query_msg = ClientMessage::Query {
            proof_nonce: None,
            ref_id: Some("empty-q".to_string()),
            routing_id: [0x11; 32],
            since: None,
            after_blob: None,
            limit: None,
        };

        let response = send_and_recv(&client, &query_msg).await;
        match &response {
            RelayMessage::Event {
                ref_id,
                event_type,
                node_proof,
            } => {
                assert_eq!(ref_id.as_deref(), Some("empty-q"));
                assert_eq!(event_type, "query_complete");
                assert_eq!(*node_proof, None, "an unbound listener returns no proof");
            }
            other => panic!("expected query_complete Event for empty query, got: {other:?}"),
        }

        handle.shutdown();
    }

    /// A listener whose relay config carries the node's bound key answers a
    /// QUERY carrying `proof_nonce` with a proof that verifies under the
    /// binding's node key and echoes the nonce.
    #[tokio::test]
    async fn a_bound_listener_signs_the_query_complete() {
        let key = crate::native::node_proof::tests::bound_key(7).unwrap();
        let (handle, addr, _storage) = start_test_listener_with_relay_config(RelayConfig {
            node_proofs: crate::native::node_proof::NodeProofs::Sign(Arc::clone(&key)),
            ..RelayConfig::defaults(crate::relay::push_gate::test_relay_url())
        })
        .await;
        let client = create_dtls_client(addr).await;
        let query_msg = ClientMessage::Query {
            proof_nonce: Some([0x5a; 32]),
            ref_id: Some("proved-q".to_string()),
            routing_id: [0x11; 32],
            since: None,
            after_blob: None,
            limit: None,
        };
        let before = crate::native::node_proof::tests::now_secs();
        let response = send_and_recv(&client, &query_msg).await;
        let after = crate::native::node_proof::tests::now_secs();
        let proof = crate::native::node_proof::tests::proof_of(&key, &response).unwrap();
        assert_eq!(proof.nonce, [0x5a; 32]);
        assert_eq!(proof.routing_id, [0x11; 32]);
        // The omitted limit is digested as omitted, not as the default.
        assert_eq!(
            proof.query_digest,
            scp_protocol::node::SentQuery {
                nonce: [0x5a; 32],
                routing_id: [0x11; 32],
                since: None,
                after_blob: None,
                limit: None,
            }
            .digest()
        );
        assert!((before..=after).contains(&proof.observed_at));
        handle.shutdown();
    }

    #[tokio::test]
    async fn graceful_shutdown_stops_listener() {
        let (handle, addr, _storage) = start_test_listener().await;

        let client = create_dtls_client(addr).await;
        let ping = ClientMessage::Ping { ts: 42 };
        let resp = send_and_recv(&client, &ping).await;
        assert!(matches!(resp, RelayMessage::Pong { ts: 42 }));

        handle.shutdown();
        assert!(handle.is_shutdown());

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(handle.is_shutdown());
    }

    #[tokio::test]
    async fn bridge_operations_return_error() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let bridge_msg = ClientMessage::BridgeRegister {
            ref_id: Some("bridge-1".to_string()),
            routing_id: [0x33; 32],
            public_key: [0x44; 32],
            signature: [0x55; 64],
            timestamp: 0,
            target_relay_hint: None,
        };

        let response = send_and_recv(&client, &bridge_msg).await;
        match &response {
            RelayMessage::Err { ref_id, code, .. } => {
                assert_eq!(ref_id.as_deref(), Some("bridge-1"));
                assert_eq!(*code, 405);
            }
            other => panic!("expected Err for bridge operation, got: {other:?}"),
        }

        handle.shutdown();
    }

    #[tokio::test]
    async fn publish_with_recipient_hint() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let routing_id = [0x44; 32];
        let hint = [0x55; 32];

        let publish_msg = ClientMessage::Publish {
            ref_id: Some("hint-1".to_string()),
            routing_id,
            recipient_hint: Some(hint),
            lifetime: BlobLifetime::Ttl(scp_relay_client::PublishTtl::of::<3600>()),
            blob: vec![0xAB, 0xCD],
        };

        let response = send_and_recv(&client, &publish_msg).await;
        match &response {
            RelayMessage::Ok {
                ref_id,
                blob_id: Some(_),
            } => {
                assert_eq!(ref_id.as_deref(), Some("hint-1"));
            }
            other => panic!("expected Ok, got: {other:?}"),
        }

        // Query and verify the recipient_hint is preserved.
        let query_msg = ClientMessage::Query {
            proof_nonce: None,
            ref_id: None,
            routing_id,
            since: None,
            after_blob: None,
            limit: None,
        };
        let data = rmp_serde::to_vec_named(&query_msg).unwrap();
        client.send(data).await.unwrap();

        let blob_resp = recv_msg(&client).await;
        match &blob_resp {
            RelayMessage::Blob {
                recipient_hint: Some(h),
                ..
            } => {
                assert_eq!(h, &hint);
            }
            other => panic!("expected Blob with recipient_hint, got: {other:?}"),
        }

        // Consume the query_complete event.
        let _ = recv_msg(&client).await;

        handle.shutdown();
    }

    #[tokio::test]
    async fn delete_then_query_returns_empty() {
        let (handle, addr, _storage) = start_test_listener().await;
        let client = create_dtls_client(addr).await;

        let routing_id = [0x66; 32];

        // Publish a blob.
        let publish_msg = ClientMessage::Publish {
            ref_id: None,
            routing_id,
            recipient_hint: None,
            lifetime: BlobLifetime::Ttl(scp_relay_client::PublishTtl::of::<3600>()),
            blob: vec![0x99],
        };
        let pub_resp = send_and_recv(&client, &publish_msg).await;
        let blob_id = match pub_resp {
            RelayMessage::Ok {
                blob_id: Some(id), ..
            } => id,
            other => panic!("expected Ok with blob_id, got: {other:?}"),
        };

        // Delete the blob.
        let delete_msg = ClientMessage::Delete {
            ref_id: None,
            blob_id,
        };
        let del_resp = send_and_recv(&client, &delete_msg).await;
        assert!(matches!(del_resp, RelayMessage::Ok { .. }));

        // Query should return empty.
        let query_msg = ClientMessage::Query {
            proof_nonce: None,
            ref_id: None,
            routing_id,
            since: None,
            after_blob: None,
            limit: None,
        };
        let response = send_and_recv(&client, &query_msg).await;
        match &response {
            RelayMessage::Event { event_type, .. } if event_type == "query_complete" => {
                // Good -- no blobs returned.
            }
            other => panic!("expected query_complete (empty), got: {other:?}"),
        }

        handle.shutdown();
    }

    /// The UDP/DTLS listener runs the same push gate as the WebSocket relay
    /// (§10.7.1) and reads the shared [`LiveRelayUrl`] on every PUBLISH: after
    /// a `set` on a clone of the handle, the new reserved routing ID and the
    /// previous one are both answered with 4063 and nothing is stored at
    /// either.
    #[tokio::test]
    async fn udp_listener_reads_the_shared_relay_url() {
        use crate::relay::push_gate::{LiveRelayUrl, PushReservation};
        let old = PushReservation::new("ws://198.51.100.7:32891/scp/v1").unwrap();
        let new = PushReservation::new("ws://203.0.113.42:8443/scp/v1").unwrap();
        let live = LiveRelayUrl::new(old.clone());
        let (handle, addr, storage) =
            start_test_listener_with_relay_config(RelayConfig::defaults(live.clone())).await;
        live.set(new.clone());
        let client = create_dtls_client(addr).await;

        for rid in [new.push_routing_id(), old.push_routing_id()] {
            let response = send_and_recv(
                &client,
                &ClientMessage::Publish {
                    ref_id: Some("push".to_string()),
                    routing_id: rid,
                    recipient_hint: None,
                    lifetime: BlobLifetime::Ttl(scp_relay_client::PublishTtl::of::<3600>()),
                    blob: vec![0x42; 64],
                },
            )
            .await;
            assert!(
                matches!(
                    &response,
                    RelayMessage::Err { code: 4063, ref_id: Some(r), .. } if r == "push"
                ),
                "{response:?}"
            );
            assert!(
                storage
                    .query(
                        &rid,
                        crate::native::storage::QueryCursor::All,
                        crate::native::storage::LifetimeFilter::Any,
                        100
                    )
                    .await
                    .unwrap()
                    .is_empty()
            );
        }

        handle.shutdown();
    }

    /// The BLOBs a QUERY at `routing_id` returns, read up to `query_complete`.
    async fn query_blob_count(client: &AsyncDtlsSession, routing_id: [u8; 32]) -> usize {
        let data = rmp_serde::to_vec_named(&ClientMessage::Query {
            proof_nonce: None,
            ref_id: Some("q".to_string()),
            routing_id,
            since: None,
            after_blob: None,
            limit: None,
        })
        .unwrap();
        client.send(data).await.unwrap();
        let mut queried = 0;
        loop {
            match recv_msg(client).await {
                RelayMessage::Blob { .. } => queried += 1,
                RelayMessage::Event { event_type, .. } if event_type == "query_complete" => {
                    return queried;
                }
                other => panic!("QUERY returned {other:?}"),
            }
        }
    }

    /// §10.7.1 "No blob storage" at the UDP/DTLS listener, which takes no
    /// SUBSCRIBE: a blob stored at a routing ID while the relay did not
    /// reserve it is not returned by a QUERY once the handle reserves that ID
    /// as a tier 3 entry's, nor after the handle releases it.
    #[tokio::test]
    async fn udp_listener_reads_no_blob_at_a_current_or_released_reserved_id() {
        let fixture = crate::relay::push_gate::tier3_fixture().unwrap();
        let direct = crate::relay::push_gate::PushReservation::new("wss://relay.udp.test").unwrap();
        let live = crate::relay::push_gate::LiveRelayUrl::new(direct.clone());
        let (handle, addr, _storage) =
            start_test_listener_with_relay_config(RelayConfig::defaults(live.clone())).await;
        let client = create_dtls_client(addr).await;
        let rid = fixture.entry_a.push_routing_id();

        let response = send_and_recv(
            &client,
            &ClientMessage::Publish {
                ref_id: Some("p".to_string()),
                routing_id: rid,
                recipient_hint: None,
                lifetime: BlobLifetime::Ttl(scp_relay_client::PublishTtl::of::<3600>()),
                blob: vec![0x42; 64],
            },
        )
        .await;
        assert!(
            matches!(
                &response,
                RelayMessage::Ok {
                    blob_id: Some(_),
                    ..
                }
            ),
            "{response:?}"
        );
        assert_eq!(query_blob_count(&client, rid).await, 1, "ordinary ID");

        live.set(fixture.live.current());
        assert_eq!(query_blob_count(&client, rid).await, 0, "current tier 3 ID");

        live.set(direct);
        assert_eq!(
            query_blob_count(&client, rid).await,
            0,
            "released tier 3 ID"
        );
        handle.shutdown();
    }

    /// §10.7.1 "Tier 3 relays" at the UDP/DTLS listener: with the handle
    /// reserving two bridge entries, a PUBLISH at either entry's tier 3 push
    /// routing ID is answered with 4063 and stores nothing, and a PUBLISH at
    /// the bridge relay's own `"scp-push-registration"` ID stores a blob.
    #[tokio::test]
    async fn udp_listener_intercepts_the_tier3_id_of_a_bridge_entry() {
        let fixture = crate::relay::push_gate::tier3_fixture().unwrap();
        let (handle, addr, storage) =
            start_test_listener_with_relay_config(RelayConfig::defaults(fixture.live.clone()))
                .await;
        let client = create_dtls_client(addr).await;
        let publish = |rid: [u8; 32]| ClientMessage::Publish {
            ref_id: Some("push".to_string()),
            routing_id: rid,
            recipient_hint: None,
            lifetime: BlobLifetime::Ttl(scp_relay_client::PublishTtl::of::<3600>()),
            blob: vec![0x42; 64],
        };

        for rid in [
            fixture.entry_a.push_routing_id(),
            fixture.entry_b.push_routing_id(),
        ] {
            let response = send_and_recv(&client, &publish(rid)).await;
            assert!(
                matches!(
                    &response,
                    RelayMessage::Err { code: 4063, ref_id: Some(r), .. } if r == "push"
                ),
                "{response:?}"
            );
            assert!(
                storage
                    .query(
                        &rid,
                        crate::native::storage::QueryCursor::All,
                        crate::native::storage::LifetimeFilter::Any,
                        100
                    )
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        let response = send_and_recv(&client, &publish(fixture.bridge_own_id)).await;
        assert!(
            matches!(
                &response,
                RelayMessage::Ok {
                    blob_id: Some(_),
                    ..
                }
            ),
            "{response:?}"
        );
        assert_eq!(
            storage
                .query(
                    &fixture.bridge_own_id,
                    crate::native::storage::QueryCursor::All,
                    crate::native::storage::LifetimeFilter::Any,
                    100
                )
                .await
                .unwrap()
                .len(),
            1
        );

        handle.shutdown();
    }

    /// PUSH-012 criterion 10 at the UDP/DTLS listener: with push enabled
    /// (the production `KelPushVerifier`) and the handle reserving two bridge
    /// entries, a PUBLISH at either entry's tier 3 push routing ID is answered
    /// with `4060` before signature verification, because no Tier 3 envelope
    /// opener exists yet (§10.7.1 "Tier 3 relays", "Tier 3 envelope"), and the
    /// blob store holds nothing at that ID.
    #[cfg(feature = "push-store")]
    #[tokio::test]
    async fn enabled_udp_listener_rejects_a_tier3_publish_with_4060() {
        let fixture = crate::relay::push_gate::tier3_fixture().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (handle, addr, storage) = start_test_listener_with_relay_config(RelayConfig {
            push: crate::relay::push_gate::PushRole::Enabled(
                crate::relay::push_gate::kel_service_for_tests(dir.path()).await,
            ),
            ..RelayConfig::defaults(fixture.live.clone())
        })
        .await;
        let client = create_dtls_client(addr).await;
        for rid in [
            fixture.entry_a.push_routing_id(),
            fixture.entry_b.push_routing_id(),
        ] {
            let publish = ClientMessage::Publish {
                ref_id: Some("push".to_string()),
                routing_id: rid,
                recipient_hint: None,
                lifetime: BlobLifetime::Ttl(scp_relay_client::PublishTtl::of::<3600>()),
                blob: vec![0x42; 64],
            };
            let response = send_and_recv(&client, &publish).await;
            assert!(
                matches!(
                    &response,
                    RelayMessage::Err { code: 4060, ref_id: Some(r), .. } if r == "push"
                ),
                "{response:?}"
            );
            assert!(
                storage
                    .query(
                        &rid,
                        crate::native::storage::QueryCursor::All,
                        crate::native::storage::LifetimeFilter::Any,
                        100
                    )
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        handle.shutdown();
    }

    // -- Store-site wakes (§10.7.1 step 5, PUSH-008) --
    //
    // A blob the transport stores must wake. Each test fails when this
    // transport's `notify` is removed.
    #[cfg(all(feature = "push-store", feature = "testing"))]
    mod wake {
        use super::*;
        use crate::relay::push_dispatch::wake_harness::WakeHarness;

        /// Publishes `blob` to `rid` on a UDP-only relay whose push role is
        /// the harness's, and waits for one wake.
        async fn publish_and_wake(rid: [u8; 32], blob: Vec<u8>) {
            let harness = WakeHarness::start(&[rid]).await.unwrap();
            let (handle, addr, _storage) = start_test_listener_with_relay_config(RelayConfig {
                push: harness.push.clone(),
                ..RelayConfig::defaults(crate::relay::push_gate::test_relay_url())
            })
            .await;
            let client = create_dtls_client(addr).await;
            let response = send_and_recv(
                &client,
                &ClientMessage::Publish {
                    ref_id: None,
                    routing_id: rid,
                    recipient_hint: None,
                    lifetime: BlobLifetime::Ttl(scp_relay_client::PublishTtl::of::<3600>()),
                    blob,
                },
            )
            .await;
            assert!(
                matches!(
                    response,
                    RelayMessage::Ok {
                        blob_id: Some(_),
                        ..
                    }
                ),
                "{response:?}"
            );
            harness.wait_for_wakes(1).await.unwrap();
            handle.shutdown();
        }

        #[tokio::test]
        async fn udp_plain_blob_publish_wakes() {
            publish_and_wake([0x46; 32], vec![7; 16]).await;
        }
    }
}
