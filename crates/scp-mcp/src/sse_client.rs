//! Blocking HTTP SSE client transport for an MCP client.
//!
//! [`SseClientTransport`] is the one SSE client every FFI bridge (`PyO3`,
//! `UniFFI` and napi-rs) hands to [`McpClient`](crate::client::McpClient). It
//! opens the `GET` stream, learns the POST path from the `endpoint` event, and
//! sends each JSON-RPC message as a POST. When the caller passes a token, it
//! sends that token as `Authorization: Bearer <token>` on the `GET` and on
//! every POST, which the bearer check an SCP SSE server always runs requires
//! (ADR-015 in `.docs/adrs/phase-3.md`).

use std::io::{BufReader, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::client::McpTransport;
use crate::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId};
use crate::stdio::read_line_bounded;

/// The error of a call on a transport whose stream has closed.
const SSE_CLOSED: &str = "SSE connection is closed; connect a new transport";

/// MCP client transport that communicates via HTTP SSE.
///
/// Holds the `GET` stream open for the session and sends each message as a
/// POST on a fresh connection. A POST the server answers outside 2xx fails
/// the call. A request returns the first JSON-RPC response on the stream whose
/// `id` is the request's, and skips every other response, every notification,
/// and every server-initiated request (a line carrying `method`), whatever its
/// `id`. Calls on one transport run one at a time: a request holds the stream
/// from before its POST until its response arrives, and a concurrent call
/// waits for it, so every response a call skips answers an earlier call that
/// already failed.
pub struct SseClientTransport {
    /// The SSE endpoint URL (e.g., `http://localhost:3000/sse`).
    _url: String,
    /// The POST URL the server named in its `endpoint` event.
    post_url: String,
    /// The `Authorization: Bearer <token>` header line, CRLF included, sent
    /// on the `GET` and on every POST; empty when the caller passed no token.
    auth_header: String,
    /// TCP stream for reading SSE events, protected by a mutex.
    sse_reader: Mutex<Option<BufReader<std::net::TcpStream>>>,
    /// The state an [`SseCloser`] shares with this transport.
    close: Arc<SseCloseState>,
}

/// The state an [`SseCloser`] shares with its transport: the closed flag and
/// the sockets a blocked call reads from.
struct SseCloseState {
    /// Set by [`SseCloser::close`]; a transport sends nothing once it is set.
    closed: AtomicBool,
    /// A clone of the `GET` stream's socket, shut down on close.
    sse_stream: TcpStream,
    /// A clone of each POST socket a call is writing to or waiting on, under
    /// the key [`SseCloseState::next_post`] gave it.
    in_flight: Mutex<Vec<(u64, TcpStream)>>,
    /// The key the next in-flight POST is stored under.
    next_post: AtomicU64,
}

/// Closes an [`SseClientTransport`] from another thread.
///
/// A call blocked writing its POST, or on the POST's status line, whose
/// connection has no timeout, or on the `GET` stream is otherwise
/// unreachable: the transport's sockets live inside the call.
/// [`SseCloser::close`] shuts down every such socket, so the blocked write or
/// read returns at once and the call fails with [`SSE_CLOSED`], and every
/// later call fails with [`SSE_CLOSED`] before it sends a POST.
#[derive(Clone)]
pub struct SseCloser(Arc<SseCloseState>);

impl SseCloser {
    /// Closes the transport: marks it closed, then shuts down the socket of
    /// every POST a call is writing to or waiting on and the `GET` stream's
    /// socket.
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::SeqCst);
        let in_flight = match self.0.in_flight.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        // A socket the peer already closed fails `shutdown`; nothing is left
        // to wake then.
        for (_, stream) in in_flight {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let _ = self.0.sse_stream.shutdown(Shutdown::Both);
    }
}

/// Reads the status code from an HTTP status line such as `HTTP/1.1 200 OK`;
/// 0 when the line holds none.
fn http_status(status_line: &str) -> u16 {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

/// Builds the `Authorization` header line for an SSE client token.
///
/// # Errors
///
/// Returns an error when the token is empty or holds a byte outside visible
/// ASCII, because a CR, LF or space would let the token inject header lines.
pub(crate) fn sse_auth_header(auth_token: Option<&str>) -> Result<String, String> {
    let Some(token) = auth_token else {
        return Ok(String::new());
    };
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("SSE auth token must be non-empty visible ASCII".to_owned());
    }
    Ok(format!("Authorization: Bearer {token}\r\n"))
}

/// Builds the `GET` that opens the SSE stream; `auth_header` is empty or a
/// line from [`sse_auth_header`].
///
/// It sends `Connection: close`, so when the server ends the stream (a lagged
/// or evicted session, a dropped `run_sse`) it also closes the connection, and
/// a read waiting on the stream sees end of file. Under keep-alive the server
/// ends only the chunked body and leaves the connection open and idle, so that
/// read would wait out the 30-second read timeout instead.
pub(crate) fn sse_get_request(path: &str, host: &str, auth_header: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         {auth_header}\
         Accept: text/event-stream\r\n\
         Connection: close\r\n\
         \r\n"
    )
}

/// Opens a TCP connection to `addr` (`host:port`), connecting only to the
/// addresses it resolved to here.
///
/// # Errors
///
/// Returns an error when `addr` does not resolve or the connection fails, and
/// when `sends_token` is set and `addr` resolves to any address that is not
/// loopback: the transport has no TLS, so a bearer token sent to another host
/// would cross the network in cleartext.
fn open_stream(addr: &str, sends_token: bool) -> Result<std::net::TcpStream, String> {
    use std::net::ToSocketAddrs;
    let resolved: Vec<std::net::SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve {addr}: {e}"))?
        .collect();
    if sends_token && !resolved.iter().all(|a| a.ip().is_loopback()) {
        return Err(format!(
            "refusing to send the SSE bearer token to {addr}: the transport has no TLS, \
             so a token goes only to a loopback address"
        ));
    }
    std::net::TcpStream::connect(&resolved[..])
        .map_err(|e| format!("failed to connect to {addr}: {e}"))
}

impl SseClientTransport {
    /// Connects to the SSE endpoint and establishes the transport.
    ///
    /// 1. Opens a TCP connection to the SSE endpoint.
    /// 2. Sends a GET request for the SSE stream, with `auth_token` as a
    ///    bearer token when one is given.
    /// 3. Reads the initial `endpoint` event to learn the POST URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is malformed, if a token is given for a
    /// host that is not loopback (the transport has no TLS), or if the
    /// connection or handshake fails; a server whose bearer check refuses the
    /// token answers HTTP 401, which fails the handshake.
    pub fn connect(url: &str, auth_token: Option<&str>) -> Result<Self, String> {
        if url.starts_with("https://") {
            return Err(
                "SSE transport does not support TLS; use http:// or add rustls dependency for HTTPS"
                    .to_owned(),
            );
        }
        let auth_header = sse_auth_header(auth_token)?;

        // Parse the URL to extract host, port, and path.
        let (host, port, path) = parse_http_url(url)?;
        let addr = format!("{host}:{port}");

        // Connect and send GET request for SSE stream.
        let stream = open_stream(&addr, auth_token.is_some())?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(|e| format!("failed to set read timeout: {e}"))?;

        let mut writer = std::io::BufWriter::new(
            stream
                .try_clone()
                .map_err(|e| format!("failed to clone stream: {e}"))?,
        );

        // Send HTTP GET for SSE.
        let get_request = sse_get_request(&path, &host, &auth_header);
        writer
            .write_all(get_request.as_bytes())
            .map_err(|e| format!("failed to send GET request: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush GET request: {e}"))?;

        let sse_stream = stream
            .try_clone()
            .map_err(|e| format!("failed to clone stream: {e}"))?;
        let mut reader = BufReader::new(stream);

        // Read the HTTP status line and validate.
        let mut status_line = String::new();
        let n = read_line_bounded(&mut reader, &mut status_line)
            .map_err(|e| format!("failed to read HTTP status line: {e}"))?;
        if n == 0 {
            return Err("connection closed before HTTP status line".to_owned());
        }
        let status_code = http_status(&status_line);
        if !(200..300).contains(&status_code) {
            return Err(format!(
                "SSE endpoint returned HTTP {status_code}: {}",
                status_line.trim()
            ));
        }

        // Read remaining HTTP response headers.
        let mut header_line = String::new();
        loop {
            header_line.clear();
            let n = read_line_bounded(&mut reader, &mut header_line)
                .map_err(|e| format!("failed to read SSE headers: {e}"))?;
            if n == 0 {
                return Err("connection closed while reading SSE headers".to_owned());
            }
            if header_line.trim().is_empty() {
                break; // End of headers.
            }
        }

        // Read the initial `endpoint` SSE event to learn the POST URL.
        let post_path;
        loop {
            let mut event_line = String::new();
            let n = read_line_bounded(&mut reader, &mut event_line)
                .map_err(|e| format!("failed to read SSE event: {e}"))?;
            if n == 0 {
                return Err("connection closed while waiting for endpoint event".to_owned());
            }
            let trimmed = event_line.trim();
            if trimmed.starts_with("data:") {
                post_path = trimmed
                    .strip_prefix("data:")
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                break;
            }
        }

        if post_path.is_empty() {
            return Err("SSE endpoint event did not contain a POST path".to_owned());
        }

        if post_path.bytes().any(|b| b < 0x20) {
            return Err("SSE endpoint path contains invalid control characters".to_owned());
        }

        // Build the full POST URL. Always http — HTTPS is rejected at entry.
        let post_url = format!("http://{host}:{port}{post_path}");

        Ok(Self {
            _url: url.to_owned(),
            post_url,
            auth_header,
            sse_reader: Mutex::new(Some(reader)),
            close: Arc::new(SseCloseState {
                closed: AtomicBool::new(false),
                sse_stream,
                in_flight: Mutex::new(Vec::new()),
                next_post: AtomicU64::new(0),
            }),
        })
    }

    /// Returns a closer that ends this transport from another thread, waking
    /// any call blocked on the server (see [`SseCloser`]).
    #[must_use]
    pub fn closer(&self) -> SseCloser {
        SseCloser(Arc::clone(&self.close))
    }

    /// Opens a connection to the session's POST URL. It sets no timeout:
    /// [`SseClientTransport::exchange_post`] says why.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL does not parse or the connection fails.
    fn open_post(&self) -> Result<TcpStream, String> {
        let (host, port, _) = parse_http_url(&self.post_url)?;
        open_stream(&format!("{host}:{port}"), !self.auth_header.is_empty())
    }

    /// Writes one JSON-RPC message as a POST to `stream`, a connection to the
    /// session's POST URL, and reads the answer's status line.
    ///
    /// The connection has no read timeout. An SCP SSE server writes the
    /// POST's status line only after it has run the message and broadcast
    /// the response, so the wait covers the call itself (a `tools/call`
    /// waits on its outlet for up to the outlet's timeout) and any wait for
    /// the server lock. A deadline here would fail calls the server ran, and a caller
    /// that retried would run them twice. A server that exits closes the
    /// connection, which ends the read.
    ///
    /// # Errors
    ///
    /// Returns an error when the write or the read fails, when the
    /// connection closes before the status line, and when the server answers
    /// outside 2xx.
    fn exchange_post(&self, stream: &TcpStream, body: &str) -> Result<(), String> {
        let (host, _, path) = parse_http_url(&self.post_url)?;
        let mut writer = std::io::BufWriter::new(stream);
        let head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             {}\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            self.auth_header,
            body.len()
        );
        writer
            .write_all(head.as_bytes())
            .map_err(|e| format!("failed to send POST: {e}"))?;
        writer
            .write_all(body.as_bytes())
            .map_err(|e| format!("failed to write POST body: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush POST: {e}"))?;
        drop(writer);
        let mut status_line = String::new();
        let n = read_line_bounded(&mut BufReader::new(stream), &mut status_line)
            .map_err(|e| format!("failed to read POST status line: {e}"))?;
        if n == 0 {
            return Err("connection closed before the POST's HTTP status line".to_owned());
        }
        let status_code = http_status(&status_line);
        if !(200..300).contains(&status_code) {
            return Err(format!(
                "SSE POST returned HTTP {status_code}: {}",
                status_line.trim()
            ));
        }
        Ok(())
    }

    /// Fails once an [`SseCloser`] closed the transport, or once a call has
    /// seen the stream close. A closed stream means the server ended the
    /// session (a newer `GET`, a lagged stream, a shutdown), so no POST is
    /// sent under it.
    ///
    /// # Errors
    ///
    /// Returns [`SSE_CLOSED`] when the transport was closed or the stream has
    /// closed.
    fn ensure_open(&self) -> Result<(), String> {
        if self.close.closed.load(Ordering::SeqCst) {
            return Err(SSE_CLOSED.to_owned());
        }
        let closed = self
            .sse_reader
            .lock()
            .map_err(|e| format!("SSE reader lock poisoned: {e}"))?
            .is_none();
        if closed {
            return Err(SSE_CLOSED.to_owned());
        }
        Ok(())
    }

    /// POSTs one JSON-RPC message to the session's POST URL and reads the
    /// answer's status line. The POST's socket is registered with the
    /// transport's [`SseCloser`] once it connects and before any byte is
    /// written, so `close` ends the write and the wait. A close does not end
    /// a connect in progress.
    ///
    /// # Errors
    ///
    /// Returns [`SSE_CLOSED`] when an [`SseCloser`] closed the transport
    /// before or during the call. Returns an error when the connection or
    /// write fails, or when the server answers outside 2xx: 401 when its
    /// bearer check refuses the token, 409 when a newer `GET` took the session
    /// over, 400 or 413 for a refused body.
    fn post(&self, body: &str) -> Result<(), String> {
        let opened = self.open_post();
        if self.close.closed.load(Ordering::SeqCst) {
            return Err(SSE_CLOSED.to_owned());
        }
        let stream = opened?;
        let key = self.register_post(&stream)?;
        let exchanged = self.exchange_post(&stream, body);
        self.unregister_post(key);
        if self.close.closed.load(Ordering::SeqCst) {
            return Err(SSE_CLOSED.to_owned());
        }
        exchanged
    }

    /// Registers a clone of a POST's socket for [`SseCloser::close`] and
    /// returns its key. The closed flag is read under the registry's lock,
    /// which `close` takes after setting it, so a POST registered after a
    /// close sees the flag and a POST registered before it is shut down.
    ///
    /// # Errors
    ///
    /// Returns [`SSE_CLOSED`] when the transport was closed, and an error
    /// when the socket cannot be cloned or the registry's lock is poisoned.
    fn register_post(&self, stream: &TcpStream) -> Result<u64, String> {
        let clone = stream
            .try_clone()
            .map_err(|e| format!("failed to clone POST stream: {e}"))?;
        let mut in_flight = self
            .close
            .in_flight
            .lock()
            .map_err(|e| format!("SSE in-flight lock poisoned: {e}"))?;
        if self.close.closed.load(Ordering::SeqCst) {
            return Err(SSE_CLOSED.to_owned());
        }
        let key = self.close.next_post.fetch_add(1, Ordering::Relaxed);
        in_flight.push((key, clone));
        drop(in_flight);
        Ok(key)
    }

    /// Removes the POST socket registered under `key`; a close may already
    /// have taken it.
    fn unregister_post(&self, key: u64) {
        let mut in_flight = match self.close.in_flight.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        in_flight.retain(|(k, _)| *k != key);
    }
}

impl McpTransport for SseClientTransport {
    /// Reads the stream until the response to `request` arrives.
    ///
    /// No count of skipped lines ends the wait. The stream is read only
    /// during a call, so every keep-alive and pushed notification (one
    /// `resources/updated` per subscription per context event) since the last
    /// call waits ahead of the response, and an SCP SSE server answers the
    /// POST only after it has run the call. A call failed on a count would
    /// fail a call the server ran, and a caller that retried would run it
    /// twice. The stream's 30-second read timeout still ends a stalled read,
    /// and an SCP SSE server writes a keep-alive every 15 seconds.
    ///
    /// # Errors
    ///
    /// Returns an error when the stream has closed, before any POST, when the
    /// POST fails, when a read fails or times out, when the stream closes
    /// during the wait, on a `data:` line that is not JSON, and on a `data:`
    /// line carrying this request's `id` that is not a valid response. A
    /// closed stream stays closed: the server has ended the session, and the
    /// caller connects a new transport. Returns
    /// [`SSE_CLOSED`] when an [`SseCloser`] closed the transport before or
    /// during the call.
    #[allow(clippy::significant_drop_tightening)] // sse_reader MutexGuard is borrowed by reader across the entire loop.
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        let body = serde_json::to_string(request)
            .map_err(|e| format!("failed to serialize request: {e}"))?;
        // The call holds the stream from before its POST until its response
        // arrives, so calls on one transport run one at a time: a second
        // call's POST goes out only after the first call returned, and no
        // call can read and skip the response of a call still waiting.
        // `ensure_open` takes this lock, so its checks are repeated here.
        let mut sse_reader = self
            .sse_reader
            .lock()
            .map_err(|e| format!("SSE reader lock poisoned: {e}"))?;
        if self.close.closed.load(Ordering::SeqCst) {
            return Err(SSE_CLOSED.to_owned());
        }
        let reader = sse_reader.as_mut().ok_or(SSE_CLOSED)?;
        self.post(&body)?;

        // The server accepted the POST; the JSON-RPC response comes on the
        // SSE stream. Read SSE events until the response to this request
        // arrives. Calls run one at a time, so a response under another id
        // answers an earlier request whose call already failed (a read
        // timeout, say); handing it to this call would shift every later
        // reply by one.
        loop {
            let mut line = String::new();
            let read = read_line_bounded(reader, &mut line);
            if self.close.closed.load(Ordering::SeqCst) {
                *sse_reader = None;
                return Err(SSE_CLOSED.to_owned());
            }
            let n = read.map_err(|e| format!("failed to read SSE event: {e}"))?;
            if n == 0 {
                *sse_reader = None;
                return Err(
                    "SSE connection closed while waiting for response; connect a new transport"
                        .to_owned(),
                );
            }
            let trimmed = line.trim();
            if trimmed.starts_with("data:") {
                let data = trimmed.strip_prefix("data:").unwrap_or("").trim();
                // Every `data:` line after the `endpoint` event carries one
                // JSON-RPC message, so a line that is not JSON fails the call,
                // as it does on the stdio transport.
                let value = serde_json::from_str::<serde_json::Value>(data)
                    .map_err(|e| format!("failed to parse response JSON: {e}"))?;
                // A notification has no id, and a server-initiated request
                // carries a method; `JsonRpcResponse` would accept the
                // request's shape, so skip it before deserializing.
                let Some(line_id) = value.get("id") else {
                    continue;
                };
                if value.get("method").is_some() {
                    continue;
                }
                if serde_json::from_value::<RequestId>(line_id.clone())
                    .ok()
                    .as_ref()
                    != Some(&request.id)
                {
                    continue;
                }
                // The server answers each id once, so a malformed answer
                // under this call's id fails the call; skipping it would
                // wait for a response that never comes.
                return serde_json::from_value(value)
                    .map_err(|e| format!("failed to parse response JSON: {e}"));
            }
        }
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        let body = serde_json::to_string(notification)
            .map_err(|e| format!("failed to serialize notification: {e}"))?;
        self.ensure_open()?;
        self.post(&body)
    }
}

/// Parses an HTTP URL into (host, port, path).
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let (scheme, rest) = if let Some(s) = url.strip_prefix("https://") {
        ("https", s)
    } else if let Some(s) = url.strip_prefix("http://") {
        ("http", s)
    } else {
        return Err(format!("unsupported URL scheme in '{url}'"));
    };

    // Reject control characters (CRLF injection defense).
    if rest.bytes().any(|b| b < 0x20) {
        return Err("URL contains invalid control characters".to_owned());
    }

    let default_port: u16 = if scheme == "https" { 443 } else { 80 };

    let (host_port, path) = rest
        .find('/')
        .map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));

    let (host, port) = if let Some(colon_idx) = host_port.rfind(':') {
        let h = &host_port[..colon_idx];
        let p_str = &host_port[colon_idx + 1..];
        let p = p_str
            .parse::<u16>()
            .map_err(|e| format!("invalid port '{p_str}': {e}"))?;
        (h.to_owned(), p)
    } else {
        (host_port.to_owned(), default_port)
    };

    Ok((host, port, path.to_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // URL parsing
    // -----------------------------------------------------------------------

    /// The transport has no TLS, so a bearer token goes only to a loopback
    /// address: a token for any other host is refused before a connection
    /// opens, and a loopback host passes the check.
    #[test]
    fn connect_refuses_to_send_a_token_to_a_non_loopback_host() {
        let Err(err) = SseClientTransport::connect("http://192.0.2.1:9/sse", Some("tok")) else {
            panic!("a token for a non-loopback host must be refused");
        };
        assert!(
            err.contains("refusing to send the SSE bearer token"),
            "got: {err}"
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let Err(err) =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok"))
        else {
            panic!("nothing listens on the port");
        };
        assert!(
            err.starts_with("failed to connect"),
            "a loopback host must pass the check and fail only at connect, got: {err}"
        );
    }

    #[test]
    fn parse_http_url_basic() {
        let (host, port, path) = parse_http_url("http://localhost:3000/sse").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 3000);
        assert_eq!(path, "/sse");
    }

    #[test]
    fn parse_http_url_default_port() {
        let (host, port, path) = parse_http_url("http://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");
    }

    #[test]
    fn parse_https_url_default_port() {
        let (host, port, path) = parse_http_url("https://example.com/api").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api");
    }

    #[test]
    fn parse_http_url_no_path() {
        let (host, port, path) = parse_http_url("http://localhost:8080").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_http_url_unsupported_scheme() {
        let result = parse_http_url("ftp://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn parse_http_url_rejects_crlf_injection() {
        let result = parse_http_url("http://evil.com\r\nX-Injected: bad/path");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("control characters"),
            "should mention control characters in error"
        );
    }

    #[test]
    fn parse_http_url_rejects_null_byte() {
        let result = parse_http_url("http://evil.com\0/path");
        assert!(result.is_err());
    }

    #[test]
    fn sse_connect_rejects_https() {
        let result = SseClientTransport::connect("https://example.com/sse", None);
        match result {
            Err(msg) => assert!(msg.contains("TLS"), "should mention TLS in error: {msg}"),
            Ok(_) => panic!("expected error for https URL"),
        }
    }

    /// Reads one HTTP request from `stream`: its head, up to the blank line,
    /// and then its `Content-Length` body, so the connection closes with
    /// nothing unread.
    fn read_request(stream: &std::net::TcpStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            let n = std::io::BufRead::read_line(&mut reader, &mut line).expect("read head");
            if n == 0 || line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        let length = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .map_or(0, |v| v.trim().parse::<usize>().expect("length"));
        let mut body = vec![0_u8; length];
        std::io::Read::read_exact(&mut reader, &mut body).expect("read body");
        head
    }

    /// Accepts the `GET`, answers it with the `endpoint` event, and returns
    /// the `GET` head with the open stream.
    fn accept_sse(listener: &std::net::TcpListener) -> (String, std::net::TcpStream) {
        let (mut sse, _) = listener.accept().expect("accept GET");
        let get = read_request(&sse);
        sse.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
              event: endpoint\r\ndata: /message?sessionId=s1\r\n\r\n",
        )
        .expect("write endpoint event");
        (get, sse)
    }

    fn request(id: i64) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: crate::protocol::JSONRPC_VERSION.to_owned(),
            method: "tools/list".to_owned(),
            params: None,
            id: crate::protocol::RequestId::Number(id),
        }
    }

    /// The SSE client sends its token on the `GET`, on a request's POST and
    /// on a notification's POST, so it passes the bearer check an SCP SSE
    /// server always runs. A request's call skips a response under another
    /// id, a late reply to an earlier call, and returns its own.
    #[test]
    fn sse_client_sends_the_bearer_token_on_every_request() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (get, mut sse) = accept_sse(&listener);
            let (mut request_conn, _) = listener.accept().expect("accept request POST");
            let request_head = read_request(&request_conn);
            request_conn
                .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .expect("answer request POST");
            sse.write_all(
                b"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"late\":true}}\r\n\r\n\
                  event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"late\":false}}\r\n\r\n",
            )
            .expect("write responses");
            let (mut notification_conn, _) = listener.accept().expect("accept notification POST");
            let notification_head = read_request(&notification_conn);
            notification_conn
                .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .expect("answer notification POST");
            (get, request_head, notification_head, sse)
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let response = transport.send_request(&request(7)).expect("request");
        assert_eq!(response.id, crate::protocol::RequestId::Number(7));
        assert_eq!(
            response.result,
            Some(serde_json::json!({"late": false})),
            "the id-6 reply belongs to an earlier call"
        );
        transport
            .send_notification(&JsonRpcNotification::new("notifications/initialized", None))
            .expect("notify");
        let (get_head, request_head, notification_head, _sse) =
            server.join().expect("server thread");
        for head in [&get_head, &request_head, &notification_head] {
            assert!(
                head.contains("\r\nAuthorization: Bearer tok-1\r\n"),
                "every request must carry the token, got: {head}"
            );
        }
    }

    /// Accepts one POST on a nonblocking `listener` within `wait`, answers it
    /// 202, and returns its JSON-RPC id; `None` when no POST arrived.
    fn accept_post_within(
        listener: &std::net::TcpListener,
        wait: std::time::Duration,
    ) -> Option<i64> {
        let deadline = std::time::Instant::now() + wait;
        loop {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    conn.set_nonblocking(false).expect("blocking POST");
                    let mut reader = BufReader::new(&conn);
                    let mut head = String::new();
                    loop {
                        let mut line = String::new();
                        let n = std::io::BufRead::read_line(&mut reader, &mut line).expect("head");
                        if n == 0 || line == "\r\n" {
                            break;
                        }
                        head.push_str(&line);
                    }
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .map_or(0, |v| v.trim().parse::<usize>().expect("length"));
                    let mut body = vec![0_u8; length];
                    std::io::Read::read_exact(&mut reader, &mut body).expect("body");
                    conn.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                        .expect("answer POST");
                    let value: serde_json::Value =
                        serde_json::from_slice(&body).expect("JSON body");
                    return Some(value["id"].as_i64().expect("numeric id"));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("accept POST: {e}"),
            }
        }
    }

    /// Writes the response to request `id` on the SSE stream.
    fn write_response(sse: &mut std::net::TcpStream, id: i64) {
        sse.write_all(
            format!(
                "event: message\r\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"id\":{id}}}}}\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write response");
    }

    /// Two calls on one shared transport run one at a time: the second
    /// call's POST goes out only after the first call has its response, so
    /// neither call reads and skips the other's response, and each returns
    /// its own. The server holds the first call's response back for 500 ms
    /// and records whether a second POST arrived in that window; when one
    /// does, it answers both and closes the stream, so a call that lost its
    /// response fails instead of hanging the test.
    #[test]
    fn sse_client_runs_concurrent_calls_on_one_transport_one_at_a_time() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (_, mut sse) = accept_sse(&listener);
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let long = std::time::Duration::from_secs(20);
            let first = accept_post_within(&listener, long).expect("first POST");
            let overlap = accept_post_within(&listener, std::time::Duration::from_millis(500));
            write_response(&mut sse, first);
            if let Some(second) = overlap {
                write_response(&mut sse, second);
                std::thread::sleep(std::time::Duration::from_millis(500));
                let _ = sse.shutdown(Shutdown::Both);
                return true;
            }
            let second = accept_post_within(&listener, long).expect("second POST");
            write_response(&mut sse, second);
            false
        });

        let transport = Arc::new(
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect"),
        );
        // Both calls must be spawned before either is joined: each waits on
        // the barrier of two, so joining the first before the second exists
        // would hang the test instead of failing it.
        let start = Arc::new(std::sync::Barrier::new(2));
        let spawn_call = |id: i64| {
            let transport = Arc::clone(&transport);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                (id, transport.send_request(&request(id)))
            })
        };
        let first = spawn_call(5);
        let second = spawn_call(6);
        let results = [
            first.join().expect("call thread"),
            second.join().expect("call thread"),
        ];
        let overlapped = server.join().expect("server thread");
        assert!(
            !overlapped,
            "a second POST went out while the first call waited for its response"
        );
        for (id, result) in results {
            let response = result.unwrap_or_else(|e| panic!("call {id} failed: {e}"));
            assert_eq!(response.id, crate::protocol::RequestId::Number(id));
            assert_eq!(response.result, Some(serde_json::json!({"id": id})));
        }
    }

    /// A POST the server refuses fails the call with the status, for a
    /// request and for a notification, rather than reporting a delivered
    /// notification or waiting out the stream's read timeout.
    #[test]
    fn sse_client_fails_a_call_whose_post_the_server_refuses() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (_, sse) = accept_sse(&listener);
            for status in ["401 Unauthorized", "409 Conflict"] {
                let (mut conn, _) = listener.accept().expect("accept POST");
                read_request(&conn);
                conn.write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                )
                .expect("refuse POST");
            }
            sse
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let started = std::time::Instant::now();
        let request_err = transport
            .send_request(&request(1))
            .expect_err("a refused request POST must fail");
        assert!(request_err.contains("HTTP 401"), "got: {request_err}");
        let notification_err = transport
            .send_notification(&JsonRpcNotification::new("notifications/initialized", None))
            .expect_err("a refused notification POST must fail");
        assert!(
            notification_err.contains("HTTP 409"),
            "got: {notification_err}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "a refused POST must fail at once, not after the stream's read timeout"
        );
        drop(server.join().expect("server thread"));
    }

    /// A POST's connection carries no read timeout, and a call whose POST
    /// the server answers only after broadcasting the response still
    /// succeeds. An SCP SSE server answers each POST after it has run the
    /// call, so a read deadline on the POST would fail calls the server ran.
    #[test]
    fn sse_client_waits_for_a_post_answer_sent_after_the_call_ran() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (_, mut sse) = accept_sse(&listener);
            let (mut probe, _) = listener.accept().expect("accept probe POST");
            read_request(&probe);
            // The client may already have dropped the probe connection.
            let _ = probe.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n");
            let (mut conn, _) = listener.accept().expect("accept request POST");
            read_request(&conn);
            sse.write_all(
                b"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}\r\n\r\n",
            )
            .expect("write response");
            std::thread::sleep(std::time::Duration::from_millis(300));
            conn.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .expect("answer request POST");
            sse
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let probe = transport.open_post().expect("probe POST");
        assert_eq!(
            probe.read_timeout().expect("read timeout"),
            None,
            "the POST's answer comes after the call ran, so its read must have no deadline"
        );
        drop(probe);
        let response = transport.send_request(&request(3)).expect("request");
        assert_eq!(response.id, crate::protocol::RequestId::Number(3));
        drop(server.join().expect("server thread"));
    }

    /// Keep-alives and pushed notifications that piled up between calls do
    /// not fail the next call however many there are: the server has run the
    /// call when it answers the POST, so its response is on the stream
    /// behind them.
    #[test]
    fn sse_client_reads_past_any_backlog_to_its_response() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (_, mut sse) = accept_sse(&listener);
            let (mut conn, _) = listener.accept().expect("accept request POST");
            read_request(&conn);
            let mut backlog = String::new();
            for id in 0..2000 {
                backlog.push_str(":keepalive\r\n\r\n");
                std::fmt::Write::write_fmt(&mut backlog, format_args!(
                    "event: message\r\nid: {id}\r\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",\"params\":{{\"uri\":\"scp://c/events\"}}}}\r\n\r\n"
                )).expect("format backlog");
            }
            backlog.push_str(
                "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{}}\r\n\r\n",
            );
            let writer = std::thread::spawn(move || {
                sse.write_all(backlog.as_bytes()).expect("write backlog");
                sse
            });
            conn.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .expect("answer request POST");
            writer.join().expect("writer thread")
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let response = transport
            .send_request(&request(5))
            .expect("a backlog must not fail a call the server ran");
        assert_eq!(response.id, crate::protocol::RequestId::Number(5));
        drop(server.join().expect("server thread"));
    }

    /// A server-initiated request (`ping`) under the call's own id is not the
    /// call's response: the call skips it and returns the response behind it.
    #[test]
    fn sse_client_skips_a_server_request_under_its_own_id() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (_, mut sse) = accept_sse(&listener);
            let (mut conn, _) = listener.accept().expect("accept request POST");
            read_request(&conn);
            sse.write_all(
                b"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n\r\n\
                  event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\r\n\r\n",
            )
            .expect("write events");
            conn.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .expect("answer request POST");
            sse
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let response = transport.send_request(&request(1)).expect("request");
        assert_eq!(response.id, crate::protocol::RequestId::Number(1));
        assert_eq!(response.result, Some(serde_json::json!({"ok": true})));
        assert!(response.error.is_none());
        drop(server.join().expect("server thread"));
    }

    /// Runs one call whose response stream carries `events`, then an
    /// answer the call must never reach, and returns the call's result. The
    /// server keeps the stream open, so a call that skipped every event would
    /// return the trailing valid response instead of failing.
    fn call_against(events: &'static str, id: i64) -> Result<JsonRpcResponse, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (_, mut sse) = accept_sse(&listener);
            let (mut conn, _) = listener.accept().expect("accept request POST");
            read_request(&conn);
            sse.write_all(events.as_bytes()).expect("write events");
            sse.write_all(
                format!(
                    "event: message\r\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"late\":true}}}}\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("write trailing response");
            conn.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .expect("answer request POST");
            sse
        });
        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let result = transport.send_request(&request(id));
        drop(server.join().expect("server thread"));
        result
    }

    /// A malformed answer under the call's own id fails the call, as it does
    /// on the stdio transport: the server answers each id once, so skipping
    /// it would wait for a response that never comes. A malformed message
    /// under another id is not this call's, and the call reads past it.
    #[test]
    fn sse_client_fails_a_call_on_a_malformed_answer_under_its_own_id() {
        for (events, what) in [
            (
                "event: message\r\ndata: {\"id\":7,\"result\":{}}\r\n\r\n",
                "no jsonrpc field",
            ),
            (
                "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"error\":\"boom\"}\r\n\r\n",
                "a malformed error object",
            ),
            (
                "event: message\r\ndata: not json\r\n\r\n",
                "a data line that is not JSON",
            ),
        ] {
            let err = call_against(events, 7).expect_err(what);
            assert!(
                err.contains("failed to parse response JSON"),
                "{what}: {err}"
            );
        }

        let response = call_against(
            "event: message\r\ndata: {\"id\":8,\"result\":{}}\r\n\r\n",
            7,
        )
        .expect("a malformed message under another id is not this call's answer");
        assert_eq!(response.id, crate::protocol::RequestId::Number(7));
        assert_eq!(response.result, Some(serde_json::json!({"late": true})));
    }

    /// Once a call sees the stream close, the server has ended the session:
    /// that call fails, and every later call fails before it sends a POST, so
    /// nothing runs under a session no stream can answer.
    #[test]
    fn sse_client_sends_nothing_after_its_stream_closed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (_, sse) = accept_sse(&listener);
            let (mut conn, _) = listener.accept().expect("accept request POST");
            read_request(&conn);
            drop(sse);
            conn.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .expect("answer request POST");
            listener.set_nonblocking(true).expect("nonblocking");
            listener
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let err = transport
            .send_request(&request(1))
            .expect_err("a closed stream must fail the call");
        assert!(err.contains("closed while waiting"), "got: {err}");
        let listener = server.join().expect("server thread");
        let err = transport
            .send_request(&request(2))
            .expect_err("a closed transport must fail");
        assert_eq!(err, SSE_CLOSED);
        let err = transport
            .send_notification(&JsonRpcNotification::new("notifications/initialized", None))
            .expect_err("a closed transport must fail");
        assert_eq!(err, SSE_CLOSED);
        assert!(
            listener.accept().is_err(),
            "no POST may reach the server after the stream closed"
        );
    }

    /// A closer ends a call whose POST the server accepted and never answers:
    /// the POST's connection has no read timeout, so nothing else would. The
    /// call fails with the closed error within a second, and a later call
    /// fails before it sends a POST.
    #[test]
    fn sse_closer_ends_a_call_waiting_on_a_silent_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (_, sse) = accept_sse(&listener);
            let (conn, _) = listener.accept().expect("accept request POST");
            read_request(&conn);
            accepted_tx.send(()).expect("signal accepted POST");
            listener.set_nonblocking(true).expect("nonblocking");
            (listener, sse, conn)
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let closer = transport.closer();
        let closing = std::thread::spawn(move || {
            accepted_rx.recv().expect("POST accepted");
            let closed_at = std::time::Instant::now();
            closer.close();
            closed_at
        });
        let err = transport
            .send_request(&request(1))
            .expect_err("a closed transport must end the call");
        let ended_at = std::time::Instant::now();
        let closed_at = closing.join().expect("closing thread");
        assert_eq!(err, SSE_CLOSED);
        assert!(
            ended_at.duration_since(closed_at) < std::time::Duration::from_secs(1),
            "close must end the blocked call at once"
        );
        let (listener, _sse, _conn) = server.join().expect("server thread");
        let err = transport
            .send_notification(&JsonRpcNotification::new("notifications/initialized", None))
            .expect_err("a closed transport must fail");
        assert_eq!(err, SSE_CLOSED);
        assert!(
            listener.accept().is_err(),
            "no POST may reach the server after close"
        );
    }

    /// A closer ends a call whose POST the server answered but whose response
    /// never arrives on the stream, before the stream's 30-second read
    /// timeout would.
    #[test]
    fn sse_closer_ends_a_call_waiting_on_the_stream() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (answered_tx, answered_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (_, sse) = accept_sse(&listener);
            let (mut conn, _) = listener.accept().expect("accept request POST");
            read_request(&conn);
            conn.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .expect("answer request POST");
            answered_tx.send(()).expect("signal answered POST");
            sse
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let closer = transport.closer();
        let closing = std::thread::spawn(move || {
            answered_rx.recv().expect("POST answered");
            std::thread::sleep(std::time::Duration::from_millis(100));
            let closed_at = std::time::Instant::now();
            closer.close();
            closed_at
        });
        let err = transport
            .send_request(&request(1))
            .expect_err("a closed transport must end the call");
        let ended_at = std::time::Instant::now();
        let closed_at = closing.join().expect("closing thread");
        assert_eq!(err, SSE_CLOSED);
        assert!(
            ended_at.duration_since(closed_at) < std::time::Duration::from_secs(1),
            "close must end the blocked stream read at once"
        );
        drop(server.join().expect("server thread"));
    }

    /// A closer ends a call blocked writing its POST to a server that
    /// accepted the connection and never reads, with a body larger than the
    /// socket buffers, and the call fails with the closed error within a
    /// second.
    #[test]
    fn sse_closer_ends_a_call_blocked_writing_its_post() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (_, sse) = accept_sse(&listener);
            let (conn, _) = listener.accept().expect("accept request POST");
            accepted_tx.send(()).expect("signal accepted POST");
            // Hold the connection unread until the test ends.
            let _ = done_rx.recv();
            drop((sse, conn));
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        let closer = transport.closer();
        let mut big = request(1);
        big.params = Some(serde_json::json!({ "pad": "a".repeat(64 * 1024 * 1024) }));
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = transport.send_request(&big);
            let _ = result_tx.send((result, std::time::Instant::now()));
        });
        accepted_rx.recv().expect("POST accepted");
        // Let the write fill the socket buffers and block.
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            result_rx.try_recv().is_err(),
            "the call must still be writing its POST before the close"
        );
        let closed_at = std::time::Instant::now();
        closer.close();
        let (result, ended_at) = result_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("close must end a call blocked writing its POST");
        assert_eq!(
            result.expect_err("a closed transport must end the call"),
            SSE_CLOSED
        );
        assert!(
            ended_at.duration_since(closed_at) < std::time::Duration::from_secs(1),
            "close must end the blocked write at once"
        );
        drop(done_tx);
        server.join().expect("server thread");
    }

    /// A token that could inject a header line, or an empty one, is refused
    /// before any connection opens.
    #[test]
    fn sse_client_rejects_a_token_that_could_inject_headers() {
        for token in ["", "a\r\nX-Evil: 1", "a b"] {
            assert!(sse_auth_header(Some(token)).is_err(), "{token:?}");
        }
        assert_eq!(sse_auth_header(None).expect("no token"), "");
    }
}
