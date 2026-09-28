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
use std::sync::Mutex;

use crate::client::McpTransport;
use crate::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use crate::stdio::read_line_bounded;

/// MCP client transport that communicates via HTTP SSE.
///
/// Holds the `GET` stream open for the session and sends each message as a
/// POST on a fresh connection. A POST the server answers outside 2xx fails
/// the call. A request returns the first JSON-RPC response on the stream whose
/// `id` is the request's, and skips every other response.
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
fn sse_auth_header(auth_token: Option<&str>) -> Result<String, String> {
    let Some(token) = auth_token else {
        return Ok(String::new());
    };
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("SSE auth token must be non-empty visible ASCII".to_owned());
    }
    Ok(format!("Authorization: Bearer {token}\r\n"))
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
        let get_request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             {auth_header}\
             Accept: text/event-stream\r\n\
             Connection: keep-alive\r\n\
             \r\n"
        );
        writer
            .write_all(get_request.as_bytes())
            .map_err(|e| format!("failed to send GET request: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush GET request: {e}"))?;

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
        })
    }

    /// Opens a connection to the session's POST URL and writes one JSON-RPC
    /// message to it, returning the connection with its answer unread.
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
    /// Returns an error when the connection or the write fails.
    fn send_post(&self, body: &str) -> Result<std::net::TcpStream, String> {
        let (host, port, path) = parse_http_url(&self.post_url)?;
        let addr = format!("{host}:{port}");
        let stream = open_stream(&addr, !self.auth_header.is_empty())?;
        let mut writer = std::io::BufWriter::new(&stream);
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
        Ok(stream)
    }

    /// POSTs one JSON-RPC message to the session's POST URL and reads the
    /// answer's status line.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection or write fails, or when the server
    /// answers outside 2xx: 401 when its bearer check refuses the token, 409
    /// when a newer `GET` took the session over, 400 or 413 for a refused body.
    fn post(&self, body: &str) -> Result<(), String> {
        let stream = self.send_post(body)?;

        let mut status_line = String::new();
        let n = read_line_bounded(&mut BufReader::new(&stream), &mut status_line)
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
}

/// Maximum number of SSE stream lines to scan for a matching JSON-RPC response.
/// If exceeded, the request fails. The TCP read timeout (30s) handles
/// individual read stalls; this bounds the non-matching lines tolerated. An
/// event takes at least two lines (a `data:` line and the blank line ending
/// it), so the bound admits at most 500 events.
const MAX_SSE_LINES: usize = 1000;

impl McpTransport for SseClientTransport {
    #[allow(clippy::significant_drop_tightening)] // sse_reader MutexGuard is borrowed by reader across the entire loop.
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        let body = serde_json::to_string(request)
            .map_err(|e| format!("failed to serialize request: {e}"))?;
        self.post(&body)?;

        // The server accepted the POST; the JSON-RPC response comes on the
        // SSE stream.
        let mut sse_reader = self
            .sse_reader
            .lock()
            .map_err(|e| format!("SSE reader lock poisoned: {e}"))?;

        let reader = sse_reader.as_mut().ok_or("SSE connection is closed")?;

        // Read SSE events until the response to this request arrives. A
        // response under another id answers an earlier request whose call
        // already failed (a read timeout, say); handing it to this call would
        // shift every later reply by one.
        for _ in 0..MAX_SSE_LINES {
            let mut line = String::new();
            let n = read_line_bounded(reader, &mut line)
                .map_err(|e| format!("failed to read SSE event: {e}"))?;
            if n == 0 {
                return Err("SSE connection closed while waiting for response".to_owned());
            }
            let trimmed = line.trim();
            if trimmed.starts_with("data:") {
                let data = trimmed.strip_prefix("data:").unwrap_or("").trim();
                // Try to parse as a JSON-RPC response.
                if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(data)
                    && response.id == request.id
                {
                    return Ok(response);
                }
            }
        }
        Err(format!(
            "no matching JSON-RPC response after {MAX_SSE_LINES} SSE lines"
        ))
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        let body = serde_json::to_string(notification)
            .map_err(|e| format!("failed to serialize notification: {e}"))?;
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
        let probe = transport.send_post("{}").expect("probe POST");
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
