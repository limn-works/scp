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
/// POST on a fresh connection. A request returns the first JSON-RPC response
/// the stream carries after its POST.
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
    /// Returns an error if the token is malformed, or if the connection or
    /// handshake fails; a server whose bearer check refuses the token answers
    /// HTTP 401, which fails the handshake.
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
        let stream = std::net::TcpStream::connect(&addr)
            .map_err(|e| format!("failed to connect to {addr}: {e}"))?;
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
        // Parse "HTTP/1.1 200 OK" — extract the status code.
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
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
}

/// Maximum number of SSE events to scan for a matching JSON-RPC response.
/// If exceeded, the request fails. The TCP read timeout (30s) handles
/// individual read stalls; this bounds total non-matching events tolerated.
const MAX_SSE_EVENTS: usize = 1000;

impl McpTransport for SseClientTransport {
    #[allow(clippy::significant_drop_tightening)] // sse_reader MutexGuard is borrowed by reader across the entire loop.
    fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        // Parse the POST URL.
        let (host, port, path) = parse_http_url(&self.post_url)?;
        let addr = format!("{host}:{port}");

        // Serialize the request.
        let body = serde_json::to_string(request)
            .map_err(|e| format!("failed to serialize request: {e}"))?;

        // Open a new TCP connection for the POST request.
        let stream = std::net::TcpStream::connect(&addr)
            .map_err(|e| format!("failed to connect to {addr}: {e}"))?;
        let mut writer = std::io::BufWriter::new(
            stream
                .try_clone()
                .map_err(|e| format!("failed to clone stream: {e}"))?,
        );

        // Send HTTP POST.
        let post_request = format!(
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
            .write_all(post_request.as_bytes())
            .map_err(|e| format!("failed to send POST request: {e}"))?;
        writer
            .write_all(body.as_bytes())
            .map_err(|e| format!("failed to write POST body: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush POST: {e}"))?;

        // The SSE server returns 202 Accepted. The actual JSON-RPC response
        // comes via the SSE stream. Read it from the SSE reader.
        let mut sse_reader = self
            .sse_reader
            .lock()
            .map_err(|e| format!("SSE reader lock poisoned: {e}"))?;

        let reader = sse_reader.as_mut().ok_or("SSE connection is closed")?;

        // Read SSE events until we find a `message` event with our response.
        for _ in 0..MAX_SSE_EVENTS {
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
                if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(data) {
                    return Ok(response);
                }
            }
        }
        Err(format!(
            "no matching JSON-RPC response after {MAX_SSE_EVENTS} SSE events"
        ))
    }

    fn send_notification(&self, notification: &JsonRpcNotification) -> Result<(), String> {
        // Parse the POST URL.
        let (host, port, path) = parse_http_url(&self.post_url)?;
        let addr = format!("{host}:{port}");

        let body = serde_json::to_string(notification)
            .map_err(|e| format!("failed to serialize notification: {e}"))?;

        let stream = std::net::TcpStream::connect(&addr)
            .map_err(|e| format!("failed to connect to {addr}: {e}"))?;
        let mut writer = std::io::BufWriter::new(stream);

        let post_request = format!(
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
            .write_all(post_request.as_bytes())
            .map_err(|e| format!("failed to send notification: {e}"))?;
        writer
            .write_all(body.as_bytes())
            .map_err(|e| format!("failed to write notification body: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush notification: {e}"))?;

        Ok(())
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

    /// Reads one HTTP request's head from `stream`, up to the blank line.
    fn read_request_head(stream: &std::net::TcpStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            let n = std::io::BufRead::read_line(&mut reader, &mut line).expect("read head");
            if n == 0 || line == "\r\n" {
                return head;
            }
            head.push_str(&line);
        }
    }

    /// The SSE client sends its token on the `GET` and on every POST, so it
    /// passes the bearer check an SCP SSE server always runs.
    #[test]
    fn sse_client_sends_the_bearer_token_on_every_request() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept GET");
            let get = read_request_head(&sse);
            sse.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
                  event: endpoint\r\ndata: /message?sessionId=s1\r\n\r\n",
            )
            .expect("write endpoint event");
            let (post_conn, _) = listener.accept().expect("accept POST");
            (get, read_request_head(&post_conn))
        });

        let transport =
            SseClientTransport::connect(&format!("http://127.0.0.1:{port}/sse"), Some("tok-1"))
                .expect("connect");
        transport
            .send_notification(&JsonRpcNotification::new("notifications/initialized", None))
            .expect("notify");
        let (get_head, post_head) = server.join().expect("server thread");
        for head in [&get_head, &post_head] {
            assert!(
                head.contains("\r\nAuthorization: Bearer tok-1\r\n"),
                "every request must carry the token, got: {head}"
            );
        }
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
