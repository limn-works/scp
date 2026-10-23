//! A local HTTP/2 (h2c) server for the push sender tests and the relay's
//! end-to-end wake tests (PUSH-008, PUSH-010, PUSH-011). Compiled only under
//! `cfg(test)`; the tests never reach Apple or Google.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// One request the server received.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    /// Every regular header, lowercase name first, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl CapturedRequest {
    /// The first value of header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A canned response.
#[derive(Debug, Clone)]
pub struct Reply {
    status: u16,
    body: Vec<u8>,
    content_type: Option<&'static str>,
}

impl Reply {
    /// A response with `status` and no body.
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            body: Vec::new(),
            content_type: None,
        }
    }
}

/// A JSON response with `status` and `body`.
pub fn json_reply(status: u16, body: &serde_json::Value) -> Reply {
    Reply {
        status,
        body: body.to_string().into_bytes(),
        content_type: Some("application/json"),
    }
}

/// The status the server answers when no canned reply is left; a test that
/// sends more than it scripted sees `ConfigError` and fails its assertion.
const UNSCRIPTED_STATUS: u16 = 418;

type Routes = Arc<Mutex<Vec<(String, VecDeque<Reply>)>>>;

/// An h2c server on `127.0.0.1` that answers each request with the next canned
/// reply of the first route whose path prefix matches, and records it.
pub struct TestServer {
    origin: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    /// A server that answers every path from `replies`, in order.
    pub async fn start(replies: Vec<Reply>) -> Self {
        Self::start_routed(vec![("/", replies)]).await
    }

    /// A server whose replies are chosen by path prefix.
    pub async fn start_routed(routes: Vec<(&str, Vec<Reply>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let routes: Routes = Arc::new(Mutex::new(
            routes
                .into_iter()
                .map(|(prefix, replies)| (prefix.to_owned(), replies.into()))
                .collect(),
        ));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let requests = requests.clone();
            async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        return;
                    };
                    let routes = routes.clone();
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let Ok(mut connection) = h2::server::handshake(socket).await else {
                            return;
                        };
                        // Each stream is served on its own task: reading a
                        // request body needs `accept` to keep driving the
                        // connection.
                        while let Some(Ok((request, respond))) = connection.accept().await {
                            let routes = routes.clone();
                            let requests = requests.clone();
                            tokio::spawn(async move {
                                serve(request, respond, &routes, &requests).await;
                            });
                        }
                    });
                }
            }
        });
        Self {
            origin,
            requests,
            task,
        }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn origin(&self) -> String {
        self.origin.clone()
    }

    /// Every request received so far, in arrival order.
    pub async fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().await.clone()
    }

    /// An origin nothing listens on, held for as long as the returned
    /// [`ClosedOrigin`] lives: a send to it fails to connect.
    pub fn closed_origin() -> ClosedOrigin {
        ClosedOrigin::reserve()
    }
}

/// A loopback port bound but never listening. A connection to it is refused,
/// and while this value lives no other socket, in this process or another
/// test process, can bind the port and answer in its place. Releasing the
/// port instead would let a concurrent test's [`TestServer`] bind it and take
/// one of that server's scripted replies.
pub struct ClosedOrigin {
    origin: String,
    _reserved: TcpSocket,
}

impl ClosedOrigin {
    fn reserve() -> Self {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let origin = format!("http://{}", socket.local_addr().unwrap());
        Self {
            origin,
            _reserved: socket,
        }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// An h2c server on `127.0.0.1` that completes the HTTP/2 handshake, accepts
/// the first request, and then stops reading the connection while holding it
/// open: it answers nothing and acknowledges no PING, as a push service whose
/// path died mid-connection does.
pub struct FrozenServer {
    origin: String,
    took: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl Drop for FrozenServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FrozenServer {
    /// Starts the server.
    pub async fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let took = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let took = took.clone();
            async move {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut connection) = h2::server::handshake(socket).await else {
                    return;
                };
                if let Some(Ok(held)) = connection.accept().await {
                    took.store(true, Ordering::SeqCst);
                    // Hold the connection and the stream, never polling
                    // either again, until the test drops the server.
                    let _held = (connection, held);
                    std::future::pending::<()>().await;
                }
            }
        });
        Ok(Self { origin, took, task })
    }

    /// `http://127.0.0.1:<port>`.
    pub fn origin(&self) -> String {
        self.origin.clone()
    }

    /// Whether the first request's headers arrived.
    pub fn took_a_request(&self) -> bool {
        self.took.load(Ordering::SeqCst)
    }
}

async fn serve(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    routes: &Routes,
    requests: &Mutex<Vec<CapturedRequest>>,
) {
    let (parts, mut body) = request.into_parts();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        bytes.extend_from_slice(&chunk);
    }
    let path = parts.uri.path().to_owned();
    requests.lock().await.push(CapturedRequest {
        method: parts.method.as_str().to_owned(),
        path: path.clone(),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_owned(),
                    v.to_str().unwrap_or("<non-utf8>").to_owned(),
                )
            })
            .collect(),
        body: bytes,
    });
    let reply = routes
        .lock()
        .await
        .iter_mut()
        .find(|(prefix, _)| path.starts_with(prefix.as_str()))
        .and_then(|(_, replies)| replies.pop_front())
        .unwrap_or_else(|| Reply::empty(UNSCRIPTED_STATUS));
    let mut response = http::Response::builder().status(reply.status);
    if let Some(content_type) = reply.content_type {
        response = response.header("content-type", content_type);
    }
    let Ok(mut stream) = respond.send_response(response.body(()).unwrap(), reply.body.is_empty())
    else {
        return;
    };
    if !reply.body.is_empty() {
        let _ = stream.send_data(Bytes::from(reply.body), true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_origin_refuses_connections_and_keeps_its_port_from_other_binds() {
        let closed = TestServer::closed_origin();
        let addr = closed.origin().trim_start_matches("http://").to_owned();
        assert!(tokio::net::TcpStream::connect(&addr).await.is_err());
        assert!(TcpListener::bind(&addr).await.is_err(), "{addr} rebound");
    }
}
