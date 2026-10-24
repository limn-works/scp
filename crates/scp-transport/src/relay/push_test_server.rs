//! A local HTTP/2 server for the push sender tests and the relay's
//! end-to-end wake tests (PUSH-008, PUSH-010, PUSH-011, PUSH-022): h2c for the
//! APNs and FCM senders, and h2 over TLS for the `WebPush` sender, which sends
//! only to `https` endpoints. Compiled only under `cfg(test)`; the tests never
//! reach Apple, Google or a browser push service.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

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
    /// Never answer: hold the stream open, as a push service that stopped
    /// answering does.
    hang: bool,
}

impl Reply {
    /// A response with `status` and no body.
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            body: Vec::new(),
            content_type: None,
            hang: false,
        }
    }

    /// No response at all: the request is recorded and its stream held open
    /// until the server is dropped.
    pub fn hang() -> Self {
        Self {
            hang: true,
            ..Self::empty(UNSCRIPTED_STATUS)
        }
    }
}

/// A JSON response with `status` and `body`.
pub fn json_reply(status: u16, body: &serde_json::Value) -> Reply {
    Reply {
        status,
        body: body.to_string().into_bytes(),
        content_type: Some("application/json"),
        hang: false,
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
        Self::serve_on(listener, origin, routes, None)
    }

    /// Serves `routes` on `listener`, over TLS when `tls` is given.
    fn serve_on(
        listener: TcpListener,
        origin: String,
        routes: Vec<(&str, Vec<Reply>)>,
        tls: Option<TlsAcceptor>,
    ) -> Self {
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
                    let tls = tls.clone();
                    tokio::spawn(async move {
                        match tls {
                            None => serve_connection(socket, routes, requests).await,
                            Some(acceptor) => {
                                let Ok(stream) = acceptor.accept(socket).await else {
                                    return;
                                };
                                serve_connection(stream, routes, requests).await;
                            }
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

/// Serves every stream of one HTTP/2 connection.
async fn serve_connection<S>(socket: S, routes: Routes, requests: Arc<Mutex<Vec<CapturedRequest>>>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(socket).await else {
        return;
    };
    // Each stream is served on its own task: reading a request body needs
    // `accept` to keep driving the connection.
    while let Some(Ok((request, respond))) = connection.accept().await {
        let routes = routes.clone();
        let requests = requests.clone();
        tokio::spawn(async move {
            serve(request, respond, &routes, &requests).await;
        });
    }
}

/// The host names a [`TlsTestServer`] certificate covers. A `WebPush` test
/// points each at `127.0.0.1` through its resolver; two names are two
/// endpoint origins on one server.
pub const TLS_TEST_HOSTS: [&str; 2] = ["push.example.net", "hung.example.net"];

/// An HTTP/2-over-TLS server on `127.0.0.1` with a fresh self-signed
/// certificate for [`TLS_TEST_HOSTS`], offering only `h2` in ALPN. Replies
/// are chosen by path prefix as for [`TestServer`].
pub struct TlsTestServer {
    server: TestServer,
    port: u16,
    root: reqwest::Certificate,
}

impl TlsTestServer {
    /// A server whose replies are chosen by path prefix.
    pub async fn start_routed(routes: Vec<(&str, Vec<Reply>)>) -> Self {
        let cert = rcgen::generate_simple_self_signed(
            TLS_TEST_HOSTS
                .iter()
                .map(|h| (*h).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let root = reqwest::Certificate::from_der(cert.cert.der()).unwrap();
        let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.cert.der().to_vec())], key)
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = TestServer::serve_on(
            listener,
            format!("https://127.0.0.1:{port}"),
            routes,
            Some(TlsAcceptor::from(Arc::new(config))),
        );
        Self { server, port, root }
    }

    /// The certificate a client must trust to reach this server.
    pub fn root(&self) -> reqwest::Certificate {
        self.root.clone()
    }

    /// `https://<host>:<port><path>`, an endpoint on this server.
    pub fn endpoint(&self, host: &str, path: &str) -> String {
        format!("https://{host}:{}{path}", self.port)
    }

    /// Every request received so far, in arrival order.
    pub async fn requests(&self) -> Vec<CapturedRequest> {
        self.server.requests().await
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
    if reply.hang {
        // `respond` stays alive on this never-finishing task, so the stream
        // stays open until the server's runtime drops it.
        std::future::pending::<()>().await;
    }
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
