//! A local HTTP/2 (h2c) server for the push sender tests (PUSH-010,
//! PUSH-011). Compiled only under `cfg(test)`; the tests never reach
//! Apple or Google.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// One request the server received.
#[derive(Debug, Clone)]
pub(super) struct CapturedRequest {
    pub(super) method: String,
    pub(super) path: String,
    /// Every regular header, lowercase name first, in arrival order.
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl CapturedRequest {
    /// The first value of header `name` (lowercase).
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A canned response.
#[derive(Debug, Clone)]
pub(super) struct Reply {
    status: u16,
    body: Vec<u8>,
    content_type: Option<&'static str>,
}

impl Reply {
    /// A response with `status` and no body.
    pub(super) fn empty(status: u16) -> Self {
        Self {
            status,
            body: Vec::new(),
            content_type: None,
        }
    }
}

/// A JSON response with `status` and `body`.
pub(super) fn json_reply(status: u16, body: &serde_json::Value) -> Reply {
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
pub(super) struct TestServer {
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
    pub(super) async fn start(replies: Vec<Reply>) -> Self {
        Self::start_routed(vec![("/", replies)]).await
    }

    /// A server whose replies are chosen by path prefix.
    pub(super) async fn start_routed(routes: Vec<(&str, Vec<Reply>)>) -> Self {
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
    pub(super) fn origin(&self) -> String {
        self.origin.clone()
    }

    /// Every request received so far, in arrival order.
    pub(super) async fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().await.clone()
    }

    /// An origin nothing listens on: a send to it fails to connect.
    pub(super) async fn closed_origin() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        origin
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
