//! A local HTTP/2 (h2c) server and a tracing capture for the push sender tests
//! (PUSH-010, PUSH-011). Compiled only under `cfg(test)`; the tests never reach
//! Apple or Google.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Once};

use bytes::Bytes;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::{Layer as _, filter};

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

/// A shared buffer the capture subscriber writes formatted events into.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `f` on this thread's active capture buffer slot.
fn with_active<R>(f: impl FnOnce(&RefCell<Option<SharedBuffer>>) -> R) -> R {
    thread_local! {
        static ACTIVE: RefCell<Option<SharedBuffer>> = const { RefCell::new(None) };
    }
    ACTIVE.with(f)
}

/// Writes to the calling thread's active capture buffer, or discards.
struct ThreadRouted;

impl<'a> MakeWriter<'a> for ThreadRouted {
    type Writer = Box<dyn Write>;

    fn make_writer(&'a self) -> Self::Writer {
        with_active(|active| match active.borrow().clone() {
            Some(buffer) => Box::new(buffer) as Box<dyn Write>,
            None => Box::new(std::io::sink()),
        })
    }
}

/// Installs, once per test process, a global subscriber that formats every
/// event of every level and target, enabled only on a thread with an active
/// capture.
///
/// The global subscriber is the fix for a lost-event race: with a
/// thread-scoped `set_default` subscriber, a callsite another test thread
/// registers concurrently can cache `Interest::never` and drop the capturing
/// test's events. The per-event filter here makes every callsite's interest
/// `sometimes`, so each event is checked against the current thread.
fn install_global() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(ThreadRouted)
            .with_filter(filter::filter_fn(|_| {
                with_active(|active| active.borrow().is_some())
            }));
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
            .expect("no other global subscriber in the scp-transport lib tests");
    });
}

/// Captures every tracing event, at every level and from every target, on the
/// current thread while it lives. The tests run on tokio's current-thread
/// runtime, so the senders' events, and hyper's and h2's, land here.
pub(super) struct LogCapture {
    buffer: SharedBuffer,
}

impl LogCapture {
    pub(super) fn install() -> Self {
        install_global();
        let buffer = SharedBuffer::default();
        with_active(|active| *active.borrow_mut() = Some(buffer.clone()));
        Self { buffer }
    }

    /// Everything captured so far.
    pub(super) fn contents(&self) -> String {
        String::from_utf8_lossy(&self.buffer.0.lock().unwrap()).into_owned()
    }
}

impl Drop for LogCapture {
    fn drop(&mut self) {
        with_active(|active| *active.borrow_mut() = None);
    }
}
