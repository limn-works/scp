//! A tracing capture for the push sender tests (PUSH-010, PUSH-011).
//! Compiled only under `cfg(test)`, in the lib tests and in the
//! `log_capture_install_race` integration test, which includes this file by
//! path; it depends on nothing in this crate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};

use tracing::Metadata;
use tracing::level_filters::LevelFilter;
use tracing::subscriber::Interest;
use tracing_subscriber::Layer as _;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, Filter, SubscriberExt as _};

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

/// Enables an event only on a thread with an active capture, and holds the
/// global level filter at `OFF` until the global dispatcher is readable.
struct CaptureFilter {
    /// Set once `set_global_default` has returned.
    armed: Arc<AtomicBool>,
}

impl<S> Filter<S> for CaptureFilter {
    fn enabled(&self, _: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        with_active(|active| active.borrow().is_some())
    }

    /// `sometimes`, so each event is checked against the current thread.
    fn callsite_enabled(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(if self.armed.load(Ordering::SeqCst) {
            LevelFilter::TRACE
        } else {
            LevelFilter::OFF
        })
    }
}

/// Installs, once per test process, a global subscriber that formats every
/// event of every level and target, enabled only on a thread with an active
/// capture.
///
/// A thread-scoped `set_default` subscriber loses events: a callsite another
/// test thread registers concurrently can cache `Interest::never`. A global
/// subscriber alone still loses them. tracing-core 0.1.36 caches a callsite's
/// interest the first time an enabled-level event reaches it
/// (`DefaultCallsite::register`, callsite.rs:308), asking the dispatcher that
/// `dispatcher::get_default` returns. `Dispatch::new` raises the global level
/// filter to the subscriber's hint at the end of `register_dispatch`
/// (callsite.rs:484, `LevelFilter::set_max` at :421), but
/// `set_global_default` makes the dispatcher readable only afterwards
/// (dispatcher.rs:326). A callsite first reached between the two asks the
/// no-op dispatcher `get_global` returns before then (dispatcher.rs:448) and
/// caches `never`, and nothing rebuilds it.
///
/// [`CaptureFilter`] closes that window: its hint is `OFF` until
/// `set_global_default` returns, so no event passes the level check and no
/// callsite registers while the dispatcher is unreadable. Arming it and
/// rebuilding the interest cache then raises the level filter with the global
/// dispatcher already readable, so every callsite registers against it.
fn install_global() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let armed = Arc::new(AtomicBool::new(false));
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(ThreadRouted)
            .with_filter(CaptureFilter {
                armed: armed.clone(),
            });
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
            .expect("no other global subscriber in this test process");
        armed.store(true, Ordering::SeqCst);
        tracing::callsite::rebuild_interest_cache();
    });
}

/// Captures every tracing event, at every level and from every target, on the
/// current thread while it lives. The tests run on tokio's current-thread
/// runtime, so the senders' events, and hyper's and h2's, land here.
pub struct LogCapture {
    buffer: SharedBuffer,
}

impl LogCapture {
    pub fn install() -> Self {
        install_global();
        let buffer = SharedBuffer::default();
        with_active(|active| *active.borrow_mut() = Some(buffer.clone()));
        Self { buffer }
    }

    /// Everything captured so far.
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.buffer.0.lock().unwrap()).into_owned()
    }
}

impl Drop for LogCapture {
    fn drop(&mut self) {
        with_active(|active| *active.borrow_mut() = None);
    }
}
