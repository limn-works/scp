//! The operating-system shutdown signal a relay or node process stops on.
//!
//! Compiled in every build, unlike [`crate::startup`]: `scp-node`'s library
//! entry point `host_site` installs this signal, so a library consumer that
//! links neither the startup utilities nor the binary still has it. The
//! `scp-node` and `scp-relay` binaries call it too, and
//! `startup::StartupError` wraps its error.
//!
//! See §10.5 of the SCP infrastructure spec.

use std::future::Future;

/// The operating system refused a handler for `signal`, so the process could
/// not learn when to shut down.
#[derive(Debug, thiserror::Error)]
#[error("failed to register a {signal} handler: {error}")]
pub struct ShutdownSignalError {
    /// The signal the handler was for: `SIGINT` or `SIGTERM` on Unix,
    /// `Ctrl-C` on Windows.
    pub signal: &'static str,
    /// The registration failure.
    pub error: std::io::Error,
}

/// Registers SIGINT and SIGTERM handlers and returns a future that resolves
/// when either signal arrives.
///
/// The handlers register when this function runs, so a refused registration
/// fails startup instead of leaving a process that cannot learn when to stop.
/// Call it from inside a Tokio runtime.
///
/// # Errors
///
/// [`ShutdownSignalError`] when the operating system refuses either handler.
#[cfg(unix)]
pub fn shutdown_signal() -> Result<impl Future<Output = ()> + Send + 'static, ShutdownSignalError> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|error| ShutdownSignalError {
        signal: "SIGINT",
        error,
    })?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|error| ShutdownSignalError {
        signal: "SIGTERM",
        error,
    })?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
}

/// Registers a Ctrl-C handler and returns a future that resolves when Ctrl-C
/// arrives.
///
/// The handler registers when this function runs, so a refused registration
/// fails startup instead of leaving a process that cannot learn when to stop.
/// Call it from inside a Tokio runtime.
///
/// # Errors
///
/// [`ShutdownSignalError`] when the operating system refuses the handler.
#[cfg(windows)]
pub fn shutdown_signal() -> Result<impl Future<Output = ()> + Send + 'static, ShutdownSignalError> {
    let mut ctrl_c = tokio::signal::windows::ctrl_c().map_err(|error| ShutdownSignalError {
        signal: "Ctrl-C",
        error,
    })?;
    Ok(async move {
        ctrl_c.recv().await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inside a Tokio runtime the handlers install, so the function returns
    /// `Ok`, and the returned future stays pending while no signal arrives.
    #[tokio::test]
    async fn shutdown_signal_installs_inside_a_runtime() {
        let installed = shutdown_signal();
        assert!(
            installed.is_ok(),
            "handler registration failed: {:?}",
            installed.err()
        );
        let Ok(shutdown) = installed else { return };
        let waited = tokio::time::timeout(std::time::Duration::from_millis(20), shutdown).await;
        assert!(
            waited.is_err(),
            "the shutdown future resolved with no signal sent"
        );
    }
}
