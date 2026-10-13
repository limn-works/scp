//! The one way a `PyO3` bridge function waits on async work.
//!
//! A `PyO3` method runs on a Python thread that holds the GIL. When it waits
//! on a context actor while still holding the GIL, and the actor's turn calls
//! back into Python (a host custody provider's `sign`, ADR-049 Decision 7a),
//! the callback cannot take the GIL back, and both sides stall until the
//! signing budget expires. A second Python thread that waits on any actor
//! while holding the GIL stalls a signing turn the same way.
//!
//! [`block_on_released`] releases the GIL for the whole wait, so a host
//! callback, or another Python thread, can always run.
//! `scripts/check-bridge-block-on.py` fails every `block_on` and
//! `block_in_place` under `crates/scp-ffi/` outside
//! `scp_ffi_common::bridge_wait::bridge_block_on`, which this wait reaches
//! through `bridge_block_on_off_thread`.
//!
//! The future must not touch Python objects: `Python<'_>` and `Bound<'_, _>`
//! are `!Send`, so the compiler rejects them, but `Py<T>` is `Send` and is not
//! rejected. Extract Python arguments before the call and convert results
//! after it.

use std::future::Future;

use pyo3::Python;
use scp_ffi_common::bridge_wait::bridge_block_on_off_thread;

use crate::error::ScpPyError;

/// Drives `fut` to completion with the GIL released.
///
/// The wait runs through
/// [`scp_ffi_common::bridge_wait::bridge_block_on_off_thread`], which picks
/// the regime the ambient tokio state permits; inside a current-thread
/// ambient runtime it drives `fut` on a private runtime on a scoped thread, so
/// `fut` may borrow the caller's locals.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` when the shared runtime is absent, when
/// the private runtime fails to build, or when the scoped thread panics.
pub fn block_on_released<F>(py: Python<'_>, fut: F) -> Result<F::Output, ScpPyError>
where
    F: Future + Send,
    F::Output: Send,
{
    py.allow_threads(|| {
        bridge_block_on_off_thread(|| crate::runtime().map_err(|e| e.to_string()), fut)
            .map_err(|e| ScpPyError::context(e.to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() -> Result<(), ScpPyError> {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().map_err(|e| ScpPyError::context(e.to_string()))
    }

    #[test]
    fn block_on_released_without_ambient_runtime_uses_shared_runtime() -> Result<(), ScpPyError> {
        init()?;
        let out = Python::with_gil(|py| block_on_released(py, async { 7_u8 }))?;
        assert_eq!(out, 7);
        Ok(())
    }

    #[test]
    fn block_on_released_inside_multi_thread_runtime() -> Result<(), ScpPyError> {
        init()?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| ScpPyError::context(e.to_string()))?;
        let out = rt.block_on(async {
            tokio::spawn(async { Python::with_gil(|py| block_on_released(py, async { 8_u8 })) })
                .await
                .map_err(|e| ScpPyError::context(e.to_string()))?
        })?;
        assert_eq!(out, 8);
        Ok(())
    }

    #[test]
    fn block_on_released_inside_current_thread_runtime_borrows_locals() -> Result<(), ScpPyError> {
        init()?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ScpPyError::context(e.to_string()))?;
        let local = String::from("borrowed");
        let out = rt.block_on(async {
            Python::with_gil(|py| block_on_released(py, async { local.len() }))
        })?;
        assert_eq!(out, 8);
        Ok(())
    }

    /// A3: while one thread waits through the helper, another Python thread
    /// can take the GIL. Holding the GIL across the wait would stall the
    /// waiter's `with_gil` below until the wait gave up.
    #[test]
    fn block_on_released_lets_another_thread_take_the_gil() -> Result<(), ScpPyError> {
        init()?;
        let (tx, rx) = tokio::sync::oneshot::channel::<u8>();
        let helper = std::thread::spawn(move || {
            // Runs only once the waiter released the GIL.
            Python::with_gil(|_py| tx.send(9).ok());
        });
        let out = Python::with_gil(|py| {
            block_on_released(py, async {
                tokio::time::timeout(std::time::Duration::from_secs(10), rx).await
            })
        })?;
        helper
            .join()
            .map_err(|_| ScpPyError::context("helper thread panicked"))?;
        assert!(matches!(out, Ok(Ok(9))));
        Ok(())
    }
}
