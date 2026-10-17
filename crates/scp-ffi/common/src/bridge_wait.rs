//! The one way an FFI bridge blocks a thread on async work.
//!
//! This module is the only code in any bridge allowed to block a thread.
//! Its private `drive` is the only `block_on` or
//! `block_in_place` caller under `crates/scp-ffi/`, reached through
//! [`bridge_block_on`] and [`bridge_block_on_off_thread`];
//! `scripts/check-bridge-block-on.py` fails any other production site in the
//! `PyO3`, napi and `UniFFI` bridges and in this crate, and every other
//! thread-blocking call (`std::thread::sleep`, a sync channel's `recv`,
//! `recv_timeout` or `recv_deadline`, a `Condvar` wait, tokio's `blocking_*`)
//! outside this file (ADR-049 Decision 7a, "Host threads"). A bridge that must release a
//! host lock around the wait does so around its call to this helper: `PyO3`
//! calls [`bridge_block_on_off_thread`] inside `Python::allow_threads`
//! (`actor_wait::block_on_released`).
//!
//! The helper reads the ambient tokio state once per wait (`regime`) and
//! picks the regime it permits, so no call site chooses one and none can
//! choose one that panics:
//!
//! 1. no ambient runtime (a host thread, a napi-rs or libuv worker, a
//!    scoped resolution thread): the caller's shared runtime's
//!    `Runtime::block_on`, which drives that runtime's IO and timer drivers
//!    even when it is a current-thread runtime;
//! 2. a multi-thread ambient runtime, where `Runtime::block_on` panics:
//!    `block_in_place` around the ambient handle, under the bridge exemption
//!    that ADR-049 Decision 7a restates;
//! 3. a current-thread ambient runtime, where `Runtime::block_on` and
//!    `block_in_place` both panic: [`bridge_block_on`] returns
//!    [`BridgeBlockOnError::CurrentThreadRuntime`], for a caller whose awaited
//!    work may need the thread the wait would block.
//!    [`bridge_block_on_off_thread`] instead drives a `Send` future on a
//!    private current-thread runtime on a scoped thread (the scope lets the
//!    future borrow the caller's locals) by calling [`bridge_block_on`] there
//!    in regime 1; it suits a future whose work runs on some other runtime.
//!
//! [`bridge_block_on`] puts no `Send` bound on the future, so a bridge can
//! wait on a `!Send` future (the custody-migration orchestrator borrows a
//! `?Sync` backend) in regimes 1 and 2.

use std::future::Future;

/// Why [`bridge_block_on`] or [`bridge_block_on_off_thread`] could not drive
/// a future to completion.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BridgeBlockOnError {
    /// Regime 1 needed the bridge's shared runtime and the bridge could not
    /// supply it; the payload is the bridge's reason.
    #[error("the bridge runtime is unavailable: {0}")]
    SharedRuntimeUnavailable(String),
    /// Regime 3 in [`bridge_block_on`]: the ambient runtime is
    /// current-thread, and the awaited work may need the thread the wait
    /// would block.
    #[error("a current-thread runtime cannot drive the wait")]
    CurrentThreadRuntime,
    /// Regime 3 in [`bridge_block_on_off_thread`] could not build its private
    /// current-thread runtime.
    #[error("a bridge wait could not build a private runtime: {0}")]
    PrivateRuntimeBuild(String),
    /// Regime 3 in [`bridge_block_on_off_thread`]: the scoped thread panicked
    /// before it returned the output.
    #[error("a bridge wait's private runtime thread panicked")]
    WaitThreadPanicked,
}

/// The ambient tokio state, read once per wait; the module documentation
/// numbers the regimes.
enum Regime {
    /// Regime 1: no ambient runtime.
    NoRuntime,
    /// Regime 2: a multi-thread ambient runtime, whose handle drives the
    /// wait under `block_in_place`.
    MultiThread(tokio::runtime::Handle),
    /// Regime 3: a current-thread ambient runtime, or a flavor neither
    /// `Runtime::block_on` nor `block_in_place` is known to accept there.
    CurrentThread,
}

fn regime() -> Regime {
    match tokio::runtime::Handle::try_current() {
        Err(_) => Regime::NoRuntime,
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            Regime::MultiThread(handle)
        }
        Ok(_) => Regime::CurrentThread,
    }
}

/// Drives `fut` in regime 1 or 2, and gives it back unpolled in regime 3.
/// The only code under `crates/scp-ffi/` that names `block_on` or
/// `block_in_place` (`scripts/check-bridge-block-on.py`).
fn drive<'r, F, S>(
    regime: Regime,
    shared: S,
    fut: F,
) -> Result<Result<F::Output, F>, BridgeBlockOnError>
where
    F: Future,
    S: FnOnce() -> Result<&'r tokio::runtime::Runtime, String>,
{
    match regime {
        Regime::NoRuntime => {
            let rt = shared().map_err(BridgeBlockOnError::SharedRuntimeUnavailable)?;
            Ok(Ok(rt.block_on(fut)))
        }
        Regime::MultiThread(handle) => Ok(Ok(tokio::task::block_in_place(|| handle.block_on(fut)))),
        Regime::CurrentThread => Ok(Err(fut)),
    }
}

/// Drives `fut` to completion on the calling thread, in the regime the
/// ambient tokio state permits (see the module documentation).
///
/// `shared` supplies the bridge's shared runtime; it is called only in
/// regime 1, so a caller inside a runtime never needs one.
///
/// # Errors
///
/// [`BridgeBlockOnError::SharedRuntimeUnavailable`] when regime 1 applies and
/// `shared` fails; [`BridgeBlockOnError::CurrentThreadRuntime`] in regime 3.
pub fn bridge_block_on<'r, F, S>(shared: S, fut: F) -> Result<F::Output, BridgeBlockOnError>
where
    F: Future,
    S: FnOnce() -> Result<&'r tokio::runtime::Runtime, String>,
{
    drive(regime(), shared, fut)?.map_err(|_| BridgeBlockOnError::CurrentThreadRuntime)
}

/// [`bridge_block_on`], except that in regime 3 it drives `fut` on a private
/// current-thread runtime on a scoped thread instead of refusing.
///
/// # Errors
///
/// [`BridgeBlockOnError::SharedRuntimeUnavailable`] when regime 1 applies and
/// `shared` fails; [`BridgeBlockOnError::PrivateRuntimeBuild`] and
/// [`BridgeBlockOnError::WaitThreadPanicked`] from regime 3.
pub fn bridge_block_on_off_thread<'r, F, S>(
    shared: S,
    fut: F,
) -> Result<F::Output, BridgeBlockOnError>
where
    F: Future + Send,
    F::Output: Send,
    S: FnOnce() -> Result<&'r tokio::runtime::Runtime, String>,
{
    let fut = match drive(regime(), shared, fut)? {
        Ok(output) => return Ok(output),
        Err(fut) => fut,
    };
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| BridgeBlockOnError::PrivateRuntimeBuild(e.to_string()))?;
                // A scoped thread has no ambient runtime: regime 1 on `rt`.
                drive(Regime::NoRuntime, || Ok(&rt), fut)?
                    .map_err(|_| BridgeBlockOnError::CurrentThreadRuntime)
            })
            .join()
            .map_err(|_| BridgeBlockOnError::WaitThreadPanicked)?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_rt() -> Result<tokio::runtime::Runtime, BridgeBlockOnError> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| BridgeBlockOnError::PrivateRuntimeBuild(e.to_string()))
    }

    #[test]
    fn regime_1_uses_the_shared_runtime() -> Result<(), BridgeBlockOnError> {
        let rt = shared_rt()?;
        let out = bridge_block_on(|| Ok(&rt), async {
            tokio::runtime::Handle::current().runtime_flavor()
        })?;
        assert_eq!(out, tokio::runtime::RuntimeFlavor::MultiThread);
        Ok(())
    }

    /// A current-thread shared runtime still drives its timer: regime 1 uses
    /// `Runtime::block_on`, not `Handle::block_on`, which would hang here.
    #[test]
    fn regime_1_drives_a_current_thread_shared_runtimes_timer() -> Result<(), BridgeBlockOnError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| BridgeBlockOnError::PrivateRuntimeBuild(e.to_string()))?;
        let out = bridge_block_on(|| Ok(&rt), async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            3_u8
        })?;
        assert_eq!(out, 3);
        Ok(())
    }

    /// A `!Send` future (one holding an `Rc` across an await) is accepted.
    #[test]
    fn regime_1_drives_a_non_send_future() -> Result<(), BridgeBlockOnError> {
        let rt = shared_rt()?;
        let out = bridge_block_on(|| Ok(&rt), async {
            let held = std::rc::Rc::new(5_u8);
            tokio::task::yield_now().await;
            *held
        })?;
        assert_eq!(out, 5);
        Ok(())
    }

    #[test]
    fn regime_1_reports_an_absent_shared_runtime() {
        let err = bridge_block_on(|| Err("absent".to_owned()), async { 1_u8 });
        assert_eq!(
            err,
            Err(BridgeBlockOnError::SharedRuntimeUnavailable(
                "absent".to_owned()
            ))
        );
    }

    /// Inside a runtime the shared runtime is never asked for.
    #[test]
    fn regime_2_inside_a_multi_thread_runtime() -> Result<(), BridgeBlockOnError> {
        let ambient = shared_rt()?;
        let out = ambient
            .block_on(async {
                tokio::spawn(async {
                    bridge_block_on(|| Err("must not be called".to_owned()), async { 8_u8 })
                })
                .await
            })
            .map_err(|_| BridgeBlockOnError::WaitThreadPanicked)??;
        assert_eq!(out, 8);
        Ok(())
    }

    #[test]
    fn regime_3_inside_a_current_thread_runtime_borrows_locals() -> Result<(), BridgeBlockOnError> {
        let ambient = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| BridgeBlockOnError::PrivateRuntimeBuild(e.to_string()))?;
        let local = String::from("borrowed");
        let out = ambient.block_on(async {
            bridge_block_on_off_thread(|| Err("must not be called".to_owned()), async {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                local.len()
            })
        })?;
        assert_eq!(out, 8);
        Ok(())
    }

    #[test]
    fn regime_reads_no_runtime_outside_every_runtime() {
        assert!(matches!(regime(), Regime::NoRuntime));
    }

    #[test]
    fn regime_reads_a_multi_thread_ambient_runtime() -> Result<(), BridgeBlockOnError> {
        let ambient = shared_rt()?;
        let read = ambient.block_on(async { regime() });
        assert!(matches!(read, Regime::MultiThread(_)));
        Ok(())
    }

    #[test]
    fn regime_reads_a_current_thread_ambient_runtime() -> Result<(), BridgeBlockOnError> {
        let ambient = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| BridgeBlockOnError::PrivateRuntimeBuild(e.to_string()))?;
        let read = ambient.block_on(async { regime() });
        assert!(matches!(read, Regime::CurrentThread));
        Ok(())
    }

    /// Regime 3 gives the future back unpolled, so the caller still owns it.
    #[test]
    fn drive_gives_the_future_back_in_regime_3() -> Result<(), BridgeBlockOnError> {
        let polled = std::sync::atomic::AtomicBool::new(false);
        let fut = async {
            polled.store(true, std::sync::atomic::Ordering::SeqCst);
            4_u8
        };
        let back = drive(
            Regime::CurrentThread,
            || Err("must not be called".to_owned()),
            fut,
        )?;
        assert!(back.is_err());
        assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn regime_3_refuses_when_the_caller_says_so() -> Result<(), BridgeBlockOnError> {
        let ambient = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| BridgeBlockOnError::PrivateRuntimeBuild(e.to_string()))?;
        let out = ambient.block_on(async {
            bridge_block_on(|| Err("must not be called".to_owned()), async { 1_u8 })
        });
        assert_eq!(out, Err(BridgeBlockOnError::CurrentThreadRuntime));
        Ok(())
    }
}
