//! A probe that tells whether an async call runs its blocking work on tokio's
//! blocking pool or inline on the thread that polls it.
//!
//! The probe runs on a `current_thread` runtime whose blocking pool has one
//! thread, and a parked task holds that thread. A call that hands its work to
//! the pool queues behind the parked task and cannot finish; a call that runs
//! the work inline finishes on its first poll. Neither outcome depends on how
//! long the work takes or how loaded the machine is, so a test built on this
//! probe needs no wall-clock threshold.
//!
//! [`blocking_pool_of_one`] builds the runtime, and
//! [`drive_while_the_blocking_pool_is_held`] runs one call on it. Every crate
//! whose async functions move file work onto the blocking pool tests them
//! through this one probe.

use std::future::Future;
use std::time::Duration;

/// How long the probe polls a call while the pool's thread is held. A call
/// that ran its work inline has already finished by its first poll, so this
/// bounds only how long a correct call is left pending.
const POLL_WINDOW: Duration = Duration::from_millis(300);

/// What [`drive_while_the_blocking_pool_is_held`] saw.
#[derive(Debug)]
pub struct HeldPoolOutcome<T, R> {
    /// Whether the call finished while the pool's only thread was held. A
    /// call that runs its blocking work on the pool reports `false`.
    pub finished_while_held: bool,
    /// What the caller's `observe` closure returned. It ran after the poll
    /// window and before the pool's thread was released, so it sees the file
    /// system as the call left it without any of its pool work.
    pub observed: R,
    /// The call's own result, after the pool's thread was released and the
    /// call ran to completion.
    pub output: T,
}

/// Why the probe could not run: the runtime would not build, or the task
/// holding the pool's thread did not finish.
#[derive(Debug)]
pub struct HeldPoolError(String);

impl std::fmt::Display for HeldPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blocking-pool probe failed: {}", self.0)
    }
}

impl std::error::Error for HeldPoolError {}

/// Builds a `current_thread` runtime with timers and I/O enabled and one
/// blocking-pool thread, the runtime [`drive_while_the_blocking_pool_is_held`]
/// needs.
///
/// # Errors
///
/// Returns [`HeldPoolError`] when tokio cannot build the runtime.
pub fn blocking_pool_of_one() -> Result<tokio::runtime::Runtime, HeldPoolError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .map_err(|e| HeldPoolError(format!("cannot build the runtime: {e}")))
}

/// Holds the only blocking thread of the runtime this future runs on, polls
/// `call` for [`POLL_WINDOW`], runs `observe`, releases the thread, and drives
/// `call` to completion.
///
/// Must run on a runtime from [`blocking_pool_of_one`]. On a runtime with more
/// blocking threads, `call` takes a free one and the probe proves nothing.
///
/// # Errors
///
/// Returns [`HeldPoolError`] when the task holding the pool's thread exited
/// before its release or did not finish.
pub async fn drive_while_the_blocking_pool_is_held<F, R>(
    call: F,
    observe: impl FnOnce() -> R,
) -> Result<HeldPoolOutcome<F::Output, R>, HeldPoolError>
where
    F: Future,
{
    let (release, held) = std::sync::mpsc::channel::<()>();
    // Queued first, so it takes the pool's one thread before anything `call`
    // spawns, and keeps it until `release` sends.
    let holder = tokio::task::spawn_blocking(move || held.recv());
    let mut call = std::pin::pin!(call);
    let early = tokio::time::timeout(POLL_WINDOW, &mut call).await;
    let observed = observe();
    release
        .send(())
        .map_err(|_| HeldPoolError("the holder exited before its release".to_owned()))?;
    holder
        .await
        .map_err(|e| HeldPoolError(format!("the holder task failed: {e}")))?
        .map_err(|e| HeldPoolError(format!("the holder lost its release channel: {e}")))?;
    Ok(match early {
        Ok(output) => HeldPoolOutcome {
            finished_while_held: true,
            observed,
            output,
        },
        Err(_) => HeldPoolOutcome {
            finished_while_held: false,
            observed,
            output: call.await,
        },
    })
}

/// [`drive_while_the_blocking_pool_is_held`] with nothing to observe, on a
/// fresh runtime from [`blocking_pool_of_one`]. Returns whether `call`
/// finished while the pool was held, and its result.
///
/// # Errors
///
/// Returns [`HeldPoolError`] when the runtime cannot be built or the probe
/// fails.
pub fn finishes_while_the_blocking_pool_is_held<F>(
    call: F,
) -> Result<(bool, F::Output), HeldPoolError>
where
    F: Future,
{
    let runtime = blocking_pool_of_one()?;
    let probe = drive_while_the_blocking_pool_is_held(call, || ());
    let outcome = runtime.block_on(probe)?; // ci-allow: block-on: a test probe drives the runtime it built from a synchronous test
    Ok((outcome.finished_while_held, outcome.output))
}
