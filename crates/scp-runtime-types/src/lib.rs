//! Types, codecs and stateless services of the SCP runtime (ADR-070 §2).
//!
//! These modules depend on no runtime state: configuration and policy types,
//! access-key, sender-key and UCAN codecs, the MLS backend, discovery,
//! economy, identity and well-known records. `scp-runtime-core` and every
//! domain crate build on them.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Test targets require the `testing` feature: `#[cfg(test)]` modules call
// `#[cfg(feature = "testing")]`-gated helpers of the scp dependencies. This
// tripwire turns a missing `--features` into a clear message instead of a
// cryptic E0599.
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime-types test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-types/testing` in a multi-package command)."
);

/// Whether the runtime's `testing` feature is on.
///
/// The one source of truth for every value-level test/production branch in the
/// runtime crates. Each runtime crate's `testing` feature enables
/// `scp-runtime-types/testing`, directly or through `scp-runtime-core/testing`, so
/// any build that turns on `testing` in one runtime crate reads `true` here in all
/// of them, and a partial feature set cannot mix test and production behaviour.
pub const TESTING: bool = cfg!(feature = "testing");

/// Declares one item `pub` in a build with `testing` (or `cfg(test)`) and
/// `pub(crate)` in every other build.
///
/// ADR-070 §5: a core item that a test outside its crate reaches, and that no
/// production code outside its crate needs, becomes `pub` only under
/// `testing`. A production build, an FFI bridge among them, cannot name it, and
/// `check-shipped-feature-graph.sh` keeps every `testing` feature off the
/// shipped graph. The `cfg` resolves in the crate that invokes the macro, so
/// the item follows that crate's own `testing` feature.
///
/// The item is written with `pub(crate)`, the visibility a production build
/// gets:
///
/// ```
/// scp_runtime_types::pub_under_testing! {
///     /// A limit only this crate and tests read.
///     pub(crate) const LIMIT: u64 = 4;
/// }
/// # fn main() { assert_eq!(LIMIT, 4); }
/// ```
#[macro_export]
macro_rules! pub_under_testing {
    ($(#[$meta:meta])* pub(crate) $($item:tt)*) => {
        $(#[$meta])*
        #[cfg(any(test, feature = "testing"))]
        pub $($item)*

        $(#[$meta])*
        #[cfg(not(any(test, feature = "testing")))]
        pub(crate) $($item)*
    };
}

pub mod context;
pub mod crypto;
pub mod discovery;
pub mod economy;
pub mod envelope;
pub mod identity;
pub mod metrics;
pub mod sync;
pub mod trust;
pub mod well_known;
