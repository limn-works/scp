//! Force-link marker for the C stubs emitted by `build.rs`.
//!
//! Callers (scp-ffi-napi's `#[cfg(test)]` module) must reference
//! [`FORCE_LINK`] so that cargo includes this crate's rlib — and the
//! `cargo:rustc-link-lib=static=napi_test_stubs` directive from its
//! `build.rs` — in the lib-test binary's link graph. Without a
//! reference, cargo would skip the rlib (it's otherwise empty) and the
//! stubs would never appear in the link args.
//!
//! This crate MUST remain a `[dev-dependencies]` entry on scp-ffi-napi
//! — never a regular `[dependencies]` entry — so the cdylib build never
//! compiles or links against the stubs. At runtime Node provides the
//! real napi_* symbols via dynamic linking.
#[doc(hidden)]
pub static FORCE_LINK: u8 = 0;
