//! Apple platform storage adapter for SCP.
//!
//! Provides [`AppleStorage`], a [`Storage`] implementation backed by `SQLCipher`-
//! encrypted `SQLite`. Unlike the generic `SqliteStorage` (which manages its own
//! encryption key), `AppleStorage` receives the encryption key from the caller
//! -- on Apple platforms this key is generated and managed by the Keychain in
//! the Swift `AppleStorage` actor (see `bindings/swift/.../AppleStorage.swift`).
//!
//! # Architecture
//!
//! The Swift side handles Keychain operations (generate / retrieve the 32-byte
//! AES-256 key, set iOS file protection). It then passes the key and database
//! directory path to this Rust adapter via `UniFFI`. The Rust adapter opens the
//! `SQLCipher` database, applies the encryption pragmas (spec section 17.5), and
//! implements the 6-method [`Storage`] trait.
//!
//! # Feature Flag
//!
//! This module is gated behind the `apple` feature in `scp-platform`:
//!
//! ```toml
//! [features]
//! apple = ["dep:rusqlite", "dep:hex"]
//! ```
//!
//! # References
//!
//! - Spec section 17.5 (`SQLCipher` configuration)
//! - Spec section 17.6 (`SQLite` as universal default)
//! - ADR-025 (Apple Platform Adapter)
//! - ADR-027 (Platform Storage Architecture)

pub mod storage;

pub use storage::AppleStorage;
