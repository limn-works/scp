//! The Rust-side custody record that fixes a callback key's type and role
//! (SCP-345; spec §17.3 `custody/record/{namespace}/{key_id}`).
//!
//! A host custody provider names its keys by id and reports each key's type
//! when asked. A [`CustodyRecordStore`] keeps the type and role the adapter
//! minted a key with, so a later host answer that disagrees is refused rather
//! than trusted, and a handle with no record is refused before any host call.
//!
//! The store over the instance storage, scoped to one identity's custody
//! namespace, and the table that admits one live store per namespace, live in
//! the bridge crates (`scp_ffi_common::custody_namespace`), where the bridge
//! instance that owns the storage is the only code that can build a table.

use std::future::Future;
use std::pin::Pin;

use crate::error::PlatformError;
use crate::traits::{KeyHandle, KeyRole, KeyType};

/// A boxed `Send` future, so [`CustodyRecordStore`] stays object-safe and an
/// adapter holds it as `Arc<dyn CustodyRecordStore>`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The type and role a custody key was minted with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyRecord {
    /// The key's type, which fixes the operations it permits.
    pub key_type: KeyType,
    /// The key's role, which fixes whether it may derive a pseudonym.
    pub role: KeyRole,
}

/// Durable records of the type and role each custody key was minted with,
/// within one namespace.
///
/// Object-safe, so an adapter holds an `Arc<dyn CustodyRecordStore>`.
pub trait CustodyRecordStore: Send + Sync {
    /// Records that `handle` holds a key of `key_type` in `role`.
    ///
    /// Recording the same record again succeeds and writes nothing.
    ///
    /// # Errors
    ///
    /// - [`PlatformError::CustodyError`] when `handle` already has a different
    ///   record, or its stored record does not decode.
    /// - Any error the storage returns.
    fn put(
        &self,
        handle: KeyHandle,
        key_type: KeyType,
        role: KeyRole,
    ) -> BoxFuture<'_, Result<(), PlatformError>>;

    /// The record for `handle`, or `None` when it has none.
    ///
    /// # Errors
    ///
    /// - [`PlatformError::CustodyError`] when the stored record has an unknown
    ///   version, type code or role byte, or the wrong length.
    /// - Any error the storage returns.
    fn get(&self, handle: KeyHandle)
    -> BoxFuture<'_, Result<Option<CustodyRecord>, PlatformError>>;

    /// Removes the record for `handle`; removing an absent record succeeds.
    ///
    /// # Errors
    ///
    /// Any error the storage returns.
    fn remove(&self, handle: KeyHandle) -> BoxFuture<'_, Result<(), PlatformError>>;
}
