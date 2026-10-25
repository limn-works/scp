//! One namespace value builds one custody record store (spec §17.3; SCP-345).
//!
//! `StorageCustodyRecordStore::new` carries a `compile_fail,E0382` doctest
//! that builds two stores from one namespace. This file is its positive
//! control, which `cargo nextest` runs where it skips doctests: the same
//! function with two namespaces compiles, and its two stores over one storage
//! keep apart the records they put concurrently under one key id.
#![cfg(feature = "in-memory-storage")]

use std::sync::Arc;

use scp_platform::in_memory::InMemoryStorage;
use scp_platform::{
    CustodyNamespace, CustodyRecord, CustodyRecordStore, KeyHandle, KeyRole, KeyType, Storage,
    StorageCustodyRecordStore,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The doctest's function, given a namespace per store.
fn two_stores<S: Storage + Clone>(
    storage: S,
    first: CustodyNamespace,
    second: CustodyNamespace,
) -> (StorageCustodyRecordStore<S>, StorageCustodyRecordStore<S>) {
    (
        StorageCustodyRecordStore::new(storage.clone(), first),
        StorageCustodyRecordStore::new(storage, second),
    )
}

#[tokio::test]
async fn two_stores_over_one_storage_keep_their_records_apart() -> TestResult {
    let storage = Arc::new(InMemoryStorage::new());
    let (a, b) = two_stores(
        Arc::clone(&storage),
        CustodyNamespace::from_bytes([0x11; 16]),
        CustodyNamespace::from_bytes([0x22; 16]),
    );
    let handle = KeyHandle::new(9);
    let (put_a, put_b) = tokio::join!(
        a.put(handle, KeyType::P256Signing, KeyRole::Operational),
        b.put(handle, KeyType::HpkeP256, KeyRole::Identity),
    );
    put_a?;
    put_b?;
    assert_eq!(
        a.get(handle).await?,
        Some(CustodyRecord {
            key_type: KeyType::P256Signing,
            role: KeyRole::Operational,
        })
    );
    assert_eq!(
        b.get(handle).await?,
        Some(CustodyRecord {
            key_type: KeyType::HpkeP256,
            role: KeyRole::Identity,
        })
    );
    assert_eq!(storage.list_keys("custody/record/").await?.len(), 2);
    Ok(())
}
