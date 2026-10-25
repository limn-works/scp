//! One namespace has at most one live custody record store per storage
//! (spec §17.3; SCP-345).
//!
//! `CustodyNamespaces::open` is the only public way to build a store. Two
//! namespaces open side by side and keep apart the records they put
//! concurrently under one key id; a second open of a live namespace is
//! refused until the first store drops.
#![cfg(feature = "in-memory-storage")]

use std::sync::Arc;

use scp_platform::in_memory::InMemoryStorage;
use scp_platform::{
    CustodyNamespace, CustodyNamespaces, CustodyRecord, CustodyRecordStore, KeyHandle, KeyRole,
    KeyType, NamespaceLive, Storage,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn two_stores_over_one_storage_keep_their_records_apart() -> TestResult {
    let storage = Arc::new(InMemoryStorage::new());
    let table = CustodyNamespaces::new();
    let a = table.open(
        Arc::clone(&storage),
        CustodyNamespace::from_bytes([0x11; 16]),
    )?;
    let b = table.open(
        Arc::clone(&storage),
        CustodyNamespace::from_bytes([0x22; 16]),
    )?;
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

#[tokio::test]
async fn a_live_namespace_opens_once_until_its_store_drops() -> TestResult {
    let storage = Arc::new(InMemoryStorage::new());
    let table = CustodyNamespaces::new();
    let first = table.open(
        Arc::clone(&storage),
        CustodyNamespace::from_bytes([0x33; 16]),
    )?;
    first
        .put(
            KeyHandle::new(1),
            KeyType::P256KeyEvent,
            KeyRole::Operational,
        )
        .await?;
    // Equal bytes in a new value are the same namespace.
    let second = table.open(
        Arc::clone(&storage),
        CustodyNamespace::from_bytes([0x33; 16]),
    );
    assert_eq!(second.err(), Some(NamespaceLive));
    // A clone of the table is the same table.
    let again = table.clone().open(
        Arc::clone(&storage),
        CustodyNamespace::from_bytes([0x33; 16]),
    );
    assert_eq!(again.err(), Some(NamespaceLive));
    drop(first);
    let reopened = table.open(
        Arc::clone(&storage),
        CustodyNamespace::from_bytes([0x33; 16]),
    )?;
    assert_eq!(
        reopened.namespace(),
        &CustodyNamespace::from_bytes([0x33; 16])
    );
    assert_eq!(
        reopened.get(KeyHandle::new(1)).await?,
        Some(CustodyRecord {
            key_type: KeyType::P256KeyEvent,
            role: KeyRole::Operational,
        }),
        "a reopened namespace reads the records its earlier store wrote"
    );
    Ok(())
}
