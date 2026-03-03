//! Storage conformance test macro.
//!
//! The [`storage_conformance`] macro generates 13 test cases that validate
//! any [`Storage`](scp_platform::Storage) implementation against the protocol
//! specification (sections 17.11, 17.13):
//!
//! 1. Store/retrieve roundtrip
//! 2. Missing key returns None
//! 3. Delete removes value
//! 4. `list_keys` returns sorted results
//! 5. `list_keys` with prefix returns sorted subset
//! 6. `delete_prefix` removes matching keys and returns count
//! 7. `delete_prefix` returns 0 for no match
//! 8. `exists` returns true for stored key
//! 9. `exists` returns false for missing key
//! 10. `exists` returns false after delete
//! 11. Overwrite replaces value
//! 12. Concurrent store + retrieve is safe
//! 13. Store empty value
//!
//! See spec sections 17.11 (Custom Storage Adapters), 17.13 (Storage
//! Conformance Extensions), and ADR-006.

/// Generates 13 conformance tests for a [`Storage`](scp_platform::Storage)
/// implementation.
///
/// # Arguments
///
/// The macro takes a single expression that evaluates to an instance of a type
/// implementing [`Storage`]. This expression is called once per test to create
/// a fresh storage instance with no pre-existing data.
///
/// # Example
///
/// ```ignore
/// use scp_testing::storage_conformance;
///
/// storage_conformance!(InMemoryStorage::new());
/// ```
///
/// See spec section 17.11.
#[macro_export]
macro_rules! storage_conformance {
    ($storage_factory:expr) => {
        mod storage_conformance {
            use super::*;

            use scp_platform::Storage;

            #[tokio::test]
            async fn roundtrip() {
                let storage = $storage_factory;
                storage
                    .store("key1", b"value1")
                    .await
                    .expect("store should succeed");
                let result = storage
                    .retrieve("key1")
                    .await
                    .expect("retrieve should succeed");
                assert_eq!(result, Some(b"value1".to_vec()));
            }

            #[tokio::test]
            async fn missing_returns_none() {
                let storage = $storage_factory;
                let result = storage
                    .retrieve("nonexistent")
                    .await
                    .expect("retrieve should succeed");
                assert_eq!(result, None);
            }

            #[tokio::test]
            async fn delete_removes() {
                let storage = $storage_factory;
                storage
                    .store("key", b"value")
                    .await
                    .expect("store should succeed");
                storage.delete("key").await.expect("delete should succeed");
                let result = storage
                    .retrieve("key")
                    .await
                    .expect("retrieve should succeed");
                assert_eq!(result, None);
            }

            #[tokio::test]
            async fn list_keys_sorted() {
                let storage = $storage_factory;
                storage.store("c", b"").await.expect("store should succeed");
                storage.store("a", b"").await.expect("store should succeed");
                storage.store("b", b"").await.expect("store should succeed");

                let keys = storage
                    .list_keys("")
                    .await
                    .expect("list_keys should succeed");
                assert_eq!(keys, vec!["a", "b", "c"]);
            }

            #[tokio::test]
            async fn list_keys_prefix_sorted() {
                let storage = $storage_factory;
                storage
                    .store("ctx/z", b"")
                    .await
                    .expect("store should succeed");
                storage
                    .store("ctx/a", b"")
                    .await
                    .expect("store should succeed");
                storage
                    .store("ctx/m", b"")
                    .await
                    .expect("store should succeed");
                storage
                    .store("other/x", b"")
                    .await
                    .expect("store should succeed");

                let keys = storage
                    .list_keys("ctx/")
                    .await
                    .expect("list_keys should succeed");
                assert_eq!(keys, vec!["ctx/a", "ctx/m", "ctx/z"]);
            }

            #[tokio::test]
            async fn delete_prefix_removes() {
                let storage = $storage_factory;
                storage
                    .store("ctx/a/1", b"1")
                    .await
                    .expect("store should succeed");
                storage
                    .store("ctx/a/2", b"2")
                    .await
                    .expect("store should succeed");
                storage
                    .store("ctx/b/1", b"3")
                    .await
                    .expect("store should succeed");
                storage
                    .store("other/x", b"4")
                    .await
                    .expect("store should succeed");

                let deleted = storage
                    .delete_prefix("ctx/a/")
                    .await
                    .expect("delete_prefix should succeed");
                assert_eq!(deleted, 2);

                // Verify deleted keys are gone.
                assert_eq!(
                    storage
                        .retrieve("ctx/a/1")
                        .await
                        .expect("retrieve should succeed"),
                    None
                );
                assert_eq!(
                    storage
                        .retrieve("ctx/a/2")
                        .await
                        .expect("retrieve should succeed"),
                    None
                );

                // Verify non-matching keys remain.
                assert_eq!(
                    storage
                        .retrieve("ctx/b/1")
                        .await
                        .expect("retrieve should succeed"),
                    Some(b"3".to_vec())
                );
                assert_eq!(
                    storage
                        .retrieve("other/x")
                        .await
                        .expect("retrieve should succeed"),
                    Some(b"4".to_vec())
                );
            }

            #[tokio::test]
            async fn delete_prefix_zero() {
                let storage = $storage_factory;
                storage
                    .store("foo", b"bar")
                    .await
                    .expect("store should succeed");

                let deleted = storage
                    .delete_prefix("nonexistent/")
                    .await
                    .expect("delete_prefix should succeed");
                assert_eq!(deleted, 0);
            }

            #[tokio::test]
            async fn exists_true() {
                let storage = $storage_factory;
                storage
                    .store("key", b"value")
                    .await
                    .expect("store should succeed");
                assert!(storage.exists("key").await.expect("exists should succeed"));
            }

            #[tokio::test]
            async fn exists_false() {
                let storage = $storage_factory;
                assert!(
                    !storage
                        .exists("missing")
                        .await
                        .expect("exists should succeed")
                );
            }

            #[tokio::test]
            async fn exists_after_delete() {
                let storage = $storage_factory;
                storage
                    .store("key", b"value")
                    .await
                    .expect("store should succeed");
                storage.delete("key").await.expect("delete should succeed");
                assert!(!storage.exists("key").await.expect("exists should succeed"));
            }

            #[tokio::test]
            async fn overwrite() {
                let storage = $storage_factory;
                storage
                    .store("key", b"first")
                    .await
                    .expect("store should succeed");
                storage
                    .store("key", b"second")
                    .await
                    .expect("store should succeed");
                let result = storage
                    .retrieve("key")
                    .await
                    .expect("retrieve should succeed");
                assert_eq!(result, Some(b"second".to_vec()));
            }

            #[tokio::test]
            async fn concurrent_access() {
                let storage = ::std::sync::Arc::new($storage_factory);

                let mut handles = Vec::new();
                for i in 0u32..10 {
                    let s = ::std::sync::Arc::clone(&storage);
                    handles.push(tokio::spawn(async move {
                        let key = format!("concurrent/{i}");
                        let value = i.to_le_bytes();
                        s.store(&key, &value)
                            .await
                            .expect("concurrent store should succeed");
                        let retrieved = s
                            .retrieve(&key)
                            .await
                            .expect("concurrent retrieve should succeed");
                        assert_eq!(retrieved, Some(value.to_vec()));
                    }));
                }

                for handle in handles {
                    handle.await.expect("task should complete");
                }

                // Verify all keys are present after concurrent writes.
                let keys = storage
                    .list_keys("concurrent/")
                    .await
                    .expect("list_keys should succeed");
                assert_eq!(keys.len(), 10);

                // Verify each value matches what was stored.
                for i in 0u32..10 {
                    let key = format!("concurrent/{i}");
                    let expected = i.to_le_bytes().to_vec();
                    let actual = storage
                        .retrieve(&key)
                        .await
                        .expect("retrieve should succeed")
                        .expect("key should exist");
                    assert_eq!(actual, expected, "value mismatch for key {key}");
                }
            }

            #[tokio::test]
            async fn store_empty_value() {
                let storage = $storage_factory;
                storage
                    .store("empty", b"")
                    .await
                    .expect("store should succeed");
                let result = storage
                    .retrieve("empty")
                    .await
                    .expect("retrieve should succeed");
                assert_eq!(result, Some(vec![]));
            }
        }
    };
}
