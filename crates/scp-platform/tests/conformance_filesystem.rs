//! Filesystem storage conformance tests.
//!
//! Validates that `FilesystemStorage` passes all 13 conformance tests
//! defined in `storage_conformance!()` (spec sections 17.6, 17.11, 17.13).

#![cfg(feature = "filesystem")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::filesystem::FilesystemStorage;

fn make_filesystem_storage() -> FilesystemStorage {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let dir_path = dir.path().to_path_buf();
    // Leak the TempDir so it outlives the test — the directory must remain
    // on disk while storage operations run. Cleanup is not critical for test
    // directories; the OS reclaims on process exit.
    let _ = Box::leak(Box::new(dir));
    FilesystemStorage::new(&dir_path).expect("FilesystemStorage::new should succeed")
}

scp_testing::storage_conformance!(make_filesystem_storage());

/// A storage rooted at a fresh directory, with that directory's path.
fn filesystem_storage_with_dir() -> (FilesystemStorage, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let storage =
        FilesystemStorage::new(dir.path()).expect("FilesystemStorage::new should succeed");
    (storage, dir)
}

/// Spec section 17.6, "FilesystemStorage": a temp file that a crash left
/// behind is never a key. `list_keys` does not return it and
/// `delete_prefix` neither counts nor fails on it.
#[tokio::test]
async fn leftover_temp_file_is_not_a_key() {
    use scp_platform::traits::Storage;

    let (storage, dir) = filesystem_storage_with_dir();
    storage.store("ctx/a/unit", b"value").await.unwrap();
    let leftover = dir.path().join("ctx").join("a").join(".tmp.1.2.3");
    std::fs::write(&leftover, b"half-written").unwrap();

    assert_eq!(
        storage.list_keys("ctx/").await.unwrap(),
        vec!["ctx/a/unit".to_owned()]
    );
    assert_eq!(
        storage.list_keys("").await.unwrap(),
        vec!["ctx/a/unit".to_owned()]
    );
    assert_eq!(storage.delete_prefix("ctx/a/").await.unwrap(), 1);
    assert!(storage.list_keys("ctx/").await.unwrap().is_empty());
}

/// No key component may use the temp file prefix, so no stored key can be
/// hidden from `list_keys`.
#[tokio::test]
async fn key_with_temp_file_prefix_is_rejected() {
    use scp_platform::traits::Storage;

    let (storage, _dir) = filesystem_storage_with_dir();
    assert!(storage.store("ctx/.tmp.x", b"value").await.is_err());
    assert!(storage.store(".tmp.x/unit", b"value").await.is_err());
}
