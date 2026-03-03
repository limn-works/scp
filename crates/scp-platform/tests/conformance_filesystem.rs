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
