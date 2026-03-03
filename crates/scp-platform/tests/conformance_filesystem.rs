//! Filesystem storage conformance tests.
//!
//! Validates that `FilesystemStorage` passes all 13 conformance tests
//! defined in `storage_conformance!()` (spec sections 17.6, 17.11, 17.13).

#![cfg(feature = "filesystem")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_platform::filesystem::FilesystemStorage;

fn make_filesystem_storage() -> FilesystemStorage {
    let dir = tempfile::tempdir().expect("tempdir should succeed");
    // Keep the tempdir so it lives for the duration of the test.
    let dir_path = dir.keep();
    FilesystemStorage::new(&dir_path).expect("FilesystemStorage::new should succeed")
}

scp_testing::storage_conformance!(make_filesystem_storage());
