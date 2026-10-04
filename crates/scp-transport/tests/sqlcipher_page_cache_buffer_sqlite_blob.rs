//! `SqliteBlobStore::open` refuses, before it opens its database, to hand out a
//! connection when `SQLite` serves pages from a `SQLITE_CONFIG_PAGECACHE`
//! buffer, whose freed slots `SQLite` keeps
//! on its own free list without `SQLCipher`'s memory security wiping them
//! (spec §17.6, `SQLCipher` configuration, and §9.15 of the security-model
//! spec, freed heap memory).
//!
//! The buffer of `scp-sqlite-pools/tests/support/page_cache_buffer.rs` is
//! configured before `SQLite` starts, which happens once per process, so this
//! file holds one test and runs in a process of its own. The constructor is
//! the first thing that runs `SQLite`, so only its own probe can raise the
//! high-water mark it refuses.

#![cfg(feature = "sqlite-blob")]
#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

#[path = "../../scp-sqlite-pools/tests/support/page_cache_buffer.rs"]
mod page_cache_buffer;

use scp_transport::native::sqlite_blob::SqliteBlobStore;

#[test]
fn sqlite_blob_store_refuses_a_page_cache_buffer() {
    page_cache_buffer::install();

    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let database = dir.path().join("blobs.db");
    let e = SqliteBlobStore::open(&database)
        .expect_err("SqliteBlobStore::open must refuse a process whose SQLite serves pages from a page-cache buffer");
    page_cache_buffer::assert_refused_before_open(
        "SqliteBlobStore::open",
        &e.to_string(),
        &database,
    );
}
