//! `CombinedNodeStorage::open` refuses to hand out a connection when `SQLite` serves pages
//! from a `SQLITE_CONFIG_PAGECACHE` buffer, whose freed slots `SQLite` keeps
//! on its own free list without `SQLCipher`'s memory security wiping them
//! (spec §17.6, `SQLCipher` configuration, and §9.15 of the security-model
//! spec, freed heap memory).
//!
//! The buffer of `scp-sqlite-pools/tests/support/page_cache_buffer.rs` is
//! configured before `SQLite` starts, which happens once per process, so this
//! file holds one test and runs in a process of its own.

#![cfg(feature = "combined")]
#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

#[path = "../../scp-sqlite-pools/tests/support/page_cache_buffer.rs"]
mod page_cache_buffer;

use scp_transport::native::combined::CombinedNodeStorage;

const KEY: &[u8; 32] = b"SCP page-cache buffer test key!!";

#[test]
fn combined_node_storage_refuses_a_page_cache_buffer() {
    page_cache_buffer::install();
    page_cache_buffer::assert_buffer_serves_pages();

    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let e = CombinedNodeStorage::open(dir.path(), KEY)
        .expect_err("CombinedNodeStorage::open must refuse a process whose SQLite serves pages from a page-cache buffer");
    assert!(
        e.to_string()
            .contains("SQLITE_CONFIG_PAGECACHE buffer has held pages"),
        "CombinedNodeStorage::open must refuse with the page-cache buffer error, got {e}"
    );
}
