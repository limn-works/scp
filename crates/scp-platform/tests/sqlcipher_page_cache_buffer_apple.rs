//! `AppleStorage::open` refuses, before it opens its database, to hand out a
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

#![cfg(feature = "apple")]
#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

#[path = "../../scp-sqlite-pools/tests/support/page_cache_buffer.rs"]
mod page_cache_buffer;

use scp_platform::apple::AppleStorage;

const KEY: &[u8; 32] = b"SCP page-cache buffer test key!!";

#[test]
fn apple_storage_refuses_a_page_cache_buffer() {
    // `SQLite`'s largest page size, so every page fits a slot.
    page_cache_buffer::install(65_536);

    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let database = dir.path().join("scp.db");
    let e = AppleStorage::open(dir.path(), KEY)
        .err()
        .expect("AppleStorage::open must refuse a process whose SQLite serves pages from a page-cache buffer");
    page_cache_buffer::assert_refused_before_open("AppleStorage::open", &e.to_string(), &database);
}
