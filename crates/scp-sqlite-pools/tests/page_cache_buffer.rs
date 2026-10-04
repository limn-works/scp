//! [`scp_sqlite_pools::require_no_page_cache_buffer`] refuses a process whose
//! `SQLite` serves pages from a `SQLITE_CONFIG_PAGECACHE` buffer (spec §17.6,
//! `SQLCipher` configuration). The buffer is configured before `SQLite`
//! starts, which happens once per process, so this file holds one test and
//! runs in a process of its own.

#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

#[path = "support/page_cache_buffer.rs"]
mod page_cache_buffer;

#[test]
fn require_no_page_cache_buffer_refuses_a_configured_buffer() {
    page_cache_buffer::install();
    page_cache_buffer::assert_buffer_serves_pages();
}
