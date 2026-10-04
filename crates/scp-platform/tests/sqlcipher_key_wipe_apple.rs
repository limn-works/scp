//! `AppleStorage::open` leaves no freed `SQLite` block holding its key's
//! hex text (spec §17.6, `SQLCipher` configuration, and §9.15 of the
//! security-model spec, freed heap memory).
//!
//! The key statement embeds the key as hex text, and `SQLite` copies that text
//! into blocks it frees while parsing and running the statement. `SQLCipher`
//! wipes a freed block only once `PRAGMA cipher_memory_security = ON` has
//! taken effect, so the constructor must run the pragma before the key
//! statement; a freed block still holding the hex key shows it did not, or
//! did not run the pragma at all. A copy in a lookaside slot is not a freed
//! block: it stays live until the connection closes, and closing frees the
//! whole lookaside buffer through `SQLCipher`'s allocator, which wipes it. The
//! constructor's `connection_serves_nothing_from_lookaside` unit test covers
//! lookaside instead.
//!
//! The recording allocator of `scp-sqlite-pools/tests/support/freed_blocks.rs`
//! sits under `SQLCipher`'s allocator wrapper and sees each block after any
//! wipe. `SQLCipher` keeps memory security process-wide and never turns it off
//! once on, so this file holds one test and runs in a process of its own.

#![cfg(feature = "apple")]
#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

#[path = "../../scp-sqlite-pools/tests/support/freed_blocks.rs"]
mod freed_blocks;

use std::fmt::Write as _;

use scp_platform::apple::AppleStorage;

/// A key whose hex text appears nowhere else in the process.
const KEY: &[u8; 32] = b"SCP freed-key wipe test key 32B!";

#[test]
fn apple_storage_frees_no_block_holding_the_key() {
    let hex_key = KEY.iter().fold(String::new(), |mut hex, b| {
        write!(hex, "{b:02x}").unwrap();
        hex
    });
    freed_blocks::install(hex_key.clone().into_bytes(), 0);

    // Positive control: before anything turns memory security on, a
    // statement holding the hex text frees blocks that still hold it, so the
    // recorder can see the key when a wipe is missing.
    let control = scp_sqlite_pools::open_in_memory().expect("control connection should open");
    control
        .execute_batch(&format!("SELECT '{hex_key}';"))
        .expect("control statement should run");
    drop(control);
    assert!(
        freed_blocks::take_matching_frees() > 0,
        "the recorder must see the hex key in blocks freed without memory security"
    );

    let dir = tempfile::tempdir().expect("tempdir should succeed");
    let storage = AppleStorage::open(dir.path(), KEY).expect("AppleStorage::open should succeed");
    drop(storage);

    assert_eq!(
        freed_blocks::take_matching_frees(),
        0,
        "AppleStorage::open freed a SQLite block that still holds the key's hex text"
    );
}
