//! Opens `SQLCipher` connections with `SQLite`'s lookaside pool, page-cache
//! bulk block, and page-cache buffer all shown off (spec §17.6, `SQLCipher` configuration, and §9.15
//! of the security-model spec, freed heap memory).
//!
//! `PRAGMA cipher_memory_security = ON` makes `SQLCipher` wipe each block its
//! allocator frees. Two `SQLite` pools reuse their slots without freeing them
//! through that allocator, so the pragma never wipes them:
//!
//! - the per-connection lookaside pool, whose slots keep a parsed key,
//!   statement text, or a bound value until the connection closes;
//! - the page cache's bulk block, allocated once per cache, whose freed page
//!   slots keep the decrypted plaintext of a page that a rollback, truncation,
//!   or cache shrink dropped (`pcache1InitBulk` and `pcache1FreePage` in
//!   `sqlite3.c`).
//!
//! [`open`] and [`open_in_memory`] check both off before the connection's
//! first statement:
//!
//! - **Page-cache bulk block.** `SQLite` allocates a bulk block only when it was
//!   compiled without `SQLITE_ENABLE_MEMORY_MANAGEMENT`. With that option
//!   `pcache1Init` sets `separateCache = 0`, so `nInitPage` stays 0 and
//!   `pcache1InitBulk` allocates nothing, whatever the run-time configuration.
//!   Before opening, each call asks the linked `SQLite`
//!   `sqlite3_compileoption_used("ENABLE_MEMORY_MANAGEMENT")` and refuses
//!   with [`PoolsError::PageCacheBulkPossible`] unless it returns 1. The bundled
//!   `SQLCipher` that libsqlite3-sys 0.30.1 compiles defines the option.
//! - **Lookaside.** After opening, each call runs
//!   `sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, NULL, 0, 0)`. `SQLite`
//!   returns `SQLITE_BUSY` while any slot is in use, so `SQLITE_OK` shows the
//!   pool is off for that connection.
//!
//! A third reuse path needs no compile option: a page-cache buffer handed to
//! `SQLite` with `sqlite3_config(SQLITE_CONFIG_PAGECACHE, ...)` before it
//! starts. `pcache1Free` returns a slot of that buffer to `SQLite`'s own free
//! list without calling `sqlite3_free`.
//!
//! - **Page-cache buffer.** Before it opens the caller's connection, each call
//!   opens a throwaway in-memory connection, runs one statement on it that
//!   reads a page, closes it, and reads the process's
//!   `SQLITE_STATUS_PAGECACHE_USED` high-water mark, refusing with
//!   [`PoolsError::PageCacheBufferUsed`] unless it is 0. The check must come
//!   before the caller's connection opens: opening a connection already checks
//!   a buffer slot out for the pager's scratch space, and the connection's
//!   first statement reads the database's pages into slots, so a check made
//!   after either would leave that connection's pages in slots `SQLite` reuses
//!   unwiped.
//!
//! The throwaway connection is the one `SQLCipher` connection exempt from the
//! requirements above and from the pragma: it sets no key, keeps its
//! lookaside pool, and is never passed to [`require_memory_security`]. It
//! opens no database SCP stores data in and holds no data, so no block it
//! frees and no slot it leaves holds a secret.
//!
//! The crate keeps no state: every open makes its checks itself.
//!
//! These checks read `SQLite`'s state, and code in the same process can change
//! that state. While no code in the process reconfigures `SQLite`, they show
//! the three paths off. Code in the same process that reconfigures `SQLite`,
//! by any call, is one limit of every check here and of the readback below.
//! Its forms include installing a custom page cache with
//! `SQLITE_CONFIG_PCACHE2` before `SQLite` starts, which `SQLite` offers no way
//! to read back; replacing the allocator with `SQLITE_CONFIG_MALLOC` after
//! `sqlite3_shutdown`, after which freed blocks go unwiped while the readback
//! still returns `1`; resetting the `SQLITE_STATUS_PAGECACHE_USED` high-water
//! mark, after which a buffer that has held pages reads 0; and installing a
//! page-cache buffer or custom page cache after `sqlite3_shutdown`, between an
//! open's page-cache buffer check and its connection, after which that
//! connection keeps its pages there although the check read 0.
//!
//! The pragma itself must run before the connection's `PRAGMA key` statement,
//! because `SQLCipher` wipes only blocks freed after the pragma takes effect.
//! After the batch that holds the key statement, each constructor calls
//! [`require_memory_security`], which reads the pragma back and refuses unless
//! it returns `1`; a plain `SQLite` returns no row, so the readback also
//! shows `SQLCipher` is the linked engine.

#![deny(unsafe_code)]

use std::ffi::{c_int, c_void};
use std::fmt;
use std::path::Path;
use std::ptr;

use rusqlite::{Connection, OptionalExtension, ffi};

/// Why a `SQLCipher` connection cannot be opened with every reuse path off.
#[derive(Debug)]
pub enum PoolsError {
    /// The linked `SQLite` was compiled without
    /// `SQLITE_ENABLE_MEMORY_MANAGEMENT`, so its page caches may allocate a
    /// bulk block that the pragma never wipes.
    PageCacheBulkPossible,
    /// `SQLite` could not open the connection.
    Open(rusqlite::Error),
    /// `sqlite3_db_config(SQLITE_DBCONFIG_LOOKASIDE, NULL, 0, 0)` did not
    /// return `SQLITE_OK`; `SQLITE_BUSY` (5) means a lookaside slot was in use.
    LookasideOn {
        /// The `SQLite` result code the call returned.
        code: c_int,
    },
    /// `sqlite3_db_status` or `sqlite3_status64` did not return `SQLITE_OK`.
    Status {
        /// The `SQLite` result code the call returned.
        code: c_int,
    },
    /// `PRAGMA cipher_memory_security` did not read back as `1`. `None` means
    /// the pragma returned no row, which a plain `SQLite` without `SQLCipher`
    /// does.
    MemorySecurityOff {
        /// The value the pragma returned, if any.
        reported: Option<String>,
    },
    /// `PRAGMA cipher_memory_security` could not be read.
    MemorySecurityUnreadable(rusqlite::Error),
    /// A page-cache buffer configured with `SQLITE_CONFIG_PAGECACHE` has held
    /// a page in this process, and `SQLite` returns its freed slots to its own
    /// free list without the pragma wiping them.
    PageCacheBufferUsed {
        /// The `SQLITE_STATUS_PAGECACHE_USED` high-water mark: the most buffer
        /// slots checked out at once since `SQLite` started.
        high_water: i64,
    },
    /// The throwaway in-memory connection that probes for a page-cache buffer
    /// could not open, run its statement, or close.
    Probe(rusqlite::Error),
}

impl fmt::Display for PoolsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PageCacheBulkPossible => f.write_str(
                "SQLite's page-cache bulk block cannot be proven absent: the linked SQLite was \
                 compiled without SQLITE_ENABLE_MEMORY_MANAGEMENT, so freed pages could keep \
                 decrypted plaintext unwiped",
            ),
            Self::Open(e) => write!(f, "failed to open database: {e}"),
            Self::LookasideOn { code } => write!(
                f,
                "SQLite's lookaside pool cannot be turned off for this connection: \
                 sqlite3_db_config(SQLITE_DBCONFIG_LOOKASIDE) returned code {code}"
            ),
            Self::Status { code } => write!(f, "a SQLite status call returned code {code}"),
            Self::MemorySecurityOff {
                reported: Some(value),
            } => write!(
                f,
                "SQLCipher's memory security is off: PRAGMA cipher_memory_security returned \
                 {value:?}, not \"1\""
            ),
            Self::MemorySecurityOff { reported: None } => f.write_str(
                "PRAGMA cipher_memory_security returned no row, so the linked engine is not \
                 SQLCipher",
            ),
            Self::MemorySecurityUnreadable(e) => {
                write!(f, "failed to read PRAGMA cipher_memory_security: {e}")
            }
            Self::PageCacheBufferUsed { high_water } => write!(
                f,
                "a SQLITE_CONFIG_PAGECACHE buffer has held pages in this process (high-water \
                 mark {high_water}), so freed pages could keep decrypted plaintext unwiped"
            ),
            Self::Probe(e) => write!(f, "the page-cache buffer probe failed: {e}"),
        }
    }
}

impl std::error::Error for PoolsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(e) | Self::MemorySecurityUnreadable(e) | Self::Probe(e) => Some(e),
            Self::PageCacheBulkPossible
            | Self::LookasideOn { .. }
            | Self::Status { .. }
            | Self::MemorySecurityOff { .. }
            | Self::PageCacheBufferUsed { .. } => None,
        }
    }
}

/// Opens the database file at `path` with the page-cache bulk block, the
/// page-cache buffer, and the lookaside pool all checked off. The caller runs
/// its key statement next.
///
/// # Errors
///
/// [`PoolsError::PageCacheBulkPossible`] when the linked `SQLite` lacks
/// `SQLITE_ENABLE_MEMORY_MANAGEMENT`, [`PoolsError::PageCacheBufferUsed`] when
/// a page-cache buffer has held a page, [`PoolsError::Probe`] when the probe
/// connection fails, and [`PoolsError::Status`] when `sqlite3_status64` fails,
/// none of them having opened the file; [`PoolsError::Open`] when `SQLite`
/// cannot open the file, and [`PoolsError::LookasideOn`] when lookaside cannot
/// be turned off.
pub fn open(path: &Path) -> Result<Connection, PoolsError> {
    open_checked(memory_management_compile_option(), || {
        Connection::open(path)
    })
}

/// Opens an in-memory database with every reuse path checked off, as [`open`]
/// does.
///
/// # Errors
///
/// As [`open`].
pub fn open_in_memory() -> Result<Connection, PoolsError> {
    open_checked(
        memory_management_compile_option(),
        Connection::open_in_memory,
    )
}

/// Reads `PRAGMA cipher_memory_security` back on `conn` and refuses unless it
/// returns `1`. Each `SQLCipher` constructor calls this after the batch that
/// holds its key statement (spec §17.6).
///
/// # Errors
///
/// [`PoolsError::MemorySecurityOff`] when the pragma returns anything but `1`
/// or no row, and [`PoolsError::MemorySecurityUnreadable`] when the query
/// fails.
pub fn require_memory_security(conn: &Connection) -> Result<(), PoolsError> {
    let reported: Option<String> = conn
        .query_row("PRAGMA cipher_memory_security", [], |row| row.get(0))
        .optional()
        .map_err(PoolsError::MemorySecurityUnreadable)?;
    require_reported_one(reported)
}

/// Accepts only the single value `1`; no row (`None`) means the engine is not
/// `SQLCipher`.
fn require_reported_one(reported: Option<String>) -> Result<(), PoolsError> {
    if reported.as_deref() == Some("1") {
        Ok(())
    } else {
        Err(PoolsError::MemorySecurityOff { reported })
    }
}

/// Refuses when a `SQLITE_CONFIG_PAGECACHE` buffer has held a page in this
/// process, after a throwaway connection has read a page so that a configured
/// buffer has served one (spec §17.6). The status is process-wide, so the call
/// reads `SQLite`'s own counter and keeps no state.
fn require_no_page_cache_buffer() -> Result<(), PoolsError> {
    probe_page_cache()?;
    require_no_buffer_slot_used(page_cache_used_high_water()?)
}

/// Opens a throwaway in-memory connection, runs one statement that reads a
/// page, and closes it. The connection holds no data of any database.
fn probe_page_cache() -> Result<(), PoolsError> {
    let probe = Connection::open_in_memory().map_err(PoolsError::Probe)?;
    probe
        .execute_batch("CREATE TABLE probe (x)")
        .map_err(PoolsError::Probe)?;
    probe.close().map_err(|(_, e)| PoolsError::Probe(e))
}

/// Only a high-water mark of 0 shows that no buffer slot ever held a page.
const fn require_no_buffer_slot_used(high_water: i64) -> Result<(), PoolsError> {
    if high_water == 0 {
        Ok(())
    } else {
        Err(PoolsError::PageCacheBufferUsed { high_water })
    }
}

/// How much a connection's lookaside pool has served since it opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookasideUse {
    /// The most lookaside slots checked out at once
    /// (`SQLITE_DBSTATUS_LOOKASIDE_USED` high-water mark).
    pub slots_high_water: c_int,
    /// The allocations the pool served (`SQLITE_DBSTATUS_LOOKASIDE_HIT`).
    pub hits: c_int,
}

/// Reports `conn`'s lookaside use since it opened. A connection from [`open`]
/// reports zero for both.
///
/// # Errors
///
/// [`PoolsError::Status`] when `sqlite3_db_status` fails.
pub fn lookaside_use(conn: &Connection) -> Result<LookasideUse, PoolsError> {
    Ok(LookasideUse {
        slots_high_water: status_high_water(conn, ffi::SQLITE_DBSTATUS_LOOKASIDE_USED)?,
        hits: status_high_water(conn, ffi::SQLITE_DBSTATUS_LOOKASIDE_HIT)?,
    })
}

/// Refuses before `connect` runs unless `memory_management` (the linked
/// `SQLite`'s answer for `ENABLE_MEMORY_MANAGEMENT`) is 1 and no page-cache
/// buffer has held a page, then turns lookaside off on the new connection.
/// [`open`] and [`open_in_memory`] pass the real answer; only this crate's
/// unit tests pass another.
fn open_checked(
    memory_management: c_int,
    connect: impl FnOnce() -> rusqlite::Result<Connection>,
) -> Result<Connection, PoolsError> {
    require_no_bulk_block(memory_management)?;
    require_no_page_cache_buffer()?;
    let conn = connect().map_err(PoolsError::Open)?;
    turn_lookaside_off(&conn)?;
    Ok(conn)
}

/// `sqlite3_compileoption_used` returns 1 when the option was defined at
/// compile time and 0 otherwise; only 1 shows the bulk block absent.
const fn require_no_bulk_block(memory_management: c_int) -> Result<(), PoolsError> {
    if memory_management == 1 {
        Ok(())
    } else {
        Err(PoolsError::PageCacheBulkPossible)
    }
}

#[allow(unsafe_code)]
fn memory_management_compile_option() -> c_int {
    // SAFETY: `sqlite3_compileoption_used` takes one NUL-terminated C string
    // and only reads it; the literal is static and NUL-terminated. The
    // function reads a constant table compiled into SQLite, needs no
    // initialization and is thread-safe.
    unsafe { ffi::sqlite3_compileoption_used(c"ENABLE_MEMORY_MANAGEMENT".as_ptr()) }
}

#[allow(unsafe_code)]
fn turn_lookaside_off(conn: &Connection) -> Result<(), PoolsError> {
    let no_buffer: *mut c_void = ptr::null_mut();
    let zero: c_int = 0;
    // SAFETY: `conn.handle()` is the live `sqlite3*` that `conn` owns and keeps
    // open for the whole borrow. `SQLITE_DBCONFIG_LOOKASIDE` takes three
    // variadic arguments, a `void*` buffer, an `int` slot size and an `int`
    // slot count, and these are exactly those types; a null buffer with a zero
    // size and count frees the connection's lookaside memory and leaves it
    // with no pool.
    let code = unsafe {
        ffi::sqlite3_db_config(
            conn.handle(),
            ffi::SQLITE_DBCONFIG_LOOKASIDE,
            no_buffer,
            zero,
            zero,
        )
    };
    if code == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(PoolsError::LookasideOn { code })
    }
}

#[allow(unsafe_code)]
fn page_cache_used_high_water() -> Result<i64, PoolsError> {
    let mut current: i64 = 0;
    let mut high_water: i64 = 0;
    // SAFETY: both out-pointers point at local `i64`s (`sqlite3_int64`) that
    // outlive the call, and a zero reset flag leaves the counters unchanged.
    // `sqlite3_status64` reads process-wide counters under SQLite's own mutex
    // and is thread-safe.
    let code = unsafe {
        ffi::sqlite3_status64(
            ffi::SQLITE_STATUS_PAGECACHE_USED,
            &raw mut current,
            &raw mut high_water,
            0,
        )
    };
    if code == ffi::SQLITE_OK {
        Ok(high_water)
    } else {
        Err(PoolsError::Status { code })
    }
}

#[allow(unsafe_code)]
fn status_high_water(conn: &Connection, op: c_int) -> Result<c_int, PoolsError> {
    let mut current: c_int = 0;
    let mut high_water: c_int = 0;
    // SAFETY: `conn.handle()` is the live `sqlite3*` that `conn` owns for the
    // whole borrow, and both out-pointers point at local `c_int`s that outlive
    // the call. A zero reset flag leaves the counters unchanged.
    let code = unsafe {
        ffi::sqlite3_db_status(conn.handle(), op, &raw mut current, &raw mut high_water, 0)
    };
    if code == ffi::SQLITE_OK {
        Ok(high_water)
    } else {
        Err(PoolsError::Status { code })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// The linked `SQLite` reports `ENABLE_MEMORY_MANAGEMENT`, so production
    /// opens pass the bulk-block check on this build.
    #[test]
    fn linked_sqlite_is_compiled_with_memory_management() {
        assert_eq!(memory_management_compile_option(), 1);
    }

    #[test]
    fn bulk_block_check_accepts_only_one() {
        assert!(require_no_bulk_block(1).is_ok());
        for answer in [0, -1, 2] {
            assert!(
                matches!(
                    require_no_bulk_block(answer),
                    Err(PoolsError::PageCacheBulkPossible)
                ),
                "answer {answer} must be refused"
            );
        }
    }

    /// A `SQLite` without the option is refused before any connection opens.
    #[test]
    fn open_refuses_without_memory_management_and_opens_nothing() {
        let connected = Cell::new(false);
        let result = open_checked(0, || {
            connected.set(true);
            Connection::open_in_memory()
        });
        assert!(
            matches!(result, Err(PoolsError::PageCacheBulkPossible)),
            "open must refuse a SQLite compiled without ENABLE_MEMORY_MANAGEMENT, got {result:?}"
        );
        assert!(
            !connected.get(),
            "the refusal must come before the connection opens"
        );
    }

    /// A connection on which no constructor ran the pragma is refused. The
    /// pragma is process-wide and can only be turned on, so nothing in this
    /// test binary turns it on.
    #[test]
    fn require_memory_security_refuses_a_connection_without_the_pragma() -> Result<(), PoolsError> {
        let conn = open_in_memory()?;
        let result = require_memory_security(&conn);
        assert!(
            matches!(
                &result,
                Err(PoolsError::MemorySecurityOff { reported: Some(value) }) if value == "0"
            ),
            "a connection without the pragma must be refused, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn memory_security_readback_accepts_only_one() {
        assert!(require_reported_one(Some("1".to_owned())).is_ok());
        for reported in [None, Some("0".to_owned()), Some("ON".to_owned())] {
            let result = require_reported_one(reported.clone());
            assert!(
                matches!(&result, Err(PoolsError::MemorySecurityOff { reported: r }) if *r == reported),
                "{reported:?} must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn page_cache_buffer_check_accepts_only_zero() {
        assert!(require_no_buffer_slot_used(0).is_ok());
        for high_water in [1, 64, -1] {
            assert!(
                matches!(
                    require_no_buffer_slot_used(high_water),
                    Err(PoolsError::PageCacheBufferUsed { high_water: h }) if h == high_water
                ),
                "high-water mark {high_water} must be refused"
            );
        }
    }

    /// No page-cache buffer is configured in this test binary, so the real
    /// counter reads 0 after the probe and a connection have read pages.
    #[test]
    fn page_cache_buffer_check_passes_without_a_buffer() -> Result<(), Box<dyn std::error::Error>> {
        let conn = open_in_memory()?;
        conn.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")?;
        require_no_page_cache_buffer()?;
        Ok(())
    }

    /// The probe error names the probe and keeps the `SQLite` error as its
    /// source.
    #[test]
    fn probe_error_keeps_its_source() {
        let e = PoolsError::Probe(rusqlite::Error::InvalidQuery);
        assert!(
            e.to_string()
                .starts_with("the page-cache buffer probe failed: ")
        );
        assert!(std::error::Error::source(&e).is_some());
    }

    /// A live prepared statement holds lookaside slots, so `SQLite` refuses
    /// to free the pool with `SQLITE_BUSY` and the call reports it; once the
    /// statement is finalized the same call succeeds.
    #[test]
    fn lookaside_in_use_is_refused_with_busy() -> Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("CREATE TABLE t (x)")?;
        let statement = conn.prepare("SELECT x FROM t WHERE x = ?1")?;
        assert!(
            status_high_water(&conn, ffi::SQLITE_DBSTATUS_LOOKASIDE_USED)? > 0,
            "the plain connection must have used lookaside for this test to reach the busy path"
        );
        let refused = turn_lookaside_off(&conn);
        assert!(
            matches!(refused, Err(PoolsError::LookasideOn { code }) if code == ffi::SQLITE_BUSY),
            "turning lookaside off under a live statement must fail with SQLITE_BUSY, got {refused:?}"
        );
        drop(statement);
        conn.flush_prepared_statement_cache();
        turn_lookaside_off(&conn)?;
        Ok(())
    }

    /// Runs only in the CI build that compiles `SQLite` with
    /// `-USQLITE_ENABLE_MEMORY_MANAGEMENT`: there the real compile-option
    /// check must refuse every open.
    #[test]
    #[ignore = "needs LIBSQLITE3_FLAGS=-USQLITE_ENABLE_MEMORY_MANAGEMENT"]
    fn open_refuses_a_sqlite_built_without_memory_management() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("pools.db");
        let file = open(&path);
        assert!(
            matches!(file, Err(PoolsError::PageCacheBulkPossible)),
            "open must refuse a SQLite compiled without ENABLE_MEMORY_MANAGEMENT, got {file:?}"
        );
        assert!(
            !path.exists(),
            "the refusal must come before the file opens"
        );
        let memory = open_in_memory();
        assert!(
            matches!(memory, Err(PoolsError::PageCacheBulkPossible)),
            "open_in_memory must refuse a SQLite compiled without ENABLE_MEMORY_MANAGEMENT, \
             got {memory:?}"
        );
        Ok(())
    }
}
