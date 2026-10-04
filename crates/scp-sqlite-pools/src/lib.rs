//! Opens `SQLCipher` connections with `SQLite`'s lookaside pool and page-cache
//! bulk block both proven off (spec §17.6, `SQLCipher` configuration, and §9.15
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
//! [`open`] and [`open_in_memory`] prove both off before the connection's
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
//!   returns `SQLITE_BUSY` while any slot is in use, so `SQLITE_OK` proves the
//!   pool is off for that connection.
//!
//! The crate keeps no state: every open makes both checks itself.

#![deny(unsafe_code)]

use std::ffi::{c_int, c_void};
use std::fmt;
use std::path::Path;
use std::ptr;

use rusqlite::{Connection, ffi};

/// Why a `SQLCipher` connection cannot be opened with both pools off.
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
    /// `sqlite3_db_status` did not return `SQLITE_OK`.
    Status {
        /// The `SQLite` result code the call returned.
        code: c_int,
    },
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
            Self::Status { code } => write!(f, "sqlite3_db_status returned code {code}"),
        }
    }
}

impl std::error::Error for PoolsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(e) => Some(e),
            Self::PageCacheBulkPossible | Self::LookasideOn { .. } | Self::Status { .. } => None,
        }
    }
}

/// Opens the database file at `path` with the page-cache bulk block and the
/// lookaside pool both proven off. The caller runs its key statement next.
///
/// # Errors
///
/// [`PoolsError::PageCacheBulkPossible`] when the linked `SQLite` lacks
/// `SQLITE_ENABLE_MEMORY_MANAGEMENT` (no connection is opened),
/// [`PoolsError::Open`] when `SQLite` cannot open the file, and
/// [`PoolsError::LookasideOn`] when lookaside cannot be turned off.
pub fn open(path: &Path) -> Result<Connection, PoolsError> {
    open_checked(memory_management_compile_option(), || {
        Connection::open(path)
    })
}

/// Opens an in-memory database with both pools proven off, as [`open`] does.
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
/// `SQLite`'s answer for `ENABLE_MEMORY_MANAGEMENT`) is 1, then turns
/// lookaside off on the new connection. [`open`] and [`open_in_memory`] pass
/// the real answer; only this crate's unit tests pass another.
fn open_checked(
    memory_management: c_int,
    connect: impl FnOnce() -> rusqlite::Result<Connection>,
) -> Result<Connection, PoolsError> {
    require_no_bulk_block(memory_management)?;
    let conn = connect().map_err(PoolsError::Open)?;
    turn_lookaside_off(&conn)?;
    Ok(conn)
}

/// `sqlite3_compileoption_used` returns 1 when the option was defined at
/// compile time and 0 otherwise; only 1 proves the bulk block absent.
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

    /// With the option present, the same path opens and turns lookaside off.
    #[test]
    fn open_with_memory_management_opens_with_lookaside_off() -> Result<(), PoolsError> {
        let conn = open_checked(1, Connection::open_in_memory)?;
        conn.execute_batch("CREATE TABLE t (v BLOB NOT NULL); INSERT INTO t VALUES (x'00');")
            .map_err(PoolsError::Open)?;
        assert_eq!(
            lookaside_use(&conn)?,
            LookasideUse {
                slots_high_water: 0,
                hits: 0
            }
        );
        Ok(())
    }
}
