//! Opens `SQLCipher` connections with `SQLite`'s lookaside pool and page-cache
//! bulk block both off (spec §17.6, `SQLCipher` configuration, and §9.15 of the
//! security-model spec, freed heap memory).
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
//! Both are turned off at run time, so a build of `SQLCipher` with any flags,
//! from the `PyPI` sdist, crates.io or the repository, has them off:
//!
//! - **Page-cache bulk block.** `SQLite` sizes the bulk block from
//!   `sqlite3GlobalConfig.nPage`, read once at initialization. Before any
//!   connection opens, this crate calls
//!   `sqlite3_config(SQLITE_CONFIG_PAGECACHE, NULL, 0, 0)` once per process,
//!   records its return code in a `OnceLock`, and initializes `SQLite`. The call
//!   returns `SQLITE_MISUSE` once `SQLite` is initialized, so a recorded
//!   `SQLITE_OK` proves the bulk block is off for every connection in the
//!   process, and any other code makes every open fail.
//! - **Lookaside.** After opening a connection and before its first statement,
//!   [`open`] calls `sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, NULL, 0,
//!   0)`. `SQLite` returns `SQLITE_BUSY` while any slot is in use, so
//!   `SQLITE_OK` proves the pool is off for that connection.
//!
//! The bundled `SQLCipher` that libsqlite3-sys 0.30.1 compiles defines
//! `SQLITE_ENABLE_MEMORY_MANAGEMENT`, under which every cache shares one page
//! group and `SQLite` allocates no bulk block, whatever the configuration. The
//! page-cache call keeps the bulk block off for a build without that flag, and
//! the recorded code is the only proof that does not depend on how `SQLite`
//! was compiled.
//!
//! [`open`] and [`open_in_memory`] are the only ways SCP opens a `SQLCipher`
//! connection. `SQLite`'s initialization reads the configuration once, so code
//! that opens a connection without this crate before the first [`open`] leaves
//! the bulk block on in a build that allocates one, and every later [`open`]
//! then fails with [`PoolsError::PageCacheBulkOn`].

#![deny(unsafe_code)]

use std::ffi::{c_int, c_void};
use std::fmt;
use std::path::Path;
use std::ptr;
use std::sync::OnceLock;

use rusqlite::{Connection, ffi};

/// The return code of this process's one pre-initialization
/// `sqlite3_config(SQLITE_CONFIG_PAGECACHE, NULL, 0, 0)` call, or of the
/// `sqlite3_initialize` that follows it when that fails. `SQLite` reads the
/// page-cache configuration only when it initializes, once per process, so
/// only a record of this one call can prove later that the bulk block is off;
/// every open reads it and refuses to proceed unless it is `SQLITE_OK`.
static PAGE_CACHE_CONFIG_RESULT: OnceLock<c_int> = OnceLock::new();

/// Why a `SQLCipher` connection cannot be opened with both pools off.
#[derive(Debug)]
pub enum PoolsError {
    /// The process-wide page-cache configuration did not return `SQLITE_OK`.
    /// `SQLITE_MISUSE` (21) means `SQLite` was initialized before the call
    /// ran, so the bulk block is on for every connection in this process.
    PageCacheBulkOn {
        /// The `SQLite` result code recorded for the configuration call.
        code: c_int,
    },
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
            Self::PageCacheBulkOn { code } => write!(
                f,
                "SQLite's page-cache bulk block cannot be proven off: the pre-initialization \
                 sqlite3_config(SQLITE_CONFIG_PAGECACHE) returned code {code} (21 means SQLite \
                 was initialized before SCP opened its first connection), so freed pages \
                 would keep decrypted plaintext unwiped"
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
            Self::PageCacheBulkOn { .. } | Self::LookasideOn { .. } | Self::Status { .. } => None,
        }
    }
}

/// Opens the database file at `path` with the page-cache bulk block and the
/// lookaside pool both proven off. The caller runs its key statement next.
///
/// # Errors
///
/// [`PoolsError::PageCacheBulkOn`] when the process-wide configuration was not
/// `SQLITE_OK`, [`PoolsError::Open`] when `SQLite` cannot open the file, and
/// [`PoolsError::LookasideOn`] when lookaside cannot be turned off.
pub fn open(path: &Path) -> Result<Connection, PoolsError> {
    require_page_cache_bulk_off()?;
    let conn = Connection::open(path).map_err(PoolsError::Open)?;
    turn_lookaside_off(&conn)?;
    Ok(conn)
}

/// Opens an in-memory database with both pools proven off, as [`open`] does.
///
/// # Errors
///
/// As [`open`].
pub fn open_in_memory() -> Result<Connection, PoolsError> {
    require_page_cache_bulk_off()?;
    let conn = Connection::open_in_memory().map_err(PoolsError::Open)?;
    turn_lookaside_off(&conn)?;
    Ok(conn)
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

fn require_page_cache_bulk_off() -> Result<(), PoolsError> {
    let code = *PAGE_CACHE_CONFIG_RESULT.get_or_init(configure_page_cache_before_init);
    if code == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(PoolsError::PageCacheBulkOn { code })
    }
}

/// Sets the page cache's initial bulk size to zero pages, then initializes
/// `SQLite` so the setting takes effect before anything else can initialize it.
/// Runs at most once per process, inside `PAGE_CACHE_CONFIG_RESULT`'s
/// `get_or_init`.
#[allow(unsafe_code)]
fn configure_page_cache_before_init() -> c_int {
    let no_buffer: *mut c_void = ptr::null_mut();
    let zero: c_int = 0;
    // SAFETY: `SQLITE_CONFIG_PAGECACHE` takes three variadic arguments, a
    // `void*` buffer, an `int` slot size and an `int` slot count, and these are
    // exactly those types. Before initialization `sqlite3_config` is not
    // thread-safe: no other thread may call into `SQLite` while it runs. Every
    // SCP connection opens through this crate, and `OnceLock::get_or_init`
    // runs this function on one thread while every other caller waits, so no
    // SCP code calls `SQLite` concurrently. Once `SQLite` is initialized the call
    // only reads the initialized flag and returns `SQLITE_MISUSE`.
    let code = unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_PAGECACHE, no_buffer, zero, zero) };
    if code != ffi::SQLITE_OK {
        return code;
    }
    // SAFETY: `sqlite3_initialize` takes no arguments and is thread-safe.
    unsafe { ffi::sqlite3_initialize() }
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
