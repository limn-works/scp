//! Refuses a `SQLCipher` connection whose library keeps `SQLite`'s lookaside
//! allocator on.
//!
//! The lookaside allocator is a per-connection pool of small slots that
//! `SQLite` hands out and takes back without calling `free`, so a slot that
//! held a parsed `PRAGMA key` value, statement text, or a bound secret keeps
//! those bytes until a later allocation reuses it or the connection closes.
//! `PRAGMA cipher_memory_security` wipes only the blocks `SQLCipher`'s
//! allocator frees, and a lookaside slot never reaches it. With lookaside off,
//! every block `SQLite` takes for a connection comes from that allocator and is
//! wiped when freed (spec §17.6, and §9.15 of the security-model spec, freed
//! heap memory).
//!
//! The workspace's `.cargo/config.toml` builds the bundled `SQLCipher` with
//! `-DSQLITE_DEFAULT_LOOKASIDE=0,0`, and `PRAGMA compile_options` reports that
//! setting. A build that reaches this crate without the flag (a build started
//! outside the repository, or one that consumes the published crate) fails
//! here with a typed error instead of opening a connection that keeps freed
//! secrets in its pool.

use rusqlite::Connection;

/// The `PRAGMA compile_options` row a library built with
/// `-DSQLITE_DEFAULT_LOOKASIDE=0,0` reports. A library built without that flag
/// reports no `DEFAULT_LOOKASIDE` row at all.
const LOOKASIDE_OFF_OPTION: &str = "DEFAULT_LOOKASIDE=0,0";

/// Returns `Ok(())` when the `SQLite` library behind `conn` was built with a
/// zero-size lookaside pool, and a description of the failure otherwise.
///
/// Call it on a new connection before any statement that carries key material.
///
/// # Errors
///
/// Returns the reason as a string when `PRAGMA compile_options` fails or does
/// not report `DEFAULT_LOOKASIDE=0,0`; each caller wraps it in its own error
/// type.
pub fn require_lookaside_off(conn: &Connection) -> Result<(), String> {
    let mut statement = conn
        .prepare("PRAGMA compile_options")
        .map_err(|e| format!("failed to read SQLite compile options: {e}"))?;
    let mut rows = statement
        .query([])
        .map_err(|e| format!("failed to read SQLite compile options: {e}"))?;
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("failed to read SQLite compile options: {e}"))?
    {
        let option: String = row
            .get(0)
            .map_err(|e| format!("failed to read SQLite compile options: {e}"))?;
        if option == LOOKASIDE_OFF_OPTION {
            return Ok(());
        }
    }
    Err(format!(
        "SQLCipher was built with SQLite's lookaside allocator on, which keeps freed \
         blocks unwiped; build it with LIBSQLITE3_FLAGS=-DSQLITE_{LOOKASIDE_OFF_OPTION}"
    ))
}
