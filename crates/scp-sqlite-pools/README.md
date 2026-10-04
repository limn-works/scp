# scp-sqlite-pools

Opens SQLCipher connections for SCP (Shared Context Protocol) with SQLite's
lookaside pool, page-cache bulk block, and page-cache buffer all off (§17.6 of the persistence
spec, SQLCipher configuration; §9.15 of the security-model spec, freed heap
memory).

`PRAGMA cipher_memory_security = ON` makes SQLCipher wipe each block its
allocator frees. The lookaside pool and the page cache's bulk block reuse their
slots without freeing them, so the pragma never wipes a key, statement text, a
bound value, or a decrypted page they hold. Every open checks both off before
the connection's first statement, and keeps no state between opens:

- SQLite allocates a bulk block only when compiled without
  `SQLITE_ENABLE_MEMORY_MANAGEMENT`. Before opening, the crate calls
  `sqlite3_compileoption_used("ENABLE_MEMORY_MANAGEMENT")` and fails with
  `PoolsError::PageCacheBulkPossible` unless it returns 1. The bundled
  SQLCipher that libsqlite3-sys 0.30.1 compiles defines the option.
- After opening, it calls
  `sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, NULL, 0, 0)` and fails
  unless that returns `SQLITE_OK`.

`open(path)` and `open_in_memory()` are the only ways SCP's Rust crates open a
SQLCipher connection; each SQLCipher constructor in `scp-platform` and
`scp-transport` calls one and maps `PoolsError` into its own storage error.
The connections that the Android and Swift SDKs open in host code do not go
through this crate.

Each constructor runs `PRAGMA cipher_memory_security = ON` before its
`PRAGMA key` statement, because SQLCipher wipes only blocks freed after the
pragma takes effect, and after that batch calls `require_memory_security`,
which reads the pragma back and fails with `PoolsError::MemorySecurityOff`
unless it returns `1`. A plain SQLite returns no row, so the readback also
shows SQLCipher is the linked engine.

A page-cache buffer that a process hands SQLite with
`sqlite3_config(SQLITE_CONFIG_PAGECACHE, ...)` before it starts reuses its
slots the same way. Before it opens the caller's connection, every open runs
one page-reading statement on a throwaway in-memory connection, closes it,
reads the `SQLITE_STATUS_PAGECACHE_USED` high-water mark with
`sqlite3_status64`, and fails with `PoolsError::PageCacheBufferUsed` unless it
is 0. The check precedes the caller's open because opening a connection already
checks a buffer slot out for the pager's scratch space, and its first statement
reads the database's pages into slots. The throwaway connection is the one
SQLCipher connection exempt from these requirements and from the pragma: it
opens no database SCP stores data in and holds no data.

These checks and the readback read SQLite's state, so they hold only while no
code in the same process reconfigures SQLite, by any call. Its forms include
installing a custom page cache with `SQLITE_CONFIG_PCACHE2` before SQLite
starts, which cannot be read back; replacing the allocator with
`SQLITE_CONFIG_MALLOC` after `sqlite3_shutdown`, after which freed blocks go
unwiped while the readback still returns `1`; resetting the
`SQLITE_STATUS_PAGECACHE_USED` high-water mark; and installing a page-cache
buffer or custom page cache after `sqlite3_shutdown`, between an open's
page-cache buffer check and its connection.

`lookaside_use` reports a connection's
lookaside use, which is zero for a connection this crate opened.

This is one of three crates that may use `unsafe` (`.docs/standards/rust.md`
§Safety Rules): its root sets `#![deny(unsafe_code)]`, and the only unsafe
blocks are its calls into SQLite's C API, each with a `// SAFETY:` comment.
