# scp-sqlite-pools

Opens SQLCipher connections for SCP (Shared Context Protocol) with SQLite's
lookaside pool and page-cache bulk block both off (§17.6 of the persistence
spec, SQLCipher configuration; §9.15 of the security-model spec, freed heap
memory).

`PRAGMA cipher_memory_security = ON` makes SQLCipher wipe each block its
allocator frees. The lookaside pool and the page cache's bulk block reuse their
slots without freeing them, so the pragma never wipes a key, statement text, a
bound value, or a decrypted page they hold. Every open proves both off before
the connection's first statement, and keeps no state between opens:

- SQLite allocates a bulk block only when compiled without
  `SQLITE_ENABLE_MEMORY_MANAGEMENT`. Before opening, the crate calls
  `sqlite3_compileoption_used("ENABLE_MEMORY_MANAGEMENT")` and fails with
  `PoolsError::PageCacheBulkPossible` unless it returns 1. The bundled
  SQLCipher that libsqlite3-sys 0.30.1 compiles defines the option.
- After opening, it calls
  `sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, NULL, 0, 0)` and fails
  unless that returns `SQLITE_OK`.

`open(path)` and `open_in_memory()` are the only ways SCP opens a SQLCipher
connection; each SQLCipher constructor in `scp-platform` and `scp-transport`
calls one and maps `PoolsError` into its own storage error. `lookaside_use`
reports a connection's lookaside use, which is zero for a connection this crate
opened.

This is one of three crates that may use `unsafe` (`.docs/standards/rust.md`
§Safety Rules): its root sets `#![deny(unsafe_code)]`, and the only unsafe
blocks are its calls into SQLite's C API, each with a `// SAFETY:` comment.
