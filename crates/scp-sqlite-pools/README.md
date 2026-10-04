# scp-sqlite-pools

Opens SQLCipher connections for SCP (Shared Context Protocol) with SQLite's
lookaside pool and page-cache bulk block both off (§17.6 of the persistence
spec, SQLCipher configuration; §9.15 of the security-model spec, freed heap
memory).

`PRAGMA cipher_memory_security = ON` makes SQLCipher wipe each block its
allocator frees. The lookaside pool and the page cache's bulk block reuse their
slots without freeing them, so the pragma never wipes a key, statement text, a
bound value, or a decrypted page they hold. This crate turns both off at run
time, whatever flags compiled SQLite:

- Once per process, before SQLite initializes, it calls
  `sqlite3_config(SQLITE_CONFIG_PAGECACHE, NULL, 0, 0)` and records the return
  code. Every open fails unless that code is `SQLITE_OK`; `SQLITE_MISUSE` means
  something initialized SQLite first.
- For each connection, before its first statement, it calls
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
