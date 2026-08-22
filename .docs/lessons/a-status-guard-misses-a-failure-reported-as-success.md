# A Status Guard Misses a Failure the Callee Reports as Success

**Date:** 2026-08-22
**Source:** Pull request #2363, the ADR-025 App Attest fail-closed change — review of `AppleStorage.bindText(_:to:at:)`

## The Problem

Pull request #2363 fixed one defect in `bindings/swift/Sources/SCP/Platform/AppleStorage.swift`
by routing all six `StorageProvider` methods through a throwing helper that reads
`sqlite3_bind_text`'s return code. That helper kept the argument shape the
unguarded call sites had used: a C string pointer from `NSString.utf8String`, and
`-1` as the length.

`sqlite3_bind_text` reads a negative length as "the bytes up to the first zero
byte", and it answers `SQLITE_OK` for that bind. So `set(key: "a\u{0}b", value: x)`
stored a row under the one-byte key `a`, `set(key: "a\u{0}c", value: y)` overwrote
that same row, and `get(key: "a\u{0}b")` answered `y`. The new guard read a status
code the truncation never set.

A measured run confirms both halves: `sqlite3_bind_text` answered `0` for a
nine-byte key, and the table then held one row whose key was five bytes.

## Why an Ordinary Review Passes It

The helper's own documentation states the criterion it enforces — "SQLite reports
a rejected bind through a return code" — and the helper enforces exactly that. The
code is internally consistent with its comment, and the comment is true. What the
comment does not say is which failures SQLite reports through that code, so a
reader checking the helper against its stated criterion finds nothing wrong.

## The Pattern

When a fix adds a guard on a callee's status code, ask which failures that callee
reports through some other channel, and which failures it reports as success. A
guard is evidence about the failures the callee signals; it is not a criterion for
the property the caller needs. State the property — here, "this method names a key
by that key's exact byte count" — and pick an argument shape that makes the
property hold by construction, rather than one that depends on the callee raising
an alarm.

Two failures `sqlite3_bind_text` reports as `SQLITE_OK`:

- a negative length, which truncates the value at its first zero byte;
- a null pointer, which binds SQL `NULL`.

## How to Catch This

- Write the case that exercises the property rather than the guard: bind a value
  carrying a zero byte and read back `length(CAST(?1 AS BLOB))`.
- Read back through the same width. `String(cString:)` truncates at a zero byte
  just as `-1` does, so fixing the bind alone leaves `listKeys` returning one
  string for two keys.
- Delete the fix and watch the case fail. Both cases added here fail on the
  C-string form: the byte-count case reads 5 where it requires 9, and the
  round-trip case loses six assertions.

## Related

- `.docs/lessons/wrap-error-sibling-methods-together.md`
- `.docs/lessons/two-independent-checks-bind-nothing.md`
