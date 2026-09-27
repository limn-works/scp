---
name: filekeycustody-v2-header
description: FileKeyCustody v0x02 key-file layout, its verified offsets, and the two defects the Aug-2026 fail-open branch left in it
metadata:
  type: project
---

# FileKeyCustody v0x02 key file (`crates/scp-platform/src/file.rs`)

Layout, verified byte-for-byte against every slice site (Aug 2026):
version 0..1 | salt 1..17 | commitment 17..49 | file_hmac 49..81 | entry_count 81..85.
`HEADER_SIZE = 85`, `ENTRY_SIZE = 61` (key_type 1 + nonce 12 + ct+tag 48).
All offset constants and all 12 slice sites agree. `open_existing` guards empty,
version, `< HEADER_SIZE`, and exact `HEADER_SIZE + n*ENTRY_SIZE` before slicing,
so no malformed file panics at construction.

## Two defects found and not yet fixed

**Tamper laundering (HIGH).** `read_file()` never checks the file HMAC. Only
`open_existing` does. `append_entry` and the `destroy_key` rewrite read the file,
mutate, and call `seal_file_mac` — so they compute a *valid* HMAC over bytes they
never verified. Swap two entries on disk while custody is open, then call
`generate_keypair`; the reordering survives the next open. The AEAD has no AAD
binding an entry to its index, so a moved ciphertext decrypts fine and a handle
signs with another handle's key. Fix: verify in `read_file`, or before mutation
in both write paths.

**Zero-byte placeholder (MEDIUM).** `create_new` reserves the path with
`create_file_exclusive` (0 bytes), then spends ~100-500 ms in Argon2id before
`atomic_write` fills it. A crash in that window, or a second concurrent
`FileKeyCustody::new` on the same path, leaves/reads a 0-byte file. Every later
open returns `"key file is empty"` forever, and that message does not tell an
operator the file is a deletable leftover. The `remove_file` at `create_new` covers
only the in-process error path.

**Why to re-check on any header change:** the header grew twice on that branch.
Grep every `data[` and `bytes[` in the file plus its tests; the tests index
`ENTRY_COUNT_OFFSET..HEADER_SIZE` and `..HEADER_SIZE` directly.
