# A Handle That Records a Position Names a Different Record After the Next Write

**Problem**: `FileKeyCustody` recorded `(key_type, entry_index)` for every key
handle and bound `key_type ‖ entry_index` as AES-256-GCM associated data.
`destroy_key` compacted the key file, which moved every entry after the removed
one down one position, and re-encrypted each moved entry under its new position
so that its associated data kept matching.

Every bridge opens one `$HOME/.scp/keys.bin`, and each identity creation
constructs a fresh `FileKeyCustody` over that path, so two custody objects
routinely sit over one file. `destroy_key` on one object shifted the entries the
other object's handles named. Three checks all passed on the resulting read:

- the file HMAC matched, because the rewrite recomputed it;
- the stored `key_type` byte matched, because `#0`, `#active`, and `#agent` are
  all Ed25519 keys of one identity;
- the associated data matched, because the rewrite re-encrypted the moved entry
  under exactly the position the stale handle recorded.

`sign` then returned a signature under a key its caller never designated, and
`destroy_key` reached by the same route deleted a key its handle never named.

**Correct pattern**: give each record an identifier the writer draws once and
never reuses, record that identifier in the handle, find the record by comparing
identifiers, and bind the identifier — not the position — as associated data.
`FileKeyCustody` now writes a 16-byte `entry_id` per entry:

```rust
fn entry_aad(key_type: StoredKeyType, entry_id: &EntryId) -> [u8; 1 + ENTRY_ID_LEN]

fn find_entry_index(data: &[u8], entry_id: &EntryId) -> Option<usize>
```

A compaction then copies each surviving entry byte for byte, a stale handle
finds no entry and returns an error, and no rewrite can hand a handle another
handle's key.

**Rule**: a position is a property of a container's current layout, not an
identity. Binding a capability to a position makes every rewrite of that
container a chance to hand a holder something it never asked for, and the
authentication tag says nothing about it, because the writer computes the tag
over the layout it just produced. Ask of any handle: which write invalidates it,
and what does its holder read afterwards?
