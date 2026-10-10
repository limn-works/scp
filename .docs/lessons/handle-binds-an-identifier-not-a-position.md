# A Handle That Records a Position Names a Different Record After the Next Write

**Problem**: `FileKeyCustody` recorded `(key_type, entry_index)` for every key
handle. `destroy_key` compacted the key file, which moved every entry after the
removed one down one position, and then decremented the indices in its own
handle map.

The Python bridge constructs a fresh `FileKeyCustody` over `$HOME/.scp/keys.bin`
for every identity it creates, and two processes can open one path, so two
custody objects sit over one file. `destroy_key` on one object shifted the
entries the other object's handles named, and nothing told the other object.
Its next read passed every check the file offered:

- the stored `key_type` byte matched, because `#0`, `#active`, and `#agent` are
  all Ed25519 keys of one identity;
- AES-256-GCM accepted the ciphertext, because nothing bound it to a slot.

`sign` then returned a signature under a key its caller never designated, and
`destroy_key` reached by the same route deleted a key its handle never named.

Two fixes that look sufficient are not. A file HMAC does not catch it, because
the writer that compacted the file recomputes the HMAC over the layout it just
produced. Associated data over `key_type ‖ entry_index` does not catch it
either: the compaction re-encrypts each moved entry under its new position, so
the associated data matches exactly the position the stale handle recorded.

**Correct pattern**: give each record an identifier the writer draws once and
never reuses, record that identifier in the handle, find the record by comparing
identifiers, and bind the identifier, not the position, as associated data.
`FileKeyCustody` writes a 16-byte `entry_id` per entry
(§17.8 of `.docs/specs/17-persistence-and-storage.md`, "Per-entry binding"):

```rust
fn entry_aad(key_type: StoredKeyType, entry_id: &EntryId) -> [u8; 1 + ENTRY_ID_LEN]

fn find_entry_index(data: &[u8], entry_id: &EntryId) -> Option<usize>
```

A compaction then copies each surviving entry byte for byte, and a stale handle
finds no entry and returns an error.

The handle's own value must come from the identifier too. A constructor that
numbers handles 1 to n by file position rebuilds the positional binding on
every reopen, and `scp-node` and the identity migration in `scp-identity`
persist handles across restarts. `FileKeyCustody` therefore uses the first
eight bytes of `entry_id` as the handle's `u64`.

**Rule**: a position is a property of a container's current layout, not an
identity. Binding a capability to a position makes every rewrite of that
container a chance to hand a holder something it never asked for, and the
authentication tag says nothing about it, because the writer computes the tag
over the layout it just produced. Ask of any handle: which write invalidates it,
and what does its holder read afterwards?
