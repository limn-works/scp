[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / prefixSuccessor

# Function: prefixSuccessor()

> **prefixSuccessor**(`prefix`): `string` \| `null`

Defined in: [src/storage/wasm-sqlite.ts:124](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L124)

Computes the exclusive upper bound for a prefix range scan.

Given a prefix string, returns the lexicographically next string that is
not a prefix match. This enables efficient B-tree range queries:
`WHERE key >= prefix AND key < prefixSuccessor(prefix)`.

Returns null if the prefix consists entirely of 0xFF bytes (no successor
exists), which means the range scan should use an unbounded upper limit.

This mirrors the Rust SqliteStorage prefix_successor pattern.

## Parameters

### prefix

`string`

## Returns

`string` \| `null`
