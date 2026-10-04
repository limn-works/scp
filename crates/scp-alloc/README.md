# scp-alloc

The wiping global allocator for SCP (Shared Context Protocol). §9.15 of the
security-model spec (freed heap memory) requires every shipped SCP binary and
cdylib to overwrite each heap block with zeros before freeing it, including the
old block a reallocation frees.

`WipingAllocator<A>` wraps an inner `GlobalAlloc` (the standard library's
`System` in production) and, on every `dealloc`, overwrites the whole block with
volatile stores before forwarding the free. It does not override `realloc`, so
the trait's default allocates the new block, copies, and frees the old block
through the wiping `dealloc`.

This crate holds the workspace's one `#[global_allocator]` static. Each shipped
artifact's crate root links it with:

```rust
use scp_alloc as _;
```

and defines no global allocator of its own. `scripts/check-wiping-allocator.sh`
enforces both rules. The crate has no dependencies and compiles to
`wasm32-unknown-unknown`, where `System` is the dlmalloc that Rust's standard
library bundles for that target.

A Rust application that links SCP library crates without linking this crate
keeps its own global allocator, and §9.15 lists that case among the limits of
the guarantee.
