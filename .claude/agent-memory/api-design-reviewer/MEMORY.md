# API Design Reviewer Memory

- [Cross-SDK shape parity](cross-sdk-shape-parity.md) — recurring divergences between SDKs (return type, JSON-string parameters, calling convention, flat-namespace collisions, untyped custody, differing defaults), the direction to converge, and one divergence the binding substrate forces.

## Durable conventions
- Storage layering: a thin `Storage` trait (six methods) under a thick coordinator is the intended shape; conformance macros (`storage_conformance!`, `blob_store_conformance!`) validate each adapter in one invocation.
- A value whose invariant a type can enforce belongs in that type: a private-field record with one validating constructor made publishing bare, unframed bytes unrepresentable, and deriving a routing id inside the callee from the record's key closed the frame-versus-address mismatch. Flag any remaining pair of parameters where one is a pure function of the other.
