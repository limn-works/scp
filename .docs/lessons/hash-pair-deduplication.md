# The RFC 6962 Interior-Node Hash Has Three Copies in `scp-event-log`

`hash_pair(left, right) = SHA-256(0x01 || left || right)` is defined three times:
`pub(crate)` in `crates/scp-event-log/src/tree.rs`, and privately in
`crates/scp-event-log/src/checkpoint.rs` and `crates/scp-event-log/src/pruning.rs`. If one
copy's domain-separation byte or input order drifts, proofs built by one module stop verifying
in another. Nothing raises an error; verification just returns `false`.

Any new module that needs an interior-node hash imports `tree::hash_pair` rather than defining
its own, and the two private copies should be replaced by that import.
