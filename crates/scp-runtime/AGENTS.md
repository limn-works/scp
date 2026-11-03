# scp-runtime

This crate assembles the runtime (ADR-070): `domain_handlers` builds the `DomainHandlers` the Supervisor constructors take, and `test_supervisor` builds a Supervisor for tests. It holds no protocol logic. The rules for every runtime crate are in `crates/scp-runtime-core/AGENTS.md`; read that file before you change this crate.
