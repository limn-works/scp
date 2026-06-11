# Supervisor hot-path primitives (ADR-049 §12 lock-free read invariant)

File: crates/scp-runtime/src/context/supervisor/supervisor.rs

- `actors: DashMap<String, ContextActorHandle>` — lookup() is lock-free DashMap::get. The per-command dispatch hot path.
- `crash_windows: DashMap<String, CrashWindow>` — crash/error path only, never steady-state reads.
- `local_dids: ArcSwap<HashSet<DID>>`, `standing_contexts: ArcSwap<HashMap<...>>` — ArcSwap load on read, write serialized through Supervisor::write_lock (tokio::Mutex, write-only).
- Providers (crypto/transport/event_log/clock/key_resolver/mls_storage/payment_adapter): OnceLock<Arc<dyn ..>> — set-once-at-init, lock-free *_ref() reads. Rust TTAS analog (OpenSSL #30659/#30670).
- write_lock: the ONLY tokio::Mutex on a write path; held only across sync registry mutations (actors.insert/remove, ArcSwap store) — never across .await. Registry-mutation serialization point shared by spawn/despawn/import/respawn.
- Enforced via crates/scp-runtime/clippy.toml disallowed-types + await_holding_lock deny.
