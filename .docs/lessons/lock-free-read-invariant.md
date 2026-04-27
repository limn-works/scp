# Lock-free read invariant

## TL;DR

For any state read on a hot path (more than once per command dispatch), use a lock-free primitive. `tokio::sync::RwLock` and `tokio::sync::Mutex` are forbidden on read paths regardless of contention, because read locks are not free even uncontended: every `RwLock::read().await` performs an atomic increment on the reader counter (and a corresponding decrement on release), and every writer invalidates the cacheline of every reader.

## Empirical citation

OpenSSL issue [#30659](https://github.com/openssl/openssl/issues/30659) — "Analysis of read locks taken while handshaking" (Apr 2026). nhorman measured:

- `RWLOCK_read_lock` on the `rand_meth_lock`: ~67 cycles per acquire, even uncontended.
- `__atomic_load_n(__ATOMIC_RELAXED)` of the same pointer: ~17 cycles per load, even uncontended.
- 4× hot-path cost difference before any contention.
- Write side requires a cacheline invalidation broadcast on every concurrent reader; readers pay an L1 miss on next acquire.

The fix was implemented in OpenSSL PR [#30670](https://github.com/openssl/openssl/pull/30670) (merged to master 2026-04-14) using a TTAS pattern: lockless `atomic_load_ptr` fast path returning the cached method on the common case (already-installed), `cmp_exch_ptr` slow path for the first-install case. Result on the `randbytes` performance test: visible throughput improvement at every thread count from 1-16. Result on the original `handshake` test: zero throughput change — because rand-lock acquires were only 4% of handshake work, and the freed cycles were absorbed by contention shifting to `EX_READ_LOCK`, `PROPERTY_READ_LOCK`, and `SSL_SESSION_READ_LOCK*`.

This is the canonical "Amdahl's law squeeze": eliminating one lock surfaces previously-masked contention. Macro wins require attacking the densest contention sources together, not one at a time. The corollary is workload sensitivity: the same code change delivers different results on different workloads depending on what fraction of total work the optimized path represents.

## Rust translation

| Pattern | Primitive | Why |
|---|---|---|
| Set once at init, never mutates after | `OnceLock<Arc<dyn …>>` | Lock during init; lock-free atomic load forever after. The Rust analog of OpenSSL's TTAS pattern in PR #30670 (`atomic_load_ptr` fast path + `cmp_exch_ptr` install). `OnceLock::get` is the lockless peek; `OnceLock::set` is the cmp_exch install. |
| Rarely written, read constantly | `ArcSwap<…>` with writes serialized by an outer `Mutex<()>` | `ArcSwap::load` is ~2 atomic ops; the outer mutex prevents lost writes from concurrent `store`. Per-write cost is high; per-read cost is essentially zero. |
| Mutation hotspot with ordering invariant | Dedicated narrow actor (e.g., `KeyPackageStoreActor`) | Mailbox serializes mutations by construction. No shared lock; no contention. |
| Counter that must monotonically advance | `AtomicU64` | `fetch_add` with `Relaxed` ordering for monotonicity-only; `SeqCst` if causal ordering with other ops is required. |
| Per-key map with rare key-set changes | `DashMap<K, …>` | Lock-free reads via sharding; per-shard mutex only on writes to that shard. |

## What "hot path" means

A read path is hot if it executes more than once per command dispatch. Examples in SCP that qualify:
- `Supervisor::lookup(context_id)` — once per public API call.
- `is_local_did(did)` — checked on every dispatch.
- `standing_peer(ctx_id)` — checked on every standing-context message.
- Provider OnceLock accessors (`crypto_ref`, `transport_ref`, `event_log_ref`, `clock_ref`, `key_resolver_ref`).
- `wrapping_public_key_for(did)` — checked on every Welcome and on every cross-identity wrapping operation.

Examples that do NOT qualify (locks are fine):
- `set_payment_adapter` — called once per FFI bridge construction.
- Saga journal append on phase transitions — saga ops are infrequent.
- `Supervisor::write_lock` itself — held briefly across ArcSwap stores; readers don't contend.

## Lock-elimination validation gate

Every commit that deletes or splits a serializing primitive MUST be accompanied by a Shuttle or stress test that:
1. Exercises the new concurrent path under realistic I/O jitter (not collapsed by fast in-memory ops).
2. Asserts correctness (no race, no silent corruption, no thread-pool exhaustion).
3. Asserts that no other lock now shows >2× the prior acquire count under the existing perf workload.

The third assertion is the OpenSSL #30659 lesson made concrete: lock removal that shifts contention 1:1 elsewhere is correctness without throughput.

## Workload-sensitivity in perf measurement

Same code change, opposite results, depending on workload composition. OpenSSL PR #30670: rand-lock TTAS fix delivered visible gain on `randbytes` (rand was ~100% of work) and zero gain on `handshake` (rand was 4% of work). When measuring a lock-related refactor, cover both:
- **Hot-path-dominated workloads**: the optimized lock acquire is a meaningful fraction of total work. Gains are visible. Use this to verify the optimization works.
- **Crypto/IO-dominated workloads**: the optimized lock acquire is a small fraction of total work. Gains are invisible. Use this to verify the optimization doesn't regress (mailbox/dispatch overhead can exceed the lock saving).

Reporting only one is misleading: hot-path-only declares false success on broad workloads; IO-dominated-only declares false failure on tight protocol paths.

## Slow-path measurement

OpenSSL PR #30670 reviewers caught that on no-atomics platforms the new TTAS code takes TWO locks (load + cmp_exch) where the original took ONE. Rust analog: ArcSwap writes are `write_lock.lock().await` + `arcswap.store()` + reader cacheline invalidation (3 atomic ops) vs prior `RwLock::write().await` (1 acquire + broadcast). Likely faster but worth measuring. Perf baselines must include the WRITE path under realistic concurrency, not just the read fast path.

## Performance rollback trigger

For any refactor whose primary goal is correctness (not performance), a measured throughput regression of >15% on a named hot path is a rollback trigger. The 15% figure is judgment-based and should be tuned per refactor; the principle is that "correctness with throughput regression" requires explicit acceptance, not silent acceptance. See ADR-049 §Decision 14 for the actor-per-context case.

## Related decisions / ADRs

- ADR-049 §12 (lock-free read invariant — normative for this refactor).
- ADR-049 §13 (lock-elimination validation gate — generalizes the OpenMLS shared-storage gate to any lock deletion).
- ADR-049 §14 (performance regression as a rollback trigger).
- ADR-049 rejected alternative: "Convert ArcSwap to RwLock for callsite parity" (rejected with this lesson as the citation).

## Related anti-patterns

- "Convert ArcSwap to RwLock so existing callsite syntax stays byte-identical." Pays a per-acquire cost forever to avoid a one-time migration. The OpenSSL data is the disproof.
- "Allow post-init mutation of a frozen-after-init primitive (RAND_METHOD, transport, event_log, clock) so callers can swap implementations." Reintroduces a hot-path lock for a write that happens once. Use construction-time injection instead.
- "Lock-elimination is correctness-sufficient." It isn't. Without surfacing where contention shifts to, the macro effect is unmeasured and likely zero.
- "Measure on the workload most likely to show wins." Confirmation bias. Pick the workload that ALSO has the most chance of showing regressions (slow path, low-contention, mailbox-overhead-dominant) and measure both.
- "The slow path doesn't matter, it's rare." It matters when the rare-path now does N atomic ops where it previously did 1. OpenSSL caught this in PR #30670 review; assume your reviewers won't and measure.
