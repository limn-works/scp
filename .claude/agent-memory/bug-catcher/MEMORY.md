# Bug Catcher Memory

## Recurring bug patterns in this codebase (most frequent first)
1. **Check-then-act across a lock release or an `.await`.** A read lock for the check, then a separate write lock for the mutation, lets concurrent callers pass the limit or race the insert (subscription limits, connection limits, standing-channel creation, a `ConcurrentHashMap` get-then-put across a suspension point). Fix: one write lock around check and mutate, or the `entry()` API.
2. **A lock guard held across an `.await` or a blocking call.** A read guard held through a 10-second DTLS receive or a jitter sleep starves writers and cleanup tasks.
3. **A bulk conversion or rename that misses call sites.** Converting fields to bounded types, replacing a resolver type, or renaming an enum variant usually leaves one field, one bridge, or one secondary path (a migration chain, a test helper) on the old form. Grep every call site of the old name before calling a conversion complete.
4. **A new parameter passed as `None` or a default at every FFI caller.** When a core signature gains a parameter, bridges pass `None` mechanically instead of resolving the value from bridge state; `..Default::default()` struct-update syntax silently drops fields the caller set.
5. **Types and logic shipped without the call site.** A complete verifier, pin check, or TOFU store that no resolution or connection path calls; a constructor documented as "call X afterward" whose integration site never calls X.
6. **`let _ = result;` on a fallible cleanup or payment step.** Discarding a close or budget-record error leaves the two layers disagreeing about state.
7. **A free function extracted from a stateful type that reaches for a global.** An extracted helper that calls `SystemClock` instead of the injected clock loses the dependency injection its caller had; thread the dependency through as a parameter.
8. **A test that feeds already-resolved values.** Passing full URIs where the bridge would expand short names skips the transformation path where the bug lives. A regression test that calls a helper directly does not cover the call sites whose gating was wrong.
9. **Filtering items inside `Stream::poll_next`.** Skipping a duplicate and returning `Pending` without arranging a re-poll hangs the task.
10. **A defense defined but not wired.** A discriminator documented "for inclusion in canonical hashes" that the hash never includes; a config field whose doc states one unit while the constructor reads another.
11. **Allocation before the bounds check.** `serde_bytes` pre-allocates from the MessagePack length hint before any size check runs, so an untrusted length can exhaust memory first.
12. **Kotlin `?.jsonObject` on a value that may be a primitive.** kotlinx.serialization throws on a non-object; `?.` only guards null. Use an `is JsonObject` check.
