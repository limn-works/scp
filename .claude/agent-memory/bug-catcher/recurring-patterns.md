---
name: recurring-patterns
description: The bug shapes that recur across SCP reviews, ranked by how often they turn up, with the grep or check that finds each one
metadata:
  type: project
---

# Recurring bug shapes in SCP

Check these first on any review. `historical-findings-2026.md` lists the
instances each one came from.

1. **TOCTOU across an async lock boundary.** Read-check, drop the guard,
   write-act. Found 10+ times: standing_channel, NAPI transport_disconnect,
   Swift resolveKeyId, HotStreamFactory.contextEvents, QUIC accept_loop, UDP
   dispatch_datagram, QUIC handle_subscribe, WebSocket total-connection limit,
   `standing_context`, `import_context`. Fix: one write lock spanning check and
   mutation, or the `entry()` API.

2. **A bulk replacement that misses call sites.** Grep every call site of the old
   type or function when swapping one. Found: `hpke_sealed_key` missed in a
   serde-bounds conversion; `BridgeDidResolver` left in three tool paths after
   #311; `rmp_serde::to_vec` left in the migration chain after the named-format
   switch; enum renames applied to WASM but not the other three bridges.

3. **An FFI bridge that passes `None` or a default for a new parameter.** The
   signature grows, the callers get updated mechanically, and the bridge state
   that holds the real value is never consulted. Found: `signing_key` twice,
   NAPI `context_create`'s `..ContextParams::default()`.

4. **A guard, type, or defense that exists but is never called.** `check_tofu`,
   `check_certificate_pin`, `MessageType::as_discriminator_byte`,
   `rt.ceiling_strings` in the WASM UCAN validator, `min_events_since_last`.
   Verify the integration point, not just the library code.

5. **`let _ = result;` on a fallible cleanup or commit.** Produces split-brain
   between two stores. Found: `py_context_close`, `execute_paid_action`.

6. **A lock guard held across an await or a sleep.** Found: `per_client_recv_loop`
   (10 s DTLS recv), `deliver_to_subscribers` (50 ms jitter).

7. **A WASM re-implementation drifting from scp-core.** Different hash input,
   a missing check, required fields treated as optional. Always diff WASM against
   the core when adding validation.

8. **Authorization duplicated at the bridge layer.** Four bridges, three different
   answers, plus the authoritative layer's own. Delegate instead.

9. **A free function extracted for a wiring gate that loses its injected
   dependency.** `check_standing` and `enforce_role_demotion` fell back to
   `SystemClock`. Thread the dependency as a parameter.

10. **A test that passes already-resolved values, masking the transformation
    under test.** The `ucan_delegate` test passed full URIs and never exercised
    the short-name fallback that carried the bug. Test the transformation path,
    not only the happy path.

11. **A doc comment that states behavior the body does not implement**, or names
    a different error code than the body raises. Read both.
