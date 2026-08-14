---
name: typed-bindings-use-handles
description: Typed FFI bindings (UniFFI, NAPI) take typed context handles, not string ids — only PyO3 uses string ids because it has no typed handle. When mirroring a PyO3 reference, match the typed sibling's handle shape.
metadata:
  type: feedback
---

When exporting a context-scoped op across the FFI bridges, the typed bindings — UniFFI (`Arc<ContextHandle>`) and NAPI (`&NapiContextHandle`) — take typed handles, NOT raw context-id `String`s. Only the PyO3 bridge uses string ids, because PyO3 has no typed handle to pass.

**Why:** Cross-binding agent-first parity (CLAUDE.md "Agent-first API design": identical shape across bindings). An app author who wrote `tool_invoke_cross_context(sourceHandle, targetHandle, ...)` should not have to author a *different* call shape (string ids) for the saga variant. The existing UniFFI `tool_invoke_cross_context` already establishes the `Arc<ContextHandle>` idiom; the NAPI saga sibling shipped with `&NapiContextHandle`. The PyO3 string form is the weaker model — do not cargo-cult it into the typed bindings (see [[../../MEMORY... feedback_choose_superior_solution]]).

**How to apply:** When a plan/reference prescribes a PyO3 string-id signature and you're implementing the UniFFI or NAPI slice, take typed handles instead and derive the id strings internally (the impl resolves handles from `context_handle_registry` by id anyway, so it costs nothing). Add the per-instance affinity check the sibling uses: UniFFI `self.inner.core.check_handle(handle.instance_id())`; NAPI `napi_check_handle!`. Caught in review on FFI task #116 Slice C (api-design + the NAPI sibling shape were the deciding evidence). The plan's string-id prescription was a stale detail; artifact-flow + parity tenets override it.
