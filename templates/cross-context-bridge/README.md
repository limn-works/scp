# Cross-Context Tool Bridge

A Rust template demonstrating cross-context tool interfaces (spec section 6.2). Two isolated SCP contexts exchange structured data through a governed bridge: Context A exposes a tool, Context B consumes it, and every interaction is mediated by both contexts' governance, rate-limited, and recorded in both event logs.

## How cross-context communication works

SCP contexts are fully isolated by default. Agents in Context A cannot read, write, or interact with Context B. The protocol provides two mechanisms for crossing boundaries:

1. **Cross-context tool interfaces** (this template) -- asymmetric, request/response. One context queries another's tool. Both contexts govern every call.
2. **Multi-parent child contexts** -- symmetric, full context. A shared space governed by multiple parent contexts.

Tool interfaces are the right choice for service-style interactions: translation, lookup, computation, or any structured API call across context boundaries.

## How the bridge operates

The bridge follows the bidirectional consent protocol (section 6.2.0.1):

1. **Register a tool** in Context A using `register_tool`. The tool has a declared JSON schema for input and output.
2. **Expose the tool** from Context A to Context B using `expose_tool`. This creates a `ToolInterface` with an `OutboundPolicy` (who can call, rate limits, payload size limits). The source side is now approved.
3. **Create an `InterfaceOffer`** via `create_interface_offer`. This captures the full tool schema and has a 7-day expiry. In production, a shared member carries the offer to Context B.
4. **Accept the interface** in Context B using `accept_tool_interface`. This sets the `InboundPolicy` (allowed source roles, response size limits, spending UCAN requirements). Both sides are now approved.
5. **Invoke across contexts** using `invoke_cross_context`. The bridge enforces:
   - Chain depth limit (default 8, context-configurable per ADR-043) to prevent amplification
   - Bidirectional approval check
   - Per-interface rate limit (default 60 calls/min)
   - Per-caller rate limit (default 10 calls/min)
   - Outbound policy: allowed callers list, payload size limit
   - Source context governance: invoker must hold `ToolInvokeAll` or `ToolInvoke(tool_id)` capability
   - Target context governance: tool must exist in target registry
   - Inbound policy: response size limit
6. **Event logging** -- both contexts receive a `CrossContextToolEvent` with a shared `request_id`, providing full provenance of every cross-context call.

The bridge can be torn down unilaterally by either context using `revoke_tool_interface`.

## Running

```sh
cargo run
```

## Customizing

### Change the tool

Replace the `ToolRegistration` in step 3 with your own tool schema and the executor closure in step 8 with your implementation. The schema must have at least two distinct fields in input or output (schema specificity floor, section 9.2.1).

### Restrict callers

Set `OutboundPolicy.allowed_callers` to a list of DIDs that may invoke the interface. When empty, any member with the `ToolInterface` capability can call.

### Adjust rate limits

Both `OutboundPolicy.max_calls_per_minute` and `InboundPolicy.max_calls_per_minute` are enforced. The effective rate is `min(outbound, inbound)`. Per-caller limits default to 10 calls/min.

### Chain depth

Set `ContextParams.max_chain_depth` on the source context to control how many hops a cross-context call can traverse. There is no protocol hard maximum; the default is 8 (ADR-043).

### Stateful sessions

For multi-turn workflows (negotiation, coordination), use `create_session` and `invoke_session` from `scp_core::context::tools::session` to maintain state across sequential invocations within the governed tool call framework.
