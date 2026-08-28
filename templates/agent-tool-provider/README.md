# SCP Agent Tool Provider

A Python agent that registers tools in an SCP context, handles invocations with UCAN authorization, and optionally bridges tools to external models via MCP (Model Context Protocol).

## Prerequisites

- Python 3.12+
- SCP Python SDK (`pip install scp-python`, or from source: `pip install -e ../../bindings/python`)

## Build and Run

```bash
cd templates/agent-tool-provider
pip install -e ../../bindings/python  # install SDK from source
python agent.py                       # run with tool invocations only
python agent.py --mcp                 # also start MCP server (stdio)
python agent.py --mcp --sse           # MCP server over SSE
```

## What This Does

### Tool Lifecycle

The agent demonstrates the complete tool lifecycle within SCP:

1. **Identity creation** -- creates a `did:dht` identity with in-memory key custody.
2. **Context creation** -- opens an encrypted context with `OutletRegister` and `OutletCallAll` capabilities in the ceiling.
3. **Tool registration** -- registers two tools (`calculator`, `search`) with JSON Schema input/output definitions and test vectors.
4. **Handler attachment** -- attaches Python callables to each tool via `register_tool_handler()`. When a tool is invoked, the handler receives validated JSON input and returns JSON output.
5. **UCAN minting** -- mints a UCAN token with `outlet_call:*` capability scoped to the context. Every outlet invocation requires a valid UCAN.
6. **Invocation** -- calls `ctx.invoke(tool_name, input, ucan_token)` which validates the UCAN, checks the input against the tool's JSON Schema, executes the handler, and returns the result.
7. **MCP bridging** (optional) -- starts an MCP server that exposes all context tools to MCP-compatible models (Claude, GPT, etc.) over stdio or SSE transport.

### Included Tools

| Tool | Description | Input | Output |
|------|-------------|-------|--------|
| `calculator` | Arithmetic on two operands | `{a, b, op}` where op is add/sub/mul/div/pow | `{result}` |
| `search` | Keyword search over a knowledge base | `{query, max_results?}` | `{results[], total}` |

## How Tools Work

### Registration

Tools are defined as `ToolDefinition` dataclasses with JSON Schema for input and output validation:

```python
from scp_sdk import ToolDefinition, TestVector

tool = ToolDefinition(
    name="my_tool",
    description="What it does",
    input_schema={
        "type": "object",
        "properties": {
            "param": {"type": "string"},
        },
        "required": ["param"],
    },
    output_schema={
        "type": "object",
        "properties": {
            "result": {"type": "string"},
        },
        "required": ["result"],
    },
    operator=identity.did,
    test_vectors=[
        TestVector(
            input={"param": "hello"},
            expected_output={"result": "HELLO"},
            description="uppercase conversion",
        ),
    ],
)
```

### Handler Attachment

After registering a tool definition, attach a Python callable that processes invocations:

```python
from scp_sdk.mcp import register_tool_handler

def my_handler(input_data: dict) -> dict:
    return {"result": input_data["param"].upper()}

register_tool_handler(ctx, "my_tool", my_handler)
```

The handler receives the validated input dict and must return a dict matching the output schema.

### Invocation

Tools are invoked through the context with UCAN authorization:

```python
from scp_sdk.ucan import mint as ucan_mint

# Mint a token authorizing tool invocation.
token = await ucan_mint(
    audience=identity.did,
    capabilities=["outlet_call:my_tool"],  # or "outlet_call:*" for all
    context=ctx.context_id,
)

# Invoke the tool.
result = await ctx.invoke("my_tool", {"param": "hello"}, token.token_id)
# result == {"result": "HELLO"}
```

### Cross-Context Invocation

Tools can be invoked across context boundaries when both contexts approve the interface:

```python
from scp_sdk.tools import invoke_cross_context

result = await invoke_cross_context(
    source_context_id="ctx-caller",
    target_context_id="ctx-provider",
    tool_id="my_tool",
    input={"param": "hello"},
    invoker_did=identity.did,
    ucan_token=token.token_id,
)
```

### Stateful Sessions

For multi-turn tool workflows, use stateful sessions:

```python
from scp_sdk.tools import session_create, session_invoke, session_close

session_id = await session_create(
    context_id=ctx.context_id,
    tool_id="my_tool",
    source_context_id=ctx.context_id,
    ttl_seconds=300,  # 5-minute session
)

result = await session_invoke(
    context_id=ctx.context_id,
    session_id=session_id,
    input={"param": "hello"},
    invoker_did=identity.did,
    ucan_token=token.token_id,
)

await session_close(ctx.context_id, session_id)
```

## How MCP Bridge Works

The MCP bridge exposes SCP context tools to external models that speak the Model Context Protocol.

### Starting the Server

```python
from scp_sdk.mcp import serve_mcp

async with await serve_mcp(
    identity=identity,
    contexts=[ctx],
    transport="stdio",   # or "sse"
) as server:
    # Server is running; tools are exposed as MCP tools
    # namespaced by context ID (e.g., "ctx-abc/calculator")
    ...
```

### Transport Modes

- **stdio** -- line-delimited JSON over stdin/stdout. Used when an MCP host (e.g., Claude Desktop) spawns the agent as a subprocess.
- **sse** -- HTTP with Server-Sent Events. Used for network-accessible MCP servers.

### Capability Filtering

The MCP server only exposes tools that the agent's role permits. If the agent lacks `OutletCallAll`, only tools matching specific `OutletCall(outlet_id)` capabilities are listed.

### Provenance

Every tool result served through MCP carries SCP provenance metadata recording the tool source, invoking agent DID, context ID, and timestamp. External models receive verifiable provenance with their tool results.

### Consuming External MCP Servers

The SDK also supports consuming tools from external MCP servers with provenance wrapping:

```python
from scp_sdk.mcp import McpClient

async with await McpClient.connect(
    "stdio",
    command=["uvx", "some-mcp-server"],
) as client:
    tools = await client.list_tools()
    result = await client.invoke(
        tool="external_tool",
        input={"key": "value"},
        context=ctx,
        identity=identity,
    )
    # result.provenance records the external source
```

## Adding Custom Tools

1. Define a `ToolDefinition` with JSON Schema for input and output.
2. Write a handler function `(dict) -> dict`.
3. Register the handler with `register_tool_handler(ctx, tool_name, handler)`.
4. Mint a UCAN token with `outlet_call:<tool_name>` capability.
5. Invoke via `ctx.invoke()` or expose via MCP with `serve_mcp()`.

Test vectors are optional but recommended -- they document expected behavior and can be used for verification during registration.

## Next Steps

- Replace `"in_memory"` custody with `"file"` and export `SCP_KEY_PASSPHRASE` — the PyO3 bridge encrypts `$HOME/.scp/keys.bin` under that passphrase. For an OS keystore, pass a `KeyCustodyProvider` to `scp.identity_create_with_custody()` instead; the bridge rejects the custody string `"platform"` with `SCP-IDENT-1003`. Neither call creates an identity on a released wheel: both return `SCP-IDENT-1059`, because no pre-rotation custody backend is wired yet
- Connect to a relay with `connect_relay()` for networked transport
- Use `session_create()`/`session_invoke()` for multi-turn tool workflows
- Add a second participant and use `delegate()` to issue scoped UCAN tokens
- Consume external MCP servers with `McpClient` and wrap results with provenance
