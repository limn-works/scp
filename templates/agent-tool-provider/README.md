# SCP Agent Tool Provider

A Python agent that registers outlets in an SCP context, handles invocations with UCAN authorization, and optionally serves the outlets to external models via MCP (Model Context Protocol).

## Prerequisites

- Python 3.12+
- For the source install: a Rust toolchain, a C compiler, and, on Linux and Windows, a full perl (plus make on Linux) for the OpenSSL the build compiles; `bindings/python/README.md` §Requirements has the details
- SCP Python SDK (`pip install scp-python`, or from source: `pip install -e ../../bindings/python`)

## Build and Run

```bash
cd templates/agent-tool-provider
pip install -e ../../bindings/python  # install SDK from source
export SCP_KEY_PASSPHRASE=...         # seals $HOME/.scp/keys.bin
export SCP_STORAGE_PASSPHRASE=...     # encrypts the SQLCipher database
python agent.py                       # run with outlet invocations only
python agent.py --mcp                 # also start an MCP server (stdio)
```

## What This Does

### Outlet Lifecycle

Every call is a method on one `SCP` instance, which the `async with` block shuts down on exit.

1. **Identity creation** -- `identity_create(CustodyType.FILE)` creates a `did:dht` identity whose keys live in `$HOME/.scp/keys.bin`, sealed under `SCP_KEY_PASSPHRASE`. `CustodyType.IN_MEMORY` works only in a build compiled with the `testing` feature; a shipped build rejects it with `SCP-IDENT-1008`.
2. **Context creation** -- `context_create` opens an encrypted context with `outlet:register` and `outlet:query:*` in the ceiling.
3. **Outlet registration** -- `outlet_register` registers two outlets (`calculator`, `search`) with JSON Schema input and output definitions and test vectors, and returns each outlet's id.
4. **Handler attachment** -- `mcp_register_outlet_handler(context_id, outlet_id, handler)` attaches a Python callable to each outlet. When the outlet is invoked, the handler receives the validated JSON input as a dict and returns a dict.
5. **UCAN minting** -- `ucan_mint` mints a UCAN token carrying `outlet:query:<outlet id>` for both outlets, which are Query outlets. Every outlet invocation requires a valid UCAN.
6. **Invocation** -- `outlet_invoke(context_id, outlet_id, input, identity_did, ucan_token)` validates the UCAN, checks the input against the outlet's JSON Schema, runs the handler, and returns the result.
7. **MCP serving** (optional) -- `mcp_serve(identity_did, [context_id], "stdio", ucan_token)` exposes the context's outlets to an MCP client over stdin and stdout, and `mcp_server_wait` returns when the client closes stdin.

### Included Outlets

| Outlet | Description | Input | Output |
|------|-------------|-------|--------|
| `calculator` | Arithmetic on two operands | `{a, b, op}` where op is add/sub/mul/div/pow | `{result}` |
| `search` | Keyword search over a knowledge base | `{query, max_results?}` | `{results[], total}` |

## How Outlets Work

### Registration

An outlet is an `OutletDefinition` with JSON Schema for input and output validation:

```python
from scp_sdk import OutletDefinition, OutletKind, TestVector

definition = OutletDefinition(
    name="my_tool",
    description="What it does",
    kind=OutletKind.Query,
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
outlet_id = await scp.outlet_register(ctx.context_id, definition)
```

### Handler Attachment

After registering the outlet, attach a Python callable that processes invocations:

```python
def my_handler(input_data: dict) -> dict:
    return {"result": input_data["param"].upper()}


await scp.mcp_register_outlet_handler(ctx.context_id, outlet_id, my_handler)
```

The handler receives the validated input dict and must return a dict matching the output schema.

### Invocation

Outlets are invoked through the instance with UCAN authorization:

```python
token = await scp.ucan_mint(ctx.context_id, identity.did, [Capability.outlet_query(outlet_id)])

result = await scp.outlet_invoke(
    ctx.context_id, outlet_id, {"param": "hello"}, identity.did, token.encoded
)
# result == {"result": "HELLO"}
```

### Stateful Sessions

For multi-turn outlet workflows, use stateful sessions:

```python
session_id = await scp.outlet_session_create(
    ctx.context_id,
    outlet_id,
    ctx.context_id,  # source context
    ttl_seconds=300,  # 5-minute session
)

result = await scp.outlet_session_invoke(
    ctx.context_id, session_id, {"param": "hello"}, identity.did, token.encoded
)

await scp.outlet_session_close(ctx.context_id, session_id)
```

## How the MCP Server Works

The MCP server exposes SCP context outlets to external models that speak the Model Context Protocol.

### Starting the Server

```python
server = await scp.mcp_serve(identity.did, [ctx.context_id], "stdio", token.encoded)
try:
    await scp.mcp_server_wait(server)  # returns when the client closes stdin
finally:
    await scp.mcp_server_stop(server)
```

The stdio transport reads line-delimited JSON on stdin and writes it on stdout, for an MCP host (for example Claude Desktop) that spawns the agent as a subprocess. The agent logs to stderr, so its log lines stay out of the protocol stream.

### Capability Filtering

The MCP server only exposes outlets that the agent's role permits.

### Provenance

Every outlet result served through MCP carries SCP provenance metadata recording the outlet source, invoking agent DID, context ID, and timestamp. External models receive verifiable provenance with their tool results.

### Consuming External MCP Servers

The SDK also consumes tools from external MCP servers and wraps each result with provenance:

```python
client = await scp.mcp_client_connect_stdio(["uvx", "some-mcp-server"])
try:
    tools = await scp.mcp_client_list_tools(client)
    result = await scp.mcp_client_invoke(
        client, "external_tool", {"key": "value"}, ctx.context_id, identity.did
    )
    # result.provenance records the external source
finally:
    await scp.mcp_client_disconnect(client)
```

A command outside the instance's stdio allowlist is rejected; `mcp_configure_stdio_allowlist` permits more binaries.

## Adding Custom Outlets

1. Define an `OutletDefinition` with JSON Schema for input and output.
2. Register it with `outlet_register` and keep the returned outlet id.
3. Write a handler function `(dict) -> dict` and attach it with `mcp_register_outlet_handler(context_id, outlet_id, handler)`.
4. Mint a UCAN token with `Capability.outlet_query(outlet_id)` for a Query outlet, or `Capability.outlet_call(outlet_id)` for an Action outlet.
5. Invoke it with `outlet_invoke` or expose it via MCP with `mcp_serve`.

Test vectors are optional but recommended -- they document expected behavior, and `outlet_verify` checks the outlet against them.

## Next Steps

- Use `outlet_session_create` and `outlet_session_invoke` for multi-turn outlet workflows
- Invite a second identity with `reserve_key_package`, `invite_member` and `context_join_from_welcome`, then mint it a scoped UCAN with `ucan_mint`
- Consume external MCP servers with `mcp_client_connect_stdio` and wrap results with provenance
