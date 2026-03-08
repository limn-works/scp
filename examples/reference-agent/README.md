# SCP Reference Agent -- MCP Translation Layer

A reference implementation of a minimum viable SCP agent that translates
between SCP tool calls and MCP (Model Context Protocol).

## Overview

This agent demonstrates the "hello world" of SCP agent development:

- **MCP server** exposing SCP context operations as tools
- **Capability filtering** based on the agent's role in each context
- **JSON Schema** definitions for all tool inputs/outputs
- **stdio transport** for MCP communication

The agent is a transparent pipe: the SDK handles all protocol mechanics.

## Architecture

```
Model <-> MCP (JSON-RPC 2.0 over stdio) <-> Reference Agent <-> SCP SDK
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `identity_create` | Create a new SCP identity (DID) |
| `context_create` | Create a context with a specified template |
| `context_join` | Join an existing context by ID |
| `context_send` | Send a message to a context |
| `context_receive` | Retrieve messages from a context |
| `context_leave` | Leave a context |

Tools are filtered by the agent's current role -- tools requiring
capabilities the agent lacks are not exposed to the model (spec
section 8.5 capability filtering).

## Prerequisites

- Python 3.12+
- `pip install scp-sdk` (optional -- the agent includes mock fallbacks
  for environments without the full SDK installed)
- `pip install pytest ruff` (for testing and linting)

## Setup

```bash
cd examples/reference-agent/
pip install pytest ruff
```

## Running

### Demo (self-contained, no external infrastructure)

```bash
python3 demo.py
```

Expected output:
```
Step 0: Initializing MCP connection...
  Server: scp-reference-agent v0.1.0
Step 1: Creating identity...
  DID: did:key:z6Mk...
Step 2: Creating context...
  Context ID: ctx-...
Step 3: Sending message...
  Sent: Hello from the SCP reference agent!
Step 4: Receiving messages...
  Received 1 message(s)
  Last message: [did:key:z6Mk...] Hello from the SCP reference agent!
Step 5: Verifying tool listing...
  Available tools: [...]
============================================================
Demo completed successfully!
============================================================
```

### As an MCP server (stdio transport)

```bash
python3 agent.py
```

The agent reads JSON-RPC 2.0 requests from stdin and writes responses
to stdout. Logs go to stderr.

## Testing

```bash
python3 -m pytest test_agent.py -v
```

### Linting

```bash
python3 -m ruff check .
python3 -m ruff format --check .
```

## References

- **Spec section 4.5** -- Agent role definition
- **Spec section 8.5** -- MCP compatibility (SCP tool definitions are
  a superset of MCP tool definitions)
- **ADR-015** -- MCP adapter (`scp-mcp` crate + Python `scp_sdk.mcp` module)
