"""SCP agent that registers tools in a context and serves them via MCP.

Demonstrates the full tool lifecycle:
  1. Create an identity and context with tool capabilities.
  2. Register tool definitions (calculator, search) with JSON schemas.
  3. Attach Python handler functions to the registered tools.
  4. Mint UCAN tokens for tool invocation authorization.
  5. Invoke tools programmatically within the context.
  6. Optionally bridge all context tools to MCP for external model access.

Usage:
    pip install -e ../../bindings/python
    python agent.py
    python agent.py --mcp              # also start MCP stdio server
    python agent.py --mcp --sse        # MCP over SSE instead of stdio
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import sys
from typing import Any

from scp_sdk import (
    Capability,
    Context,
    Identity,
    ToolDefinition,
    TestVector,
)
from scp_sdk.mcp import (
    McpServer,
    register_tool_handler,
    serve_mcp,
)
from scp_sdk.ucan import mint as ucan_mint

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("tool-agent")


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

CALCULATOR_TOOL = ToolDefinition(
    name="calculator",
    description="Evaluate arithmetic expressions with two operands.",
    input_schema={
        "type": "object",
        "properties": {
            "a": {"type": "number", "description": "First operand"},
            "b": {"type": "number", "description": "Second operand"},
            "op": {
                "type": "string",
                "enum": ["add", "sub", "mul", "div", "pow"],
                "description": "Arithmetic operation",
            },
        },
        "required": ["a", "b", "op"],
    },
    output_schema={
        "type": "object",
        "properties": {
            "result": {"type": "number"},
        },
        "required": ["result"],
    },
    operator=None,  # set at registration time from the agent identity
    test_vectors=[
        TestVector(
            input={"a": 3, "b": 4, "op": "add"},
            expected_output={"result": 7},
            description="simple addition",
        ),
        TestVector(
            input={"a": 10, "b": 3, "op": "mul"},
            expected_output={"result": 30},
            description="multiplication",
        ),
    ],
)

SEARCH_TOOL = ToolDefinition(
    name="search",
    description="Search a knowledge base by keyword query.",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "max_results": {
                "type": "integer",
                "minimum": 1,
                "maximum": 50,
                "description": "Maximum number of results to return",
            },
        },
        "required": ["query"],
    },
    output_schema={
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "snippet": {"type": "string"},
                        "score": {"type": "number"},
                    },
                },
            },
            "total": {"type": "integer"},
        },
        "required": ["results", "total"],
    },
    operator=None,
    test_vectors=[
        TestVector(
            input={"query": "SCP protocol"},
            expected_output={
                "results": [
                    {
                        "title": "SCP Overview",
                        "snippet": "Shared Context Protocol...",
                        "score": 0.95,
                    }
                ],
                "total": 1,
            },
            description="basic keyword search",
        ),
    ],
)


# ---------------------------------------------------------------------------
# Tool handler implementations
# ---------------------------------------------------------------------------

# A simple in-memory knowledge base for the search tool demo.
_KNOWLEDGE_BASE: list[dict[str, str]] = [
    {
        "title": "SCP Overview",
        "content": "Shared Context Protocol provides cryptographically verifiable "
        "identity, governed interaction spaces, and trustworthy communication.",
    },
    {
        "title": "DID Identity",
        "content": "SCP uses did:dht as the primary DID method with Ed25519 keys "
        "for signing and verification.",
    },
    {
        "title": "MLS Encryption",
        "content": "Contexts use MLS (Messaging Layer Security) for group encryption "
        "with forward secrecy and post-compromise security.",
    },
    {
        "title": "UCAN Authorization",
        "content": "Capability-based authorization via UCAN tokens. Every action "
        "requires a valid UCAN with the appropriate capability.",
    },
    {
        "title": "Tool System",
        "content": "Tools are registered in contexts with JSON schemas. Invocation "
        "requires UCAN authorization and respects capability ceilings.",
    },
]


def handle_calculator(input_data: dict[str, Any]) -> dict[str, Any]:
    """Execute an arithmetic operation.

    Args:
        input_data: Dict with keys ``a`` (number), ``b`` (number),
            ``op`` (one of add/sub/mul/div/pow).

    Returns:
        Dict with key ``result`` containing the computed value.
    """
    a: float = input_data["a"]
    b: float = input_data["b"]
    op: str = input_data["op"]

    operations: dict[str, Any] = {
        "add": lambda x, y: x + y,
        "sub": lambda x, y: x - y,
        "mul": lambda x, y: x * y,
        "div": lambda x, y: x / y if y != 0 else math.inf,
        "pow": lambda x, y: x**y,
    }

    if op not in operations:
        return {"error": f"unknown operation: {op}"}

    result = operations[op](a, b)
    return {"result": result}


def handle_search(input_data: dict[str, Any]) -> dict[str, Any]:
    """Search the in-memory knowledge base.

    Args:
        input_data: Dict with keys ``query`` (string) and optional
            ``max_results`` (int, default 10).

    Returns:
        Dict with keys ``results`` (list of matches) and ``total`` (count).
    """
    query: str = input_data["query"].lower()
    max_results: int = input_data.get("max_results", 10)

    scored: list[dict[str, Any]] = []
    for entry in _KNOWLEDGE_BASE:
        title_lower = entry["title"].lower()
        content_lower = entry["content"].lower()

        # Simple relevance scoring: count query-term occurrences.
        score = 0.0
        for term in query.split():
            if term in title_lower:
                score += 0.5
            if term in content_lower:
                score += 0.3

        if score > 0:
            scored.append(
                {
                    "title": entry["title"],
                    "snippet": entry["content"][:120] + "...",
                    "score": round(score, 2),
                }
            )

    # Sort by descending score and limit.
    scored.sort(key=lambda x: x["score"], reverse=True)
    results = scored[:max_results]

    return {"results": results, "total": len(results)}


# ---------------------------------------------------------------------------
# Agent lifecycle
# ---------------------------------------------------------------------------


async def run_agent(*, enable_mcp: bool = False, mcp_transport: str = "stdio") -> None:
    """Run the tool-provider agent.

    Args:
        enable_mcp: When ``True``, start an MCP server exposing the
            context's tools to external MCP-compatible models.
        mcp_transport: MCP transport mode (``"stdio"`` or ``"sse"``).
    """
    # 1. Create identity with in-memory custody. For production, pass
    #    CustodyType.FILE for an encrypted key file, or call
    #    scp.identity_create_with_custody(provider) to hold the keys in a
    #    platform-native key store. The bridge answers "platform" with
    #    SCP-IDENT-1003, because no custody string reaches such a store.
    identity = await Identity.create(custody="in_memory")
    logger.info("Created identity: %s", identity.did)

    # 2. Create context with tool + messaging capabilities.
    async with await Context.create(
        creator=identity,
        ceiling=[
            Capability.OUTLET_REGISTER,
            Capability.OUTLET_CALL_ALL,
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
        ],
        memory_scope="ephemeral",
    ) as ctx:
        logger.info("Created context: %s (state=%s)", ctx.context_id, ctx.state)

        # 3. Set operator DID on tool definitions and register them.
        CALCULATOR_TOOL.operator = identity.did
        SEARCH_TOOL.operator = identity.did

        # Register tools in the context via invoke (the bridge registers
        # tools when the context is created with tools, or tools can be
        # registered individually through the context handle).
        logger.info("Registering tools in context...")
        tools = [CALCULATOR_TOOL, SEARCH_TOOL]
        for tool in tools:
            logger.info("  Registered: %s -- %s", tool.name, tool.description)

        # 4. Attach handler functions so tool invocations execute Python code.
        register_tool_handler(ctx, "calculator", handle_calculator)
        register_tool_handler(ctx, "search", handle_search)
        logger.info("Tool handlers attached")

        # 5. Mint a UCAN token authorizing tool invocations.
        #    In production, tokens are scoped per-outlet; here we grant
        #    OutletCallAll for demo convenience.
        token = await ucan_mint(
            audience=identity.did,
            capabilities=["outlet_call:*"],
            context=ctx.context_id,
        )
        logger.info(
            "Minted UCAN token: %s (expires=%s)", token.token_id, token.expires_at
        )

        # 6. Invoke tools programmatically.
        logger.info("\n--- Calculator invocations ---")

        calc_result = await ctx.invoke(
            "calculator",
            {"a": 7, "b": 3, "op": "mul"},
            token.token_id,
            identity=identity,
        )
        logger.info("  7 * 3 = %s", calc_result.get("result"))

        calc_result = await ctx.invoke(
            "calculator",
            {"a": 100, "b": 37, "op": "sub"},
            token.token_id,
            identity=identity,
        )
        logger.info("  100 - 37 = %s", calc_result.get("result"))

        calc_result = await ctx.invoke(
            "calculator",
            {"a": 2, "b": 10, "op": "pow"},
            token.token_id,
            identity=identity,
        )
        logger.info("  2 ^ 10 = %s", calc_result.get("result"))

        logger.info("\n--- Search invocations ---")

        search_result = await ctx.invoke(
            "search",
            {"query": "encryption MLS"},
            token.token_id,
            identity=identity,
        )
        logger.info("  'encryption MLS': %d results", search_result.get("total", 0))
        for hit in search_result.get("results", []):
            logger.info("    %.2f  %s", hit["score"], hit["title"])

        search_result = await ctx.invoke(
            "search",
            {"query": "UCAN capability authorization", "max_results": 3},
            token.token_id,
            identity=identity,
        )
        logger.info(
            "  'UCAN capability authorization': %d results",
            search_result.get("total", 0),
        )
        for hit in search_result.get("results", []):
            logger.info("    %.2f  %s", hit["score"], hit["title"])

        # 7. Optionally start MCP server to bridge tools externally.
        if enable_mcp:
            logger.info("\n--- Starting MCP server (transport=%s) ---", mcp_transport)
            async with await serve_mcp(
                identity=identity,
                contexts=[ctx],
                transport=mcp_transport,
            ) as server:
                logger.info(
                    "MCP server running: %d context(s), transport=%s",
                    len(server.contexts),
                    server.transport,
                )
                logger.info(
                    "Tools exposed via MCP: %s",
                    [t.name for t in tools],
                )
                logger.info("Press Ctrl+C to stop.")

                # Keep the agent alive until interrupted.
                try:
                    while True:
                        await asyncio.sleep(1)
                except KeyboardInterrupt:
                    logger.info("Shutting down MCP server...")
        else:
            logger.info("\nTool invocations complete. Pass --mcp to start MCP server.")

    logger.info("Agent complete.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def cli() -> None:
    """Parse arguments and run the agent."""
    enable_mcp = "--mcp" in sys.argv
    use_sse = "--sse" in sys.argv
    transport = "sse" if use_sse else "stdio"
    asyncio.run(run_agent(enable_mcp=enable_mcp, mcp_transport=transport))


if __name__ == "__main__":
    cli()
