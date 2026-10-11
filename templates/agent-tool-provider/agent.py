"""SCP agent that registers outlets in a context and serves them via MCP.

Demonstrates the outlet lifecycle:
  1. Create an identity and a context with outlet capabilities.
  2. Register outlet definitions (calculator, search) with JSON schemas.
  3. Attach Python handler functions to the registered outlets.
  4. Mint a UCAN token that authorizes invoking both Query outlets.
  5. Invoke the outlets programmatically within the context.
  6. Optionally serve the context's outlets to an MCP client over stdio.

Usage:
    pip install -e ../../bindings/python
    export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
    export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database
    python agent.py
    python agent.py --mcp              # also start an MCP stdio server
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import sys
from pathlib import Path
from typing import Any

from scp_sdk import (
    SCP,
    Capability,
    CustodyType,
    MemoryScope,
    OutletDefinition,
    OutletKind,
    TestVector,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("tool-agent")


# ---------------------------------------------------------------------------
# Outlet definitions
# ---------------------------------------------------------------------------


def calculator_outlet(operator_did: str) -> OutletDefinition:
    """Return the calculator outlet definition operated by ``operator_did``."""
    return OutletDefinition(
        name="calculator",
        description="Evaluate arithmetic expressions with two operands.",
        kind=OutletKind.Query,
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
        operator=operator_did,
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


def search_outlet(operator_did: str) -> OutletDefinition:
    """Return the search outlet definition operated by ``operator_did``."""
    return OutletDefinition(
        name="search",
        description="Search a knowledge base by keyword query.",
        kind=OutletKind.Query,
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
        operator=operator_did,
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


async def run_agent(*, enable_mcp: bool = False) -> None:
    """Run the outlet-provider agent.

    Args:
        enable_mcp: When ``True``, serve the context's outlets to an
            MCP client over stdio until the client disconnects.
    """
    storage_dir = Path.home() / ".scp" / "agent-tool-provider"
    storage_dir.mkdir(parents=True, exist_ok=True)
    async with SCP(
        storage={
            "type": "sqlite",
            "path": str(storage_dir),
            "passphrase": os.environ["SCP_STORAGE_PASSPHRASE"],
        }
    ) as scp:
        # 1. Create an identity whose keys live in the passphrase-sealed key file.
        identity = await scp.identity_create(CustodyType.FILE)
        logger.info("Created identity: %s", identity.did)

        # 2. Create a context with outlet and messaging capabilities.
        ctx = await scp.context_create(
            identity.did,
            {
                "ceiling": [
                    Capability.OUTLET_REGISTER.value,
                    Capability.OUTLET_QUERY_ALL.value,
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
            },
        )
        logger.info("Created context: %s (state=%s)", ctx.context_id, ctx.state)

        # 3. Register both outlets. Each call returns the outlet id that every
        #    later call names.
        calculator_id = await scp.outlet_register(
            ctx.context_id, calculator_outlet(identity.did)
        )
        search_id = await scp.outlet_register(
            ctx.context_id, search_outlet(identity.did)
        )
        logger.info(
            "Registered outlets: calculator=%s search=%s", calculator_id, search_id
        )

        # 4. Attach the handler functions that run when an outlet is invoked.
        await scp.mcp_register_outlet_handler(
            ctx.context_id, calculator_id, handle_calculator
        )
        await scp.mcp_register_outlet_handler(ctx.context_id, search_id, handle_search)
        logger.info("Outlet handlers attached")

        # 5. Mint a UCAN token that authorizes invoking these two Query outlets.
        token = await scp.ucan_mint(
            ctx.context_id,
            identity.did,
            [
                Capability.outlet_query(calculator_id),
                Capability.outlet_query(search_id),
            ],
        )
        logger.info("Minted UCAN token: %s", token.token_id)

        # 6. Invoke the outlets programmatically.
        logger.info("--- Calculator invocations ---")
        for a, b, op, label in (
            (7, 3, "mul", "7 * 3"),
            (100, 37, "sub", "100 - 37"),
            (2, 10, "pow", "2 ^ 10"),
        ):
            calc_result = await scp.outlet_invoke(
                ctx.context_id,
                calculator_id,
                {"a": a, "b": b, "op": op},
                identity.did,
                token.encoded,
            )
            logger.info("  %s = %s", label, calc_result.get("result"))

        logger.info("--- Search invocations ---")
        for search_input in (
            {"query": "encryption MLS"},
            {"query": "UCAN capability authorization", "max_results": 3},
        ):
            search_result = await scp.outlet_invoke(
                ctx.context_id,
                search_id,
                search_input,
                identity.did,
                token.encoded,
            )
            logger.info(
                "  %r: %d results", search_input["query"], search_result.get("total", 0)
            )
            for hit in search_result.get("results", []):
                logger.info("    %.2f  %s", hit["score"], hit["title"])

        # 7. Optionally serve the context's outlets to an MCP client over stdio.
        if enable_mcp:
            logger.info("--- Starting MCP server (transport=stdio) ---")
            server = await scp.mcp_serve(
                identity.did, [ctx.context_id], "stdio", token.encoded
            )
            try:
                # Returns when the MCP client closes stdin.
                await scp.mcp_server_wait(server)
            finally:
                await scp.mcp_server_stop(server)
        else:
            logger.info(
                "Outlet invocations complete. Pass --mcp to start an MCP server."
            )

    logger.info("Agent complete.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def cli() -> None:
    """Parse arguments and run the agent."""
    asyncio.run(run_agent(enable_mcp="--mcp" in sys.argv))


if __name__ == "__main__":
    cli()
