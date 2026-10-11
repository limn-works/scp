"""Outlet registration, verification, and UCAN minting within a context.

Demonstrates defining an outlet with JSON schemas and test vectors,
registering it in a context, verifying it against those vectors, and
minting the UCAN token a caller presents to invoke it.

Prerequisites:
    pip install scp-sdk
    # or: maturin develop --release (from bindings/python/)
    export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
    export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database

Usage:
    python tools.py
"""

import asyncio
import os
from pathlib import Path

from scp_sdk import (
    SCP,
    Capability,
    CustodyType,
    MemoryScope,
    OutletDefinition,
    OutletKind,
    StorageConfig,
    TestVector,
)


def node_storage(name: str) -> StorageConfig:
    """Return SQLCipher storage at ``$HOME/.scp/<name>``.

    ``SCP_STORAGE_PASSPHRASE`` derives the database key. An unset variable
    raises ``KeyError`` here, before any database opens.
    """
    path = Path.home() / ".scp" / name
    path.mkdir(parents=True, exist_ok=True)
    return {
        "type": "sqlite",
        "path": str(path),
        "passphrase": os.environ["SCP_STORAGE_PASSPHRASE"],
    }


async def main() -> None:
    async with SCP(storage=node_storage("tools-example")) as scp:
        # 1. Create an identity for the outlet operator.
        operator = await scp.identity_create(CustodyType.FILE)
        print(f"Operator DID: {operator.did}")

        # 2. Create a context whose ceiling allows registering and calling outlets.
        ctx = await scp.context_create(
            operator.did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.OUTLET_REGISTER.value,
                    Capability.OUTLET_CALL_ALL.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
            },
        )
        print(f"Context: {ctx.context_id}")

        # 3. Define a calculator outlet with JSON schemas and test vectors.
        calculator = OutletDefinition(
            name="calculator",
            description="A simple arithmetic calculator",
            kind=OutletKind.Query,
            input_schema={
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                    "op": {"type": "string", "enum": ["add", "sub", "mul"]},
                },
                "required": ["a", "b", "op"],
            },
            output_schema={
                "type": "object",
                "properties": {"result": {"type": "number"}},
                "required": ["result"],
            },
            operator=operator.did,
            test_vectors=[
                TestVector(
                    input={"a": 2, "b": 3, "op": "add"},
                    expected_output={"result": 5},
                    description="2 + 3 = 5",
                ),
                TestVector(
                    input={"a": 7, "b": 3, "op": "mul"},
                    expected_output={"result": 21},
                    description="7 * 3 = 21",
                ),
            ],
        )

        # 4. Register the outlet. The returned id names it in every later call.
        outlet_id = await scp.outlet_register(ctx.context_id, calculator)
        print(f"\nOutlet registered: {outlet_id}")

        # 5. Verify the outlet against its test vectors.
        verification = await scp.outlet_verify(ctx.context_id, outlet_id)
        print(f"  Verification passed: {verification.passed}")

        # 6. Mint a UCAN token that authorizes calling this one outlet.
        token = await scp.ucan_mint(
            ctx.context_id,
            operator.did,
            [f"outlet:call:{outlet_id}"],
        )
        print(f"\nUCAN minted: {token.token_id}")
        print(f"  Capabilities: {token.capabilities}")

    print("\nOutlet operations complete.")


if __name__ == "__main__":
    asyncio.run(main())
