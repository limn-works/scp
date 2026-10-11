"""Minimal SCP agent in Python.

Creates a DID identity and opens an encrypted context.

Usage:
    pip install -e ../../bindings/python
    export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
    export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database
    python main.py
"""

import asyncio
import os
from pathlib import Path

from scp_sdk import SCP, Capability, CustodyType, MemoryScope


async def main() -> None:
    storage_dir = Path.home() / ".scp" / "python-agent"
    storage_dir.mkdir(parents=True, exist_ok=True)
    async with SCP(
        storage={
            "type": "sqlite",
            "path": str(storage_dir),
            "passphrase": os.environ["SCP_STORAGE_PASSPHRASE"],
        }
    ) as scp:
        # 1. Create a DID identity whose keys live in the passphrase-sealed key file.
        identity = await scp.identity_create(CustodyType.FILE)
        print(f"Created identity: {identity.did}")

        # 2. Create an encrypted context with messaging capabilities.
        ctx = await scp.context_create(
            identity.did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                    Capability.ROLE_ASSIGN.value,
                    Capability.MEMBER_INVITE.value,
                    Capability.MEMBER_REMOVE.value,
                    Capability.GOVERNANCE_PROPOSE.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
            },
        )
        print(f"Created context: {ctx.context_id}")
        print(f"  State: {ctx.state}")

    print("\nAgent complete.")


if __name__ == "__main__":
    asyncio.run(main())
