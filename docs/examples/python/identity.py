"""Identity creation and DID document inspection.

Demonstrates creating a new SCP identity using did:dht,
inspecting the resulting DID document, and resolving it.

Prerequisites:
    pip install scp-sdk
    # or: maturin develop --release (from bindings/python/)
    export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
    export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database

Usage:
    python identity.py
"""

import asyncio
import os
from pathlib import Path

from scp_sdk import SCP, CustodyType, StorageConfig


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
    async with SCP(storage=node_storage("identity-example")) as scp:
        # 1. Create a new identity whose keys live in the encrypted key file.
        #    CustodyType.FILE keeps them in $HOME/.scp/keys.bin, sealed under
        #    the passphrase in SCP_KEY_PASSPHRASE. An unset passphrase raises
        #    SCP-VALID-7001.
        identity = await scp.identity_create(CustodyType.FILE)

        print(f"DID: {identity.did}")
        print(f"Custody type: {identity.custody_type}")
        print()

        # 2. Resolve the DID to its document.
        #    This queries the DHT and returns a DIDDocument dataclass.
        doc = await scp.identity_resolve(identity.did)

        print("DID Document:")
        print(f"  ID: {doc.id}")
        print(f"  Verification methods: {len(doc.verification_methods)}")
        for vm in doc.verification_methods:
            print(f"    - {vm['id']} (type: {vm.get('type', 'unknown')})")
        print(f"  Services: {len(doc.services)}")
        print(f"  Also known as: {doc.also_known_as}")
        print()

        # 3. Create an identity with an agent signing key (ADR-039).
        #    Agent keys enable human+agent shared DID patterns.
        agent_identity = await scp.identity_create_with_agent_key(CustodyType.FILE)
        print(f"Agent identity DID: {agent_identity.did}")
        print(f"  Agent public key: {agent_identity.agent_public_key_multibase}")

    print()
    print("Identity operations complete.")


if __name__ == "__main__":
    asyncio.run(main())
