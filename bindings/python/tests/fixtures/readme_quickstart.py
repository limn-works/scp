"""The quick start from ``bindings/python/README.md``, verbatim.

``test_readme_quickstart.py`` runs this file as its own process with
``SCP_KEY_PASSPHRASE`` and a scratch ``HOME`` set, which is what a reader does
from a shell. A change to either copy that the other does not mirror fails
review, so the README stops drifting from what runs.
"""

import asyncio

from scp_sdk import SCP, Capability, CustodyType, MemoryScope


async def main():
    # Every call routes through an SCP instance (ADR-048). Name a storage
    # backend: this constructor has no default.
    scp = SCP(storage={"type": "in_memory"})

    # Create a cryptographic identity (DID). Name a custody backend too —
    # `identity_create` has no default either (spec §17.17.1,
    # SCP-CAPSEL-8000). `CustodyType.FILE` encrypts $HOME/.scp/keys.bin under
    # SCP_KEY_PASSPHRASE (Argon2id + AES-256-GCM, spec §17.8).
    identity = await scp.identity_create(CustodyType.FILE)
    print(f"DID: {identity.did}")

    # Create an encrypted context. The ceiling bounds every capability any
    # member of this context can ever hold, so it must carry `context:close`
    # for the `context_close` call below to pass its capability check.
    ctx = await scp.context_create(
        identity.did,
        {
            "ceiling": [
                Capability.MESSAGES_READ.value,
                Capability.MESSAGES_WRITE.value,
                Capability.CONTEXT_CLOSE.value,
            ],
            "memory_scope": MemoryScope.EPHEMERAL.value,
            "ttl": 3600,
        },
    )

    # Send a message (MLS-encrypted, signed, provenance-tagged).
    await scp.context_send(ctx._raw_handle, identity.did, b"Hello from SCP")

    await scp.context_close(ctx._raw_handle, identity.did)
    await scp.shutdown(5.0)


asyncio.run(main())
