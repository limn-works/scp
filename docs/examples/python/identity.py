"""Identity creation and DID document inspection.

Demonstrates creating a new SCP identity using did:dht,
inspecting the resulting DID document, and resolving it.

Prerequisites:
    pip install scp-sdk
    # or: maturin develop --release (from bindings/python/)

Usage:
    python identity.py
"""

import asyncio

from scp_sdk import Identity, CustodyType


async def main() -> None:
    # 1. Create a new identity with the encrypted key file SCP implements.
    #    In production, pass "encrypted_file" for the on-disk key store SCP
    #    implements, or "os_keystore" together with a KeyCustodyProvider for
    #    the operating system's own key store. Section 3.2.2 of the identity
    #    spec, the custody vocabulary, states those two values. Neither call
    #    creates an identity on a released wheel: both return SCP-IDENT-1059,
    #    because no pre-rotation custody backend is wired yet.
    identity = await Identity.create(custody=CustodyType.ENCRYPTED_FILE)

    print(f"DID: {identity.did}")
    print(f"Custody type: {identity.custody_type}")
    print()

    # 2. Resolve the DID to its document.
    #    This queries the DHT and returns a DIDDocument dataclass.
    doc = await identity.resolve(identity.did)

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
    agent_identity = await Identity.create_with_agent_key(
        custody=CustodyType.ENCRYPTED_FILE,
    )
    print(f"Agent identity DID: {agent_identity.did}")
    print()

    # 4. Add an agent key to an existing identity.
    updated = await identity.add_agent_key()
    print(f"Added agent key to: {updated.did}")

    # 5. Rotate the agent key.
    rotated = await updated.rotate_agent_key()
    print(f"Rotated agent key for: {rotated.did}")

    # 6. Remove the agent key.
    cleaned = await rotated.remove_agent_key()
    print(f"Removed agent key from: {cleaned.did}")

    print()
    print("Identity operations complete.")


if __name__ == "__main__":
    asyncio.run(main())
