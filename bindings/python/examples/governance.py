"""Governance demo.

Starts an in-memory relay, creates an identity, creates a governed context,
executes a role-change governance action, and verifies the result.

Phase 4 PR 5 (#1549) moved governance helpers onto :class:`scp_sdk.SCP`.
Use :meth:`SCP.governance_execute` with a JSON proposal.

Requires a built native extension (``maturin develop --release``).
"""

import asyncio
import json

from scp_sdk import SCP
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    with SCP(storage={"type": "in_memory"}) as scp:
        # 1. Start an in-memory relay.
        relay = await scp.relay_start_in_memory()
        print(f"Relay listening at {relay.relay_url}")

        # 1b. Connect transport to the relay.
        await scp.transport_connect(relay.relay_url)

        # 2. Create admin identity.
        admin = await scp.identity_create(CustodyType.IN_MEMORY)
        print(f"Admin DID: {admin.did}")

        # 3. Create a context with governance enabled.
        ctx = await scp.context_create(
            admin.did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                    Capability.MEMBER_INVITE.value,
                    Capability.GOVERNANCE_PROPOSE.value,
                    Capability.GOVERNANCE_VOTE.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
                "ttl": 600.0,
            },
        )
        print(f"Governed context created: {ctx.context_id}")

        try:
            # 4. Create a second identity and have them join.
            member = await scp.identity_create(CustodyType.IN_MEMORY)
            await scp.context_join(ctx._raw_handle, member.did)
            print(f"Member {member.did} joined")

            # 5. Admin executes a governance action to change the member's role.
            proposal = json.dumps(
                {
                    "action": {
                        "ChangeRole": {
                            "target_did": member.did,
                            "new_role": "moderator",
                        },
                    },
                }
            )
            result = await scp.governance_execute(ctx._raw_handle, proposal)
            print(f"Governance action result: {result}")

            # 6. Cleanup.
            await scp.context_leave(ctx._raw_handle, member.did)
            await scp.context_close(ctx._raw_handle, admin.did)
        finally:
            await relay.shutdown()

    print("Demo complete")


if __name__ == "__main__":
    asyncio.run(main())
