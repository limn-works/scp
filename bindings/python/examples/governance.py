"""Governance demo.

Starts an in-memory relay, creates an identity, creates a governed context,
proposes a role change via governance, executes the action, and verifies
the result.

Requires a built native extension (``maturin develop --release``).
"""

import asyncio
import json

from scp_sdk import Context, Identity
from scp_sdk.governance import execute_governance_action
from scp_sdk.server import Relay
from scp_sdk.transport import connect_relay
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    # 1. Start an in-memory relay
    async with await Relay.start_in_memory() as relay:
        print(f"Relay listening at {relay.relay_url}")

        # 1b. Connect transport to the relay
        await connect_relay(relay.relay_url)

        # 2. Create admin identity
        admin = await Identity.create(custody=CustodyType.IN_MEMORY)
        print(f"Admin DID: {admin.did}")

        # 3. Create a context with governance enabled
        async with await Context.create(
            creator=admin,
            ceiling=[
                Capability.MESSAGES_READ,
                Capability.MESSAGES_WRITE,
                Capability.MEMBER_INVITE,
                Capability.GOVERNANCE_PROPOSE,
                Capability.GOVERNANCE_VOTE,
            ],
            memory_scope=MemoryScope.EPHEMERAL,
            governance="single_admin",
            ttl=600.0,
        ) as ctx:
            print(f"Governed context created: {ctx.context_id}")

            # 4. Create a second identity and have them join
            member = await Identity.create(custody=CustodyType.IN_MEMORY)
            membership = await ctx.join(member)
            print(f"Member {member.did} joined as: {membership.role}")

            # 5. Admin executes a governance action to change the member's role
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
            result = await execute_governance_action(
                context=ctx,
                proposal_json=proposal,
            )
            print(f"Governance action result: {result}")

            # 6. Cleanup
            await ctx.leave(member)
            await ctx.close(admin)

    print("Demo complete")


if __name__ == "__main__":
    asyncio.run(main())
