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

            # 5. Admin proposes a governance action to change the member's role.
            #    Under SingleAdmin the proposal is tracked, approved, and
            #    executed by the runtime in one step; the response carries the
            #    `proposal_id` the engine retained.
            action = json.dumps(
                {
                    "ChangeRole": {
                        "did": member.did,
                        "new_role": "moderator",
                    },
                }
            )
            propose_result = json.loads(
                await scp.governance_propose(ctx._raw_handle, admin.did, action)
            )
            proposal_id = propose_result["proposal_id"]
            print(f"Proposed + executed governance action: {proposal_id}")

            # `governance_execute` runs an already-approved proposal BY ID. The
            # runtime resolves the authoritative proposal from its own
            # quorum-validated engine — the caller passes no action, only the id.
            # The SingleAdmin propose above already executed this proposal, so a
            # direct execute now demonstrates the runtime's replay guard.
            try:
                await scp.governance_execute(ctx._raw_handle, admin.did, proposal_id)
            except Exception as replay:  # illustrative
                print(f"Re-executing an applied proposal is rejected: {replay}")

            # 6. Cleanup.
            await scp.context_leave(ctx._raw_handle, member.did)
            await scp.context_close(ctx._raw_handle, admin.did)
        finally:
            await relay.shutdown()

    print("Demo complete")


if __name__ == "__main__":
    asyncio.run(main())
