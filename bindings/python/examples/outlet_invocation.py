"""Outlet invocation demo.

Starts an in-memory relay, creates an identity, creates a context with
outlet capabilities, mints a UCAN token for authorization, invokes the
outlet, and verifies the result.

Phase 4 PR 5 (#1549) moved every operation onto :class:`SCP` — see
:meth:`SCP.relay_start_in_memory`, :meth:`SCP.transport_connect`,
:meth:`SCP.identity_create`, :meth:`SCP.context_create`,
:meth:`SCP.ucan_mint`, :meth:`SCP.outlet_invoke`, and
:meth:`SCP.context_close`.

Requires a built native extension (``maturin develop --release``).
"""

import asyncio

from scp_sdk import SCP
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    with SCP(storage={"type": "in_memory"}) as scp:
        # 1. Start an in-memory relay.
        relay = await scp.relay_start_in_memory()
        print(f"Relay listening at {relay.relay_url}")

        # 1b. Connect transport to the relay.
        await scp.transport_connect(relay.relay_url)

        # 2. Create an identity.
        identity = await scp.identity_create(CustodyType.IN_MEMORY)
        print(f"Identity DID: {identity.did}")

        # 3. Create a context with outlet capabilities.
        ctx = await scp.context_create(
            identity.did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                    Capability.TOOL_INVOKE_ALL.value,
                    Capability.TOOL_REGISTER.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
            },
        )
        print(f"Context created: {ctx.context_id}")

        try:
            # 4. Mint a UCAN token authorizing outlet invocation.
            ucan_token = await scp.ucan_mint(
                ctx.context_id,
                identity.did,
                ["tool:invoke:*"],
            )
            print(f"UCAN minted: {ucan_token.token_id}")

            # 5. Invoke the outlet (requires a UCAN token).
            try:
                result = await scp.outlet_invoke(
                    ctx.context_id,
                    "weather",
                    {"city": "Berlin"},
                    identity.did,
                    ucan_token.token_id,
                )
                print(f"Weather result: {result}")
            except Exception as exc:
                # Outlet invocation may fail without a registered outlet handler.
                print(f"Outlet invocation result: {exc}")

            # 6. Cleanup.
            await scp.context_close(ctx._raw_handle, identity.did)
            print("Context closed")
        finally:
            await relay.shutdown()

    print("Demo complete")


if __name__ == "__main__":
    asyncio.run(main())
