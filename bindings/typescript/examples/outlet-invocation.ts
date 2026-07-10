/**
 * Outlet invocation demo.
 *
 * Starts an in-memory relay via the caller-owned `SCP`, creates an
 * identity, creates a context with outlet capabilities, registers an outlet
 * with test vectors, mints a UCAN token, invokes the outlet with
 * authorization, and reports the result.
 *
 * Post-Phase-4 (ADR-048): all bridge operations route through an
 * explicit `SCP` instance. The free-function `mintUcan` and the static
 * `Relay.startInMemory()` factory were removed — use
 * `scp.relayStartInMemory()` and `scp.ucanMint(...)`.
 *
 * Run: bun run examples/outlet-invocation.ts
 */

import { SCP, type OutletDefinition, type UcanToken, defineOutletDefinition } from "../src/index";

async function main(): Promise<void> {
  const scp = new SCP({ storage: { type: "in_memory" } });
  let relay: Awaited<ReturnType<SCP["relayStartInMemory"]>> | null = null;
  try {
    // 1. Start an in-memory relay.
    relay = await scp.relayStartInMemory();
    console.log(`Relay listening at ${relay.relayUrl}`);

    // 2. Create an identity.
    const identity = await scp.identityCreate("in_memory");
    console.log(`Identity DID: ${identity.did}`);

    // 3. Wire the bridge's transport to the relay.
    await scp.configureRelayTransport(relay.relayUrl, identity.did);

    // 4. Define an outlet with test vectors.
    const weatherOutlet: OutletDefinition = defineOutletDefinition({
      name: "weather",
      description: "Get current weather for a city",
      inputSchema: {
        type: "object",
        properties: { city: { type: "string" } },
        required: ["city"],
      },
      outputSchema: {
        type: "object",
        properties: {
          tempC: { type: "number" },
          condition: { type: "string" },
        },
      },
      operator: identity.did,
      testVectors: [
        {
          input: { city: "Berlin" },
          expectedOutput: { tempC: 18, condition: "cloudy" },
          description: "Berlin weather lookup",
        },
      ],
    });

    // 5. Create a context with outlet capabilities.
    const ctx = await scp.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write", "outlet:call:*", "outlet:register"],
        memoryScope: "ephemeral",
        governance: "single_admin",
      }),
    );
    console.log(`Context created: ${ctx.contextId}`);

    // 6. Register the outlet.
    const outletId = await scp.outletRegister(ctx._rawHandle, weatherOutlet);
    console.log(`Registered outlet: ${outletId}`);

    // 7. Mint a UCAN token for outlet invocation.
    const ucan = (await scp.ucanMint(ctx._rawHandle, identity.did, ["outlet_call:*"])) as UcanToken;
    console.log(`UCAN minted: ${ucan.id}`);

    // 8. Invoke the outlet with the UCAN token.
    try {
      const result = await scp.outletInvoke(
        ctx._rawHandle,
        "weather",
        JSON.stringify({ city: "Berlin" }),
        identity.did,
        ucan.encoded,
      );
      console.log("Weather result:", result);
    } catch (err) {
      console.log("Outlet invocation result:", err);
    }

    // 9. Cleanup.
    await scp.contextClose(ctx._rawHandle, identity.did);
    console.log("Context closed");
  } finally {
    if (relay !== null) {
      await relay.shutdown();
    }
    await scp.shutdown(5);
    console.log("Demo complete");
  }
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
