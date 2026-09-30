/**
 * MCP integration: expose SCP outlets via an MCP JSON-RPC server, then
 * connect as an MCP client to an MCP server on this machine.
 *
 * Post-Phase-4 (ADR-048): all bridge operations route through an
 * explicit `SCP` instance. The free-function shims (`serveMcp`,
 * `connectMcp`, `connectMcpStdio`) were removed — use
 * `scp.mcpServerCreate`, `scp.mcpClientConnectSse`, and the other
 * `scp.mcp*` methods directly.
 *
 * Run: bun run examples/mcp-integration.ts, with a separate SCP SSE server
 * listening on localhost:8080 and SCP_MCP_SSE_TOKEN and
 * SCP_MCP_SSE_CONTEXT_ID set as the client section below describes.
 */

import { SCP, defineOutletDefinition } from "../src/index";

async function main(): Promise<void> {
  const scp = new SCP({ storage: { type: "in_memory" } });
  try {
    const identity = await scp.identityCreate("in_memory");

    // Create a context with outlet capabilities.
    const ctx = await scp.contextCreate(
      identity,
      JSON.stringify({
        ceiling: ["messages:read", "messages:write", "outlet:call:*", "outlet:register"],
        memoryScope: "ephemeral",
        governance: "single_admin",
      }),
    );

    // Register an outlet in the context.
    const outlet = defineOutletDefinition({
      name: "summarize",
      description: "Summarize text content",
      kind: "action",
      inputSchema: {
        type: "object",
        properties: { text: { type: "string" } },
        required: ["text"],
      },
      outputSchema: {
        type: "object",
        properties: { summary: { type: "string" } },
      },
      operator: identity.did,
    });
    await scp.outletRegister(ctx._rawHandle, outlet);

    // Start an MCP server exposing context outlets on stdio.
    const server = await scp.mcpServerCreate({
      identityDid: identity.did,
      contextIds: [ctx.contextId],
      transport: "stdio",
    });
    console.log("MCP server running, exposing outlets");

    try {
      // Or connect as an MCP client to a separate SCP SSE server that must
      // already be running on this machine at port 8080. An SCP SSE server
      // serves its event stream at `/sse` and takes requests at `/message`,
      // so the client dials `/sse`. That server cannot serve `ctx`: `ctx`
      // lives only in this process's in-memory instance, and the server this
      // example starts above uses stdio. The SSE server must expose a context
      // holding a `summarize` outlet; this example reads that context's ID
      // from SCP_MCP_SSE_CONTEXT_ID. An SCP server lists each outlet as
      // `<context_id>/call.<outlet>` or `<context_id>/query.<outlet>` and
      // refuses a bare outlet name in `tools/call`, so the example invokes the
      // name `mcpClientListTools` returns; the context ID passed to
      // `mcpClientInvoke` feeds only local provenance. An SCP SSE server
      // always runs a bearer check (ADR-015), so pass the token that server's
      // operator gives you; this example reads it from SCP_MCP_SSE_TOKEN. The transport has no
      // TLS, so a token is sent only to a loopback host.
      const sseToken = process.env.SCP_MCP_SSE_TOKEN;
      if (sseToken === undefined || sseToken === "") {
        throw new Error("set SCP_MCP_SSE_TOKEN to the bearer token of the SCP SSE server");
      }
      const sseContextId = process.env.SCP_MCP_SSE_CONTEXT_ID;
      if (sseContextId === undefined || sseContextId === "") {
        throw new Error(
          "set SCP_MCP_SSE_CONTEXT_ID to the ID of a context the SCP SSE server exposes",
        );
      }
      const client = await scp.mcpClientConnectSse("http://localhost:8080/sse", sseToken);
      try {
        const outlets = await scp.mcpClientListTools(client);
        console.log(`The server offers ${outlets.length} outlet(s)`);
        const summarizeNames = [`${sseContextId}/call.summarize`, `${sseContextId}/query.summarize`];
        const summarize = outlets
          .map((t) => (t as { name?: unknown }).name)
          .find((n): n is string => typeof n === "string" && summarizeNames.includes(n));
        if (summarize === undefined) {
          throw new Error(`context ${sseContextId} offers no summarize outlet`);
        }

        const result = await scp.mcpClientInvoke(
          client,
          summarize,
          JSON.stringify({ text: "SCP is a protocol for..." }),
          sseContextId,
          identity.did,
        );
        console.log("Result:", result);
      } finally {
        await scp.mcpClientDisconnect(client);
      }
    } finally {
      await scp.mcpServerStop(server);
    }

    await scp.contextClose(ctx._rawHandle, identity.did);
  } finally {
    await scp.shutdown(5);
  }
}

main().catch((error: unknown) => {
  console.error("Demo failed:", error);
  process.exit(1);
});
