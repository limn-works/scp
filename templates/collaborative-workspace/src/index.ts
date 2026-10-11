/**
 * Multi-party collaborative workspace over SCP.
 *
 * Demonstrates:
 * - Identity creation and agent key binding (ADR-039)
 * - Governed context with role-based capabilities
 * - Adding participants with different roles (Admin, Moderator, Member, Observer)
 * - Shared outlet registration with capability-gated invocation
 * - Governance proposals under single-admin governance
 * - UCAN delegation for scoped authorization
 * - Trust evaluation from the event log
 * - Event log auditing with Merkle proofs
 *
 * One SCP instance hosts every participant, as a team server hosting its
 * members' agents would. The TypeScript SDK ships no production key store,
 * so the caller passes the `KeyCustodyProvider` that holds every
 * participant's keys; the SDK's one `CustodyType`, `"in_memory"`, works only
 * with an addon built with the `testing` feature.
 *
 * Usage:
 *   import { runWorkspace } from "./src/index";
 *   await runWorkspace(custody, relayUrl, process.env.SCP_STORAGE_PASSPHRASE);
 */

import {
  Capabilities,
  type ContextParams,
  defineOutletDefinition,
  type KeyCustodyProvider,
  outletQuery,
  SCP,
} from "@limn-works/scp-ts";

import {
  addParticipant,
  changeParticipantRole,
  listMembers,
  removeParticipant,
  roleName,
  stringField,
} from "./participant";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Capabilities forming the workspace ceiling -- the maximum grantable set. */
const WORKSPACE_CEILING: readonly string[] = [
  Capabilities.MESSAGES_READ,
  Capabilities.MESSAGES_WRITE,
  Capabilities.ROLE_ASSIGN,
  Capabilities.MEMBER_INVITE,
  Capabilities.MEMBER_REMOVE,
  Capabilities.OUTLET_REGISTER,
  Capabilities.OUTLET_QUERY_ALL,
  Capabilities.GOVERNANCE_PROPOSE,
  Capabilities.GOVERNANCE_VOTE,
];

/** Workspace lifetime before governance must extend it. */
const WORKSPACE_TTL_SECS = 86_400;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(section: string, message: string): void {
  console.log(`[${section}] ${message}`);
}

function divider(title: string): void {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`  ${title}`);
  console.log("=".repeat(60));
}

// ---------------------------------------------------------------------------
// Main workflow
// ---------------------------------------------------------------------------

export async function runWorkspace(
  custody: KeyCustodyProvider,
  relayUrl: string,
  storagePassphrase: string,
): Promise<void> {
  const scp = new SCP({
    storage: { type: "sqlite", path: "./scp-workspace", passphrase: storagePassphrase },
  });
  try {
    // =======================================================================
    // 1. Create admin identity
    // =======================================================================
    divider("1. Admin Identity");

    const created = await scp.identityCreateWithCustody(custody);
    const admin = await scp.identityAddAgentKey(created);
    log("identity", `Admin DID: ${admin.did}`);

    // Attach the relay transport before the first context: the context
    // supervisor starts on the first context and binds the transport it
    // finds then.
    await scp.configureRelayTransport(relayUrl, admin.did);
    log("identity", `Relay transport: ${relayUrl}`);

    // =======================================================================
    // 2. Create governed workspace context
    // =======================================================================
    divider("2. Workspace Context");

    const contextParams: ContextParams = {
      ceiling: [...WORKSPACE_CEILING],
      memoryScope: "full",
      governance: "single_admin",
      mode: "Encrypted",
      ceilingPolicy: "governed",
      ttl: WORKSPACE_TTL_SECS,
    };

    const ctx = await scp.contextCreate(admin, JSON.stringify(contextParams));
    log("context", `Context ID: ${ctx.contextId}`);
    log("context", `Initial members: ${await scp.contextMemberCount(ctx)}`);

    // =======================================================================
    // 3. Register shared outlets
    // =======================================================================
    divider("3. Outlet Registration");

    // A summarization outlet available to Members and above.
    const summarizeOutlet = defineOutletDefinition({
      name: "summarize",
      description: "Summarizes the conversation history in the workspace",
      kind: "query",
      inputSchema: {
        type: "object",
        properties: {
          maxLength: { type: "number", description: "Maximum summary length in characters" },
          format: { type: "string", enum: ["bullet", "paragraph", "outline"] },
        },
        required: ["maxLength"],
      },
      outputSchema: {
        type: "object",
        properties: {
          summary: { type: "string" },
          messageCount: { type: "number" },
        },
        required: ["summary", "messageCount"],
      },
      operator: admin.did,
      testVectors: [
        {
          input: { maxLength: 100, format: "bullet" },
          expectedOutput: { summary: "- Test summary", messageCount: 0 },
          description: "Empty workspace returns zero-message summary",
        },
      ],
    });

    const summarizeId = await scp.outletRegister(ctx, summarizeOutlet);
    log("outlets", `Registered 'summarize' outlet: ${summarizeId}`);

    // A code-review outlet.
    const reviewOutlet = defineOutletDefinition({
      name: "code-review",
      description: "Performs automated code review on submitted patches",
      kind: "query",
      inputSchema: {
        type: "object",
        properties: {
          diff: { type: "string", description: "Unified diff to review" },
          language: { type: "string", description: "Programming language" },
        },
        required: ["diff"],
      },
      outputSchema: {
        type: "object",
        properties: {
          findings: {
            type: "array",
            items: {
              type: "object",
              properties: {
                severity: { type: "string" },
                message: { type: "string" },
                line: { type: "number" },
              },
            },
          },
          approved: { type: "boolean" },
        },
        required: ["findings", "approved"],
      },
      operator: admin.did,
    });

    const reviewId = await scp.outletRegister(ctx, reviewOutlet);
    log("outlets", `Registered 'code-review' outlet: ${reviewId}`);

    // Verify outlet integrity against its test vectors.
    const verification = await scp.outletVerify(ctx, summarizeId);
    log("outlets", `Outlet verification: ${JSON.stringify(verification)}`);

    // =======================================================================
    // 4. Add participants with different roles
    // =======================================================================
    divider("4. Participant Management");

    const moderator = await addParticipant(scp, ctx, custody, "Moderator", admin);
    log("members", `Moderator joined: ${moderator.identity.did}`);

    const member = await addParticipant(scp, ctx, custody, "Member", admin);
    log("members", `Member joined: ${member.identity.did}`);

    const observer = await addParticipant(scp, ctx, custody, "Observer", admin);
    log("members", `Observer joined: ${observer.identity.did}`);

    const members = await listMembers(scp, ctx);
    log("members", `Total members: ${members.length}`);
    for (const m of members) {
      log("members", `  ${m.did} -> ${roleName(m.role)}`);
    }

    // =======================================================================
    // 5. Capability-based authorization
    // =======================================================================
    divider("5. Capability-Based Authorization");

    // Mint a token scoped to the one outlet the member may call.
    const summarizeCapability = outletQuery(summarizeId);
    const memberOutletToken = stringField(
      await scp.ucanMint(ctx, member.identity.did, [summarizeCapability]),
      "encoded",
    );
    log("ucan", "Minted summarize token for member");

    // Validate the token against the required capability.
    await scp.ucanValidate(ctx, memberOutletToken, summarizeCapability, member.identity.did);
    log("ucan", "Token validated for summarize invocation");

    // Delegate a subset of the moderator's capabilities to the member.
    const delegated = await scp.ucanDelegate(
      ctx,
      moderator.identity.did,
      member.identity.did,
      moderator.token,
      [Capabilities.MESSAGES_READ, Capabilities.MESSAGES_WRITE],
    );
    log("ucan", `Delegated token from moderator to member: ${stringField(delegated, "id")}`);

    // Invoke the summarize outlet as the member. Awaiting the handle drains
    // the stream to its aggregated result.
    const summary = await ctx.outlets.invoke(
      summarizeId,
      { maxLength: 200, format: "paragraph" },
      { ucanToken: memberOutletToken, callerDid: member.identity.did },
    );
    log("outlets", `Outlet output: ${JSON.stringify(summary.value)}`);

    // =======================================================================
    // 6. Messaging
    // =======================================================================
    divider("6. Messaging");

    const encoder = new TextEncoder();
    await scp.contextSend(ctx, admin.did, encoder.encode("Welcome to the collaborative workspace!"));
    log("messages", "Admin sent welcome message");

    await scp.contextSend(
      ctx,
      moderator.identity.did,
      encoder.encode("Moderator checking in. Ready to review."),
    );
    log("messages", "Moderator sent message");

    // =======================================================================
    // 7. Governance
    // =======================================================================
    divider("7. Governance");

    // Under single_admin governance, the admin's proposals execute at once.
    const promoted = await changeParticipantRole(scp, ctx, admin, member, "Moderator");
    log("governance", `Promoted ${promoted.identity.did} to ${promoted.role}`);

    const updatedRole = await scp.contextMemberRole(ctx, promoted.identity.did);
    log("governance", `Verified role: ${roleName(updatedRole)}`);

    // Propose extending the TTL by 12 hours.
    const extended = await scp.contextProposeTtlExtension(ctx, admin.did, 43_200);
    log("governance", `TTL extension executed: ${extended}`);

    // List all proposals.
    const proposals = await scp.contextGovernanceListProposals(ctx);
    log("governance", `All proposals: ${proposals}`);

    // =======================================================================
    // 8. Trust evaluation
    // =======================================================================
    divider("8. Trust Evaluation");

    const trust = await scp.evaluateTrust(ctx, moderator.identity.did);
    log("trust", "Trust evaluation for moderator:");
    log("trust", `  Subject: ${trust.subjectDid}`);
    log("trust", `  Context: ${trust.contextId}`);
    log("trust", `  Governance actions by: ${trust.behavioralRecord.governanceActionsBy}`);
    log("trust", `  Outlet invocations: ${trust.behavioralRecord.outletInvocationCount}`);
    log("trust", `  Attestations: ${trust.attestations.length}`);

    // =======================================================================
    // 9. Event log audit
    // =======================================================================
    divider("9. Event Log Audit");

    const events = await scp.eventLogQuery(ctx);
    log("events", `Total events: ${events.length}`);

    const checkpoint = await scp.eventLogCheckpoint(ctx, admin, 0);
    log("events", `Checkpoint root: ${stringField(checkpoint, "merkleRoot")}`);

    if (events.length > 0) {
      const proof = await scp.eventLogVerify(
        ctx,
        JSON.stringify({ type: "inclusion", leaf_index: 0 }),
      );
      log("events", `First event inclusion proof: ${JSON.stringify(proof)}`);
    }

    // =======================================================================
    // 10. Cleanup
    // =======================================================================
    divider("10. Cleanup");

    await removeParticipant(scp, ctx, admin, observer, "Workspace complete");
    log("cleanup", `Removed observer: ${observer.identity.did}`);
    log("cleanup", `Final member count: ${await scp.contextMemberCount(ctx)}`);

    // Close the context (terminates for all members).
    await scp.contextClose(ctx, admin.did);
    log("cleanup", "Workspace context closed");

    console.log("\nCollaborative workspace demo complete.");
  } finally {
    await scp.shutdown();
  }
}
