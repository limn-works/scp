/**
 * Multi-party collaborative workspace over SCP.
 *
 * Demonstrates:
 * - Identity creation and agent key binding (ADR-039)
 * - Governed context with role-based capabilities
 * - Adding participants with different roles (Admin, Moderator, Member, Observer)
 * - Shared tool registration with capability-gated invocation
 * - Governance proposals and voting (threshold model)
 * - UCAN delegation for scoped authorization
 * - Trust evaluation from the event log
 * - Event log auditing with Merkle proofs
 *
 * Usage:
 *   bun run src/index.ts
 */

import {
  Context,
  type ContextParams,
  defineToolDefinition,
  delegateUcan,
  evaluateTrust,
  EventLog,
  Identity,
  mintUcan,
  validateUcan,
} from "@limn-works/scp-ts";

import {
  addParticipant,
  changeParticipantRole,
  listMembers,
  removeParticipant,
} from "./participant";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Capabilities forming the workspace ceiling -- the maximum grantable set. */
const WORKSPACE_CEILING: readonly string[] = [
  "messages:read",
  "messages:write",
  "role:assign",
  "member:invite",
  "member:remove",
  "outlet:register",
  "outlet:call:*",
  "governance:propose",
  "governance:vote",
];

/** Role definitions mapping role names to their capability subsets. */
const WORKSPACE_ROLES: Readonly<Record<string, readonly string[]>> = {
  Admin: [...WORKSPACE_CEILING],
  Moderator: [
    "messages:read",
    "messages:write",
    "member:invite",
    "outlet:call:*",
    "governance:propose",
    "governance:vote",
  ],
  Member: [
    "messages:read",
    "messages:write",
    "outlet:call:*",
  ],
  Observer: [
    "messages:read",
  ],
};

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

async function main(): Promise<void> {
  // =========================================================================
  // 1. Create admin identity
  // =========================================================================
  divider("1. Admin Identity");

  const admin = await Identity.createWithAgentKey({ custody: "in_memory" });
  log("identity", `Admin DID: ${admin.did}`);
  log("identity", `Custody: ${admin.custodyType}`);

  // =========================================================================
  // 2. Create governed workspace context
  // =========================================================================
  divider("2. Workspace Context");

  const contextParams: ContextParams = {
    ceiling: [...WORKSPACE_CEILING],
    roles: { ...WORKSPACE_ROLES },
    memoryScope: "full",
    governance: "single_admin",
    mode: "Encrypted",
    ceilingPolicy: "governed",
    ttl: 86400, // 24 hours
  };

  const ctx = await Context.create(admin, contextParams);
  log("context", `Context ID: ${ctx.contextId}`);

  const memberCount = await ctx.memberCount();
  log("context", `Initial members: ${memberCount}`);

  // =========================================================================
  // 3. Register shared tools
  // =========================================================================
  divider("3. Tool Registration");

  // A summarization tool available to Members and above.
  const summarizeTool = defineToolDefinition({
    name: "summarize",
    description: "Summarizes the conversation history in the workspace",
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

  const summarizeToolId = await ctx.registerTool(summarizeTool);
  log("tools", `Registered 'summarize' tool: ${summarizeToolId}`);

  // A code-review tool restricted to Moderator+ roles.
  const reviewTool = defineToolDefinition({
    name: "code-review",
    description: "Performs automated code review on submitted patches",
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

  const reviewToolId = await ctx.registerTool(reviewTool);
  log("tools", `Registered 'code-review' tool: ${reviewToolId}`);

  // Verify tool integrity against test vectors.
  const verifyResult = await ctx.verifyTool(summarizeToolId);
  log("tools", `Tool verification passed: ${verifyResult.passed}`);

  // =========================================================================
  // 4. Add participants with different roles
  // =========================================================================
  divider("4. Participant Management");

  // Add a moderator.
  const moderator = await addParticipant(ctx, "Moderator", admin);
  log("members", `Moderator joined: ${moderator.identity.did}`);
  log("members", `  Role: ${moderator.role}`);
  log("members", `  Token capabilities: ${moderator.token.capabilities.join(", ")}`);

  // Add a regular member.
  const member = await addParticipant(ctx, "Member", admin);
  log("members", `Member joined: ${member.identity.did}`);
  log("members", `  Role: ${member.role}`);

  // Add an observer (read-only).
  const observer = await addParticipant(ctx, "Observer", admin);
  log("members", `Observer joined: ${observer.identity.did}`);
  log("members", `  Role: ${observer.role}`);

  // List all members and roles.
  const members = await listMembers(ctx);
  log("members", `Total members: ${members.length}`);
  for (const m of members) {
    log("members", `  ${m.did} -> ${m.role}`);
  }

  // =========================================================================
  // 5. Capability-based authorization
  // =========================================================================
  divider("5. Capability-Based Authorization");

  // Mint a scoped token for tool invocation.
  const memberToolToken = await mintUcan(
    ctx,
    member.identity.did,
    ["outlet:call:*", `outlet:call:${summarizeToolId}`],
  );
  log("ucan", `Minted tool token for member: ${memberToolToken.id}`);

  // Validate the token against the required capability.
  await validateUcan(ctx, memberToolToken.encoded, `outlet:call:${summarizeToolId}`);
  log("ucan", "Token validated for summarize tool invocation");

  // Delegate a subset of the moderator's capabilities to the member.
  const delegatedToken = await delegateUcan(
    ctx,
    moderator.token,
    moderator.identity.did,
    member.identity.did,
    ["messages:read", "messages:write"],
  );
  log("ucan", `Delegated token from moderator to member: ${delegatedToken.id}`);
  log("ucan", `  Delegated capabilities: ${delegatedToken.capabilities.join(", ")}`);

  // Invoke the summarize tool with the member's scoped token.
  const toolOutput = await ctx.invokeTool(
    summarizeToolId,
    { maxLength: 200, format: "paragraph" },
    member.identity,
    memberToolToken.encoded,
  );
  log("tools", `Tool output: ${JSON.stringify(toolOutput)}`);

  // =========================================================================
  // 6. Messaging
  // =========================================================================
  divider("6. Messaging");

  await ctx.send("Welcome to the collaborative workspace!");
  log("messages", "Admin sent welcome message");

  // Join the context as the moderator and send a message.
  await ctx.join(moderator.identity);
  await ctx.send("Moderator checking in. Ready to review.");
  log("messages", "Moderator sent message");

  // =========================================================================
  // 7. Governance: propose and vote
  // =========================================================================
  divider("7. Governance");

  // --- Single-admin governance: immediate execution ---

  // Promote the member to Moderator via governance.
  const promotedMember = await changeParticipantRole(ctx, member, "Moderator");
  log("governance", `Promoted ${promotedMember.identity.did} to ${promotedMember.role}`);

  // Verify the role change took effect.
  const updatedRole = await ctx.memberRole(promotedMember.identity.did);
  log("governance", `Verified role: ${updatedRole}`);

  // --- Demonstrate the proposal lifecycle ---
  // Even under single_admin, the proposal/vote API works (auto-approved).

  // Propose extending the TTL by 12 hours.
  const extendAction = JSON.stringify({
    ExtendTtl: { additional_secs: 43200 },
  });
  const proposalResult = await ctx.proposeGovernanceAction(extendAction);
  log("governance", `TTL extension proposal: ${proposalResult}`);

  // Parse the proposal result to get the proposal ID.
  const proposalData = JSON.parse(proposalResult) as {
    proposal_id: string;
    status: string;
  };
  log("governance", `  Proposal ID: ${proposalData.proposal_id}`);
  log("governance", `  Status: ${proposalData.status}`);

  // List all proposals.
  const proposals = await ctx.listGovernanceProposals();
  log("governance", `All proposals: ${proposals}`);

  // Propose modifying the ceiling to add a new capability.
  const ceilingAction = JSON.stringify({
    ModifyCeiling: {
      new_ceiling: [...WORKSPACE_CEILING, "analytics:read"],
    },
  });
  const ceilingProposal = await ctx.proposeGovernanceAction(ceilingAction);
  log("governance", `Ceiling modification proposal: ${ceilingProposal}`);

  // =========================================================================
  // 8. Trust evaluation
  // =========================================================================
  divider("8. Trust Evaluation");

  // Evaluate trust for the moderator based on their event log activity.
  const trustEval = await evaluateTrust(ctx, moderator.identity.did);
  log("trust", `Trust evaluation for moderator:`);
  log("trust", `  Subject: ${trustEval.subjectDid}`);
  log("trust", `  Context: ${trustEval.contextId}`);
  log("trust", `  Participation count: ${trustEval.behavioralRecord.participationCount}`);
  log("trust", `  Governance actions by: ${trustEval.behavioralRecord.governanceActionsBy}`);
  log("trust", `  Attestations: ${trustEval.attestations.length}`);

  // =========================================================================
  // 9. Event log audit
  // =========================================================================
  divider("9. Event Log Audit");

  const eventLog = new EventLog(ctx);

  // Query all events.
  const allEvents = await eventLog.query();
  log("events", `Total events: ${allEvents.length}`);
  for (const event of allEvents.slice(0, 5)) {
    log("events", `  [${event.sequence}] ${event.eventType} by ${event.actorDid}`);
  }
  if (allEvents.length > 5) {
    log("events", `  ... and ${allEvents.length - 5} more`);
  }

  // Query governance-specific events.
  const govEvents = await eventLog.query({ eventType: "GovernanceAction" });
  log("events", `Governance events: ${govEvents.length}`);

  // Create a Merkle checkpoint for the current state.
  const checkpoint = await eventLog.checkpoint();
  log("events", `Checkpoint root: ${checkpoint.root}`);
  log("events", `Checkpoint event count: ${checkpoint.eventCount}`);

  // Verify inclusion of the first event.
  if (allEvents.length > 0) {
    const proof = await eventLog.verify({ type: "inclusion", leafIndex: 0 });
    log("events", `First event inclusion proof verified: ${proof.verified}`);
  }

  // =========================================================================
  // 10. Cleanup
  // =========================================================================
  divider("10. Cleanup");

  // Remove the observer.
  await removeParticipant(ctx, observer, "Workspace complete");
  log("cleanup", `Removed observer: ${observer.identity.did}`);

  // Final member count.
  const finalCount = await ctx.memberCount();
  log("cleanup", `Final member count: ${finalCount}`);

  // Close the context (terminates for all members).
  await ctx.close();
  log("cleanup", "Workspace context closed");

  console.log("\nCollaborative workspace demo complete.");
}

main().catch((error: unknown) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
