/**
 * Participant management helpers for multi-party SCP workspaces.
 *
 * Encapsulates the pattern of creating identities, joining contexts with
 * specific roles, and minting role-scoped UCAN tokens for each participant.
 */

import {
  type Context,
  Identity,
  type MemberRole,
  mintUcan,
  type UcanToken,
} from "@limn-works/scp-ts";

// ---------------------------------------------------------------------------
// Role capability mapping
// ---------------------------------------------------------------------------

/** Capabilities granted to each built-in role. */
const ROLE_CAPABILITIES: Readonly<Record<string, readonly string[]>> = {
  Admin: [
    "messages:read",
    "messages:write",
    "role:assign",
    "member:invite",
    "member:remove",
    "outlet:register",
    "outlet:call:*",
    "governance:propose",
    "governance:vote",
  ],
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

/**
 * Returns the capability set for a given role name. Falls back to Observer
 * capabilities for unrecognized roles.
 */
export function capabilitiesForRole(role: string): readonly string[] {
  return ROLE_CAPABILITIES[role] ?? ROLE_CAPABILITIES.Observer ?? [];
}

// ---------------------------------------------------------------------------
// Participant descriptor
// ---------------------------------------------------------------------------

/** A participant with their identity, assigned role, and UCAN token. */
export interface Participant {
  /** The participant's SCP identity. */
  readonly identity: Identity;
  /** Role assigned within the workspace context. */
  readonly role: MemberRole;
  /** UCAN token scoped to the participant's role capabilities. */
  readonly token: UcanToken;
}

// ---------------------------------------------------------------------------
// Participant lifecycle
// ---------------------------------------------------------------------------

/**
 * Creates a new participant identity, adds them to the context with
 * the given role via governance, and mints a role-scoped UCAN token.
 *
 * The admin identity must be the context creator (or an admin member)
 * so that the governance action and UCAN mint succeed.
 *
 * @param ctx - The workspace context to join.
 * @param role - The role to assign (Admin, Moderator, Member, Observer).
 * @param adminIdentity - An admin identity authorized to add members.
 * @returns A fully initialized Participant.
 */
export async function addParticipant(
  ctx: Context,
  role: MemberRole,
  adminIdentity: Identity,
): Promise<Participant> {
  // 1. Create a fresh identity for this participant.
  const identity = await Identity.create({ custody: "in_memory" });

  // 2. Add the participant to the context via governance.
  //    For SingleAdmin contexts this executes immediately.
  const addAction = JSON.stringify({
    AddMember: {
      did: identity.did,
      role,
    },
  });
  await ctx.executeGovernanceAction(addAction);

  // 3. Mint a UCAN token scoped to the participant's role capabilities.
  const capabilities = capabilitiesForRole(role);
  const token = await mintUcan(ctx, identity.did, capabilities);

  return { identity, role, token };
}

/**
 * Removes a participant from the context via governance.
 *
 * @param ctx - The workspace context.
 * @param participant - The participant to remove.
 * @param reason - Optional removal reason for the audit log.
 */
export async function removeParticipant(
  ctx: Context,
  participant: Participant,
  reason?: string,
): Promise<void> {
  const removeAction = JSON.stringify({
    RemoveMember: {
      did: participant.identity.did,
      reason: reason ?? null,
    },
  });
  await ctx.executeGovernanceAction(removeAction);
}

/**
 * Changes a participant's role via governance and mints a new UCAN
 * token matching the updated role capabilities.
 *
 * @param ctx - The workspace context.
 * @param participant - The participant whose role is changing.
 * @param newRole - The new role to assign.
 * @returns An updated Participant with the new role and token.
 */
export async function changeParticipantRole(
  ctx: Context,
  participant: Participant,
  newRole: MemberRole,
): Promise<Participant> {
  // 1. Execute the role change via governance.
  const changeAction = JSON.stringify({
    ChangeRole: {
      did: participant.identity.did,
      new_role: newRole,
    },
  });
  await ctx.executeGovernanceAction(changeAction);

  // 2. Mint a new token with the updated role's capabilities.
  const capabilities = capabilitiesForRole(newRole);
  const token = await mintUcan(ctx, participant.identity.did, capabilities);

  return { identity: participant.identity, role: newRole, token };
}

/**
 * Lists all member DIDs and their roles in the context.
 *
 * @param ctx - The workspace context.
 * @returns An array of { did, role } pairs.
 */
export async function listMembers(
  ctx: Context,
): Promise<readonly { did: string; role: MemberRole | null }[]> {
  const dids = await ctx.memberDids();
  const members: { did: string; role: MemberRole | null }[] = [];
  for (const did of dids) {
    const role = await ctx.memberRole(did);
    members.push({ did, role });
  }
  return members;
}
