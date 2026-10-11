/**
 * Participant management helpers for multi-party SCP workspaces.
 *
 * Encapsulates the pattern of creating identities, joining contexts with
 * specific roles, and minting role-scoped UCAN tokens for each participant.
 */

import {
  type BuiltInRole,
  type Context,
  type Identity,
  type KeyCustodyProvider,
  type MemberRole,
  type SCP,
} from "@limn-works/scp-ts";

// ---------------------------------------------------------------------------
// Result narrowing
// ---------------------------------------------------------------------------

/**
 * Read a string field from a native result object, rejecting any other shape.
 * `ucanMint` and `ucanDelegate` type their results as `unknown`.
 */
export function stringField(value: unknown, name: string): string {
  if (typeof value !== "object" || value === null || !(name in value)) {
    throw new TypeError(`result has no ${name} field`);
  }
  const field = (value as Record<string, unknown>)[name];
  if (typeof field !== "string") throw new TypeError(`${name} is not a string`);
  return field;
}

/** Render a role for logs: a built-in role's name or a custom role's name. */
export function roleName(role: MemberRole | null): string {
  if (role === null) return "none";
  return typeof role === "string" ? role : role.name;
}

// ---------------------------------------------------------------------------
// Role capability mapping
// ---------------------------------------------------------------------------

/** The roles this workspace assigns. Each is a protocol-defined role. */
export type WorkspaceRole = Extract<BuiltInRole, "Admin" | "Moderator" | "Member" | "Observer">;

/**
 * Capabilities this workspace puts in each role's UCAN token. Each set is a
 * subset of the workspace ceiling.
 */
const ROLE_CAPABILITIES: Readonly<Record<WorkspaceRole, readonly string[]>> = {
  Admin: [
    "messages:read",
    "messages:write",
    "role:assign",
    "member:invite",
    "member:remove",
    "outlet:register",
    "outlet:query:*",
    "governance:propose",
    "governance:vote",
  ],
  Moderator: [
    "messages:read",
    "messages:write",
    "member:invite",
    "outlet:query:*",
    "governance:propose",
    "governance:vote",
  ],
  Member: ["messages:read", "messages:write", "outlet:query:*"],
  Observer: ["messages:read"],
};

/** Returns the token capability set for a workspace role. */
export function capabilitiesForRole(role: WorkspaceRole): readonly string[] {
  return ROLE_CAPABILITIES[role];
}

// ---------------------------------------------------------------------------
// Participant descriptor
// ---------------------------------------------------------------------------

/** A participant with their identity, assigned role, and UCAN token. */
export interface Participant {
  /** The participant's SCP identity. */
  readonly identity: Identity;
  /** Role assigned within the workspace context. */
  readonly role: WorkspaceRole;
  /** Encoded UCAN token scoped to the participant's role capabilities. */
  readonly token: string;
}

// ---------------------------------------------------------------------------
// Participant lifecycle
// ---------------------------------------------------------------------------

/**
 * Propose a governance action as `proposerDid`. Under `single_admin`
 * governance an admin's proposal executes in the same call.
 */
async function govern(scp: SCP, ctx: Context, proposerDid: string, action: object): Promise<void> {
  await scp.contextGovernancePropose(ctx, JSON.stringify(action), proposerDid);
}

/**
 * Creates a new participant identity, adds it to the context, assigns the
 * given role through governance, and mints a role-scoped UCAN token.
 *
 * The admin identity must be the context creator (or an admin member)
 * so that the governance action and UCAN mint succeed.
 *
 * @param scp - The SCP instance that hosts the workspace.
 * @param ctx - The workspace context to join.
 * @param custody - The key store that holds the new identity's keys.
 * @param role - The role to assign (Moderator, Member, Observer).
 * @param admin - An admin identity authorized to assign roles.
 * @returns A fully initialized Participant.
 */
export async function addParticipant(
  scp: SCP,
  ctx: Context,
  custody: KeyCustodyProvider,
  role: WorkspaceRole,
  admin: Identity,
): Promise<Participant> {
  // 1. Create a fresh identity for this participant.
  const identity = await scp.identityCreateWithCustody(custody);

  // 2. Add the participant to the context, then assign its role. Bridges
  //    report a built-in role by its lowercase name.
  await scp.contextJoin(ctx, identity.did);
  await govern(scp, ctx, admin.did, {
    ChangeRole: { did: identity.did, new_role: role.toLowerCase() },
  });

  // 3. Mint a UCAN token scoped to the participant's role capabilities.
  const token = stringField(
    await scp.ucanMint(ctx, identity.did, capabilitiesForRole(role)),
    "encoded",
  );

  return { identity, role, token };
}

/**
 * Removes a participant from the context via governance.
 *
 * @param scp - The SCP instance that hosts the workspace.
 * @param ctx - The workspace context.
 * @param admin - An admin identity authorized to remove members.
 * @param participant - The participant to remove.
 * @param reason - Optional removal reason for the audit log.
 */
export async function removeParticipant(
  scp: SCP,
  ctx: Context,
  admin: Identity,
  participant: Participant,
  reason?: string,
): Promise<void> {
  await govern(scp, ctx, admin.did, {
    RemoveMember: { did: participant.identity.did, reason: reason ?? null },
  });
}

/**
 * Changes a participant's role via governance and mints a new UCAN
 * token matching the updated role capabilities.
 *
 * @param scp - The SCP instance that hosts the workspace.
 * @param ctx - The workspace context.
 * @param admin - An admin identity authorized to assign roles.
 * @param participant - The participant whose role is changing.
 * @param newRole - The new role to assign.
 * @returns An updated Participant with the new role and token.
 */
export async function changeParticipantRole(
  scp: SCP,
  ctx: Context,
  admin: Identity,
  participant: Participant,
  newRole: WorkspaceRole,
): Promise<Participant> {
  // 1. Execute the role change via governance.
  await govern(scp, ctx, admin.did, {
    ChangeRole: { did: participant.identity.did, new_role: newRole.toLowerCase() },
  });

  // 2. Mint a new token with the updated role's capabilities.
  const token = stringField(
    await scp.ucanMint(ctx, participant.identity.did, capabilitiesForRole(newRole)),
    "encoded",
  );

  return { identity: participant.identity, role: newRole, token };
}

/**
 * Lists all member DIDs and their roles in the context.
 *
 * @param scp - The SCP instance that hosts the workspace.
 * @param ctx - The workspace context.
 * @returns An array of { did, role } pairs.
 */
export async function listMembers(
  scp: SCP,
  ctx: Context,
): Promise<readonly { did: string; role: MemberRole | null }[]> {
  const dids = await scp.contextMemberDids(ctx);
  const members: { did: string; role: MemberRole | null }[] = [];
  for (const did of dids) {
    members.push({ did, role: await scp.contextMemberRole(ctx, did) });
  }
  return members;
}
