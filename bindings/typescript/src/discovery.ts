/**
 * Discovery module for the SCP TypeScript SDK.
 *
 * Provides functions for parsing SCP addresses, creating discovery queries,
 * normalizing addresses, discovering contexts from DIDs or `scp://` URIs,
 * and resolving addresses to typed `AddressResolution` results.
 *
 * See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).
 */

import { mapBridgeError, ValidationError } from "./errors";
import { getBridge } from "./internal/bridge";
import { safeJsonParse } from "./internal/json-utils";
import type { AddressResolution, ResolutionLayer, ResolutionPath, TrustLevel } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A parsed SCP address. */
export interface ParsedAddress {
  /** Address type: `"DiscoveryHandle"`, `"DomainHandle"`, `"AttestationHandle"`, or `"Unscoped"` (PascalCase per §22.11.3). */
  readonly type: string;
  /** Additional fields depend on the address type. */
  readonly [key: string]: unknown;
}

/**
 * A context discovery result.
 *
 * Includes `trustLevel` and `resolutionPath` per §22.2.1 `AddressResolution`.
 */
export interface DiscoveryResult {
  readonly contextId: string;
  readonly relayUrls: readonly string[];
  readonly publisherDid: string;
  readonly discoverySource: string;
  readonly mode: string | null;
  readonly metadataSummary: string | null;
  /** Trust level of this discovery result (§22.7). */
  readonly trustLevel: TrustLevel;
  /** Resolution path recording which layer produced this result (§22.7). */
  readonly resolutionPath: ResolutionPath;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parses a `ResolutionPath` from a bridge JSON object.
 */
function parseResolutionPath(raw: Record<string, unknown>): ResolutionPath {
  return {
    layer: (raw.layer as ResolutionLayer) ?? "Domain",
    source: (raw.source as string) ?? "unknown",
    sourceId: (raw.source_id ?? raw.sourceId ?? null) as string | null,
    resolvedAt: (raw.resolved_at ?? raw.resolvedAt ?? 0) as number,
  };
}

/** The 6 valid TrustLevel kind values per §22.7. */
const VALID_TRUST_LEVEL_KINDS = new Set([
  "DirectExchange",
  "LocalPetname",
  "DomainVerified",
  "AttestationVerified",
  "DiscoveryContextVerified",
  "MultiLayerCorroborated",
]);

/**
 * Validates that a string is one of the 6 spec-defined TrustLevel kind values.
 *
 * @throws {ValidationError} If the kind is not in the spec-defined set.
 */
function validateTrustLevelKind(kind: string): asserts kind is TrustLevel["kind"] {
  if (!VALID_TRUST_LEVEL_KINDS.has(kind)) {
    throw new ValidationError(
      `Unknown TrustLevel kind: "${kind}". Expected one of: ${[...VALID_TRUST_LEVEL_KINDS].join(", ")}`,
      "SCP-VALID-7100",
    );
  }
}

/**
 * Parses a trust level from the bridge JSON. The NAPI bridge emits trust
 * levels as `{ "kind": "..." }` objects (discriminated unions per §22.7).
 * The `MultiLayerCorroborated` variant additionally carries `sources`.
 *
 * Also handles legacy string values (e.g. `"DomainVerified"`) by wrapping
 * them into the discriminated union shape.
 *
 * @throws {ValidationError} On unrecognized variants or unexpected input types.
 * §22.7 defines exactly 6 variants.
 */
function parseTrustLevel(raw: unknown): TrustLevel {
  if (raw != null && typeof raw === "object" && "kind" in raw) {
    const obj = raw as Record<string, unknown>;
    const kind = String(obj.kind);
    validateTrustLevelKind(kind);
    if (kind === "MultiLayerCorroborated") {
      const rawSources = (obj.sources ?? []) as Array<Record<string, unknown>>;
      return {
        kind: "MultiLayerCorroborated",
        sources: rawSources.map(parseResolutionPath),
      };
    }
    return { kind };
  }
  // Handle plain string trust levels from the bridge.
  if (typeof raw === "string") {
    validateTrustLevelKind(raw);
    if (raw === "MultiLayerCorroborated") {
      return { kind: "MultiLayerCorroborated", sources: [] };
    }
    return { kind: raw };
  }
  throw new ValidationError(
    `Invalid TrustLevel value: expected object with "kind" or string, got ${typeof raw}`,
    "SCP-VALID-7101",
  );
}

/**
 * Parses a raw bridge discovery result item (snake_case JSON) into a
 * `DiscoveryResult` with trust and resolution path metadata.
 */
function parseDiscoveryResult(item: Record<string, unknown>): DiscoveryResult {
  const rawPath = (item.resolution_path ?? item.resolutionPath ?? {}) as Record<string, unknown>;
  return {
    contextId: (item.context_id ?? item.contextId) as string,
    relayUrls: (item.relay_urls ?? item.relayUrls) as readonly string[],
    publisherDid: (item.publisher_did ?? item.publisherDid) as string,
    discoverySource: (item.discovery_source ?? item.discoverySource) as string,
    mode: (item.mode ?? null) as string | null,
    metadataSummary: (item.metadata_summary ?? item.metadataSummary ?? null) as string | null,
    trustLevel: parseTrustLevel(item.trust_level ?? item.trustLevel),
    resolutionPath: parseResolutionPath(rawPath),
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parses an SCP address string into its components.
 *
 * @param address - The address string to parse (e.g., `"alice@cooking-community"`).
 * @returns The parsed address object.
 * @throws {ValidationError} If the address is malformed.
 */
export async function parseAddress(address: string): Promise<ParsedAddress> {
  try {
    const bridge = await getBridge();
    const result = await bridge.discoveryParseAddress(address);
    return safeJsonParse(result, "discoveryParseAddress") as ParsedAddress;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Creates a discovery query as a JSON string.
 *
 * @param options - Query parameters.
 * @returns A JSON string representing the discovery query.
 */
export async function createQuery(options?: {
  capabilities?: string[];
  keywords?: string[];
  minHistorySecs?: number;
}): Promise<string> {
  try {
    const bridge = await getBridge();
    return bridge.discoveryCreateQuery(
      options?.capabilities,
      options?.keywords,
      options?.minHistorySecs,
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Normalizes an address string per SCP addressing rules.
 *
 * @param address - The address to normalize.
 * @returns The normalized address string.
 */
export async function normalizeAddress(address: string): Promise<string> {
  try {
    const bridge = await getBridge();
    return bridge.discoveryNormalizeAddress(address);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Discovers contexts from a DID string or `scp://` URI.
 *
 * @param query - A DID string or `scp://` URI.
 * @returns Parsed discovery results including trust level and resolution path.
 * @throws {ContextError} If discovery fails.
 * @throws {ValidationError} If the query is neither a DID nor an `scp://` URI.
 */
export async function discoverContexts(query: string): Promise<DiscoveryResult[]> {
  try {
    const bridge = await getBridge();
    const raw = await bridge.contextDiscover(query);
    const parsed = safeJsonParse(raw, "contextDiscover") as Array<Record<string, unknown>>;
    return parsed.map(parseDiscoveryResult);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Resolves an SCP address (DID or `scp://` URI) to typed `AddressResolution` results.
 *
 * Wraps `discoverContexts()` and returns `AddressResolution[]` with the
 * discriminated union structure matching §22.2.1.
 *
 * Currently resolves context addresses only. Identity resolution (petnames,
 * attestation handles, domain handles) requires handle tool infrastructure
 * defined in §22.3-22.6 and will be wired when those subsystems are
 * available.
 *
 * @param query - A DID string or `scp://` URI.
 * @returns Typed address resolution results.
 * @throws {ContextError} If discovery fails.
 * @throws {ValidationError} If the query is neither a DID nor an `scp://` URI.
 */
export async function resolveAddress(query: string): Promise<AddressResolution[]> {
  const results = await discoverContexts(query);
  return results.map(
    (r): AddressResolution => ({
      type: "Context",
      contextId: r.contextId,
      relayUrls: r.relayUrls,
      mode: r.mode,
      trustLevel: r.trustLevel,
      resolutionPath: r.resolutionPath,
    }),
  );
}

// ---------------------------------------------------------------------------
// Petname operations (§22.4)
// ---------------------------------------------------------------------------

/**
 * Assigns a petname to a DID within the owner's local namespace.
 *
 * @param ownerDid - DID of the identity that owns this petname map.
 * @param targetDid - DID to assign the petname to.
 * @param name - The petname string.
 * @throws {ValidationError} If `ownerDid` is empty.
 */
export async function petnameSet(ownerDid: string, targetDid: string, name: string): Promise<void> {
  try {
    const bridge = await getBridge();
    bridge.petnameSet(ownerDid, targetDid, name);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Removes a petname from a DID.
 *
 * @param ownerDid - DID of the identity that owns this petname map.
 * @param targetDid - DID to remove the petname from.
 * @throws {ValidationError} If `ownerDid` is empty.
 */
export async function petnameRemove(ownerDid: string, targetDid: string): Promise<void> {
  try {
    const bridge = await getBridge();
    bridge.petnameRemove(ownerDid, targetDid);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Assigns a petname to a context within the owner's local namespace.
 *
 * @param ownerDid - DID of the identity that owns this petname map.
 * @param contextId - Context ID to assign the petname to.
 * @param name - The petname string.
 * @throws {ValidationError} If `ownerDid` is empty.
 */
export async function petnameSetContext(
  ownerDid: string,
  contextId: string,
  name: string,
): Promise<void> {
  try {
    const bridge = await getBridge();
    bridge.petnameSetContext(ownerDid, contextId, name);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Removes a petname from a context.
 *
 * @param ownerDid - DID of the identity that owns this petname map.
 * @param contextId - Context ID to remove the petname from.
 * @throws {ValidationError} If `ownerDid` is empty.
 */
export async function petnameRemoveContext(ownerDid: string, contextId: string): Promise<void> {
  try {
    const bridge = await getBridge();
    bridge.petnameRemoveContext(ownerDid, contextId);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Resolves a petname to a list of DIDs.
 *
 * @param ownerDid - DID of the identity that owns this petname map.
 * @param name - The petname to resolve.
 * @returns Array of DID strings matching the petname.
 * @throws {ValidationError} If `ownerDid` is empty.
 */
export async function petnameResolveDid(ownerDid: string, name: string): Promise<string[]> {
  try {
    const bridge = await getBridge();
    const json = bridge.petnameResolveDid(ownerDid, name);
    return safeJsonParse(json, "petnameResolveDid") as string[];
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Resolves a petname to a list of context IDs.
 *
 * @param ownerDid - DID of the identity that owns this petname map.
 * @param name - The petname to resolve.
 * @returns Array of context ID strings matching the petname.
 * @throws {ValidationError} If `ownerDid` is empty.
 */
export async function petnameResolveContext(ownerDid: string, name: string): Promise<string[]> {
  try {
    const bridge = await getBridge();
    const json = bridge.petnameResolveContext(ownerDid, name);
    return safeJsonParse(json, "petnameResolveContext") as string[];
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Gets the petname assigned to a DID, if any.
 *
 * @param ownerDid - DID of the identity that owns this petname map.
 * @param targetDid - DID to look up.
 * @returns The petname string, or `null` if no petname is assigned.
 * @throws {ValidationError} If `ownerDid` is empty.
 */
export async function petnameGetForDid(
  ownerDid: string,
  targetDid: string,
): Promise<string | null> {
  try {
    const bridge = await getBridge();
    return bridge.petnameGetForDid(ownerDid, targetDid);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Gets the petname assigned to a context, if any.
 *
 * @param ownerDid - DID of the identity that owns this petname map.
 * @param contextId - Context ID to look up.
 * @returns The petname string, or `null` if no petname is assigned.
 * @throws {ValidationError} If `ownerDid` is empty.
 */
export async function petnameGetForContext(
  ownerDid: string,
  contextId: string,
): Promise<string | null> {
  try {
    const bridge = await getBridge();
    return bridge.petnameGetForContext(ownerDid, contextId);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// Handle Registry operations (§22.3.1)
// ---------------------------------------------------------------------------

/** Result of a handle registration. */
export interface HandleRegisterResult {
  readonly status: string;
  readonly entry_id: string | null;
}

/** Result of a handle lookup. */
export interface HandleLookupResult {
  readonly results: readonly Record<string, unknown>[];
}

/** Result of a handle deregistration. */
export interface HandleDeregisterResult {
  readonly removed: boolean;
}

/**
 * Registers a handle in a context with discovery tools.
 *
 * @param discoveryContextId - ID of the context.
 * @param handle - The handle string to register.
 * @param targetJson - JSON describing the target (`{ "type": "identity", "did": "..." }` or `{ "type": "context", "context_id": "...", "relay_urls": [...] }`).
 * @param registrantDid - DID of the registrant.
 * @param options - Optional description and tags.
 * @returns Registration result.
 * @throws {ValidationError} If `targetJson` is malformed.
 */
export async function handleRegister(
  discoveryContextId: string,
  handle: string,
  targetJson: string,
  registrantDid: string,
  options?: { description?: string; tags?: string[] },
): Promise<HandleRegisterResult> {
  try {
    const bridge = await getBridge();
    const result = bridge.handleRegister(
      discoveryContextId,
      handle,
      targetJson,
      registrantDid,
      options?.description,
      options?.tags,
    );
    return safeJsonParse(result, "handleRegister") as HandleRegisterResult;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Looks up a handle in a context with discovery tools.
 *
 * @param discoveryContextId - ID of the context.
 * @param handle - The handle string to look up.
 * @param typeFilter - Optional filter: `"identity"` or `"context"`.
 * @returns Lookup result with a `results` array of matching entries.
 */
export async function handleLookup(
  discoveryContextId: string,
  handle: string,
  typeFilter?: string,
): Promise<HandleLookupResult> {
  try {
    const bridge = await getBridge();
    const result = bridge.handleLookup(discoveryContextId, handle, typeFilter);
    return safeJsonParse(result, "handleLookup") as HandleLookupResult;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Deregisters a handle from a context with discovery tools.
 *
 * @param discoveryContextId - ID of the context.
 * @param handle - The handle string to deregister.
 * @param did - DID of the registrant requesting deregistration.
 * @returns Deregistration result with a `removed` boolean.
 */
export async function handleDeregister(
  discoveryContextId: string,
  handle: string,
  did: string,
): Promise<HandleDeregisterResult> {
  try {
    const bridge = await getBridge();
    const result = bridge.handleDeregister(discoveryContextId, handle, did);
    return safeJsonParse(result, "handleDeregister") as HandleDeregisterResult;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// Scope Registry operations (§22.3.5, ADR-043)
// ---------------------------------------------------------------------------

/** Target context for a scope entry (context-only by construction per ADR-043). */
export interface ScopeTarget {
  readonly context_id: string;
  readonly relay_urls: readonly string[];
}

/** Optional metadata attached to a scope registration (§22.3.5). */
export interface ScopeMetadata {
  readonly description: string | null;
  readonly tags: readonly string[] | null;
}

/** A single scope entry in the registry (§22.3.5). */
export interface ScopeEntry {
  readonly name: string;
  readonly target: ScopeTarget;
  readonly owner_did: string;
  readonly registered_at: number;
  readonly metadata: ScopeMetadata;
  readonly entry_id: string;
}

/** Result of a scope registration. */
export interface ScopeRegisterResult {
  readonly status: "registered" | "conflict" | "updated";
  readonly entry_id: string | null;
}

/** Result of a scope lookup. */
export interface ScopeLookupResult {
  readonly results: readonly ScopeEntry[];
}

/** Result of a scope deregistration. */
export interface ScopeDeregisterResult {
  readonly removed: boolean;
}

/**
 * Registers a scope name in a scope registry.
 *
 * @param scopeContextId - ID of the context hosting the scope registry.
 * @param name - Scope name to register (`[a-z0-9-]`, max 64 chars).
 * @param targetContextId - Context ID the scope name resolves to.
 * @param relayUrls - Relay URLs for the target context.
 * @param registrantDid - DID of the registrant.
 * @param options - Optional description and tags.
 * @returns Registration result.
 * @throws {ValidationError} If the scope name or relay URLs are invalid.
 */
export async function scopeRegister(
  scopeContextId: string,
  name: string,
  targetContextId: string,
  relayUrls: string[],
  registrantDid: string,
  options?: { description?: string; tags?: string[] },
): Promise<ScopeRegisterResult> {
  try {
    const bridge = await getBridge();
    const result = bridge.scopeRegister(
      scopeContextId,
      name,
      targetContextId,
      relayUrls,
      registrantDid,
      options?.description,
      options?.tags,
    );
    return safeJsonParse(result, "scopeRegister") as ScopeRegisterResult;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Looks up a scope name in a scope registry.
 *
 * @param scopeContextId - ID of the context hosting the scope registry.
 * @param name - The scope name to look up.
 * @returns Lookup result with a `results` array of matching scope entries.
 */
export async function scopeLookup(
  scopeContextId: string,
  name: string,
): Promise<ScopeLookupResult> {
  try {
    const bridge = await getBridge();
    const result = bridge.scopeLookup(scopeContextId, name);
    return safeJsonParse(result, "scopeLookup") as ScopeLookupResult;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Deregisters a scope name from a scope registry.
 *
 * @param scopeContextId - ID of the context hosting the scope registry.
 * @param name - The scope name to deregister.
 * @param did - DID of the registrant requesting deregistration.
 * @returns Deregistration result with a `removed` boolean.
 */
export async function scopeDeregister(
  scopeContextId: string,
  name: string,
  did: string,
): Promise<ScopeDeregisterResult> {
  try {
    const bridge = await getBridge();
    const result = bridge.scopeDeregister(scopeContextId, name, did);
    return safeJsonParse(result, "scopeDeregister") as ScopeDeregisterResult;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// Multi-path address resolution (§22.8)
// ---------------------------------------------------------------------------

/**
 * Resolves a human-readable address via multi-path resolution pipeline.
 *
 * Uses the petname layer first, then handle registries, then attestation
 * and domain layers per §22.8.
 *
 * @param ownerDid - DID of the identity whose petname map to consult.
 * @param address - The address string to resolve (e.g., `"alice@cooking-community"`).
 * @param knownContextsJson - Optional JSON object mapping context IDs to names.
 *   If omitted, uses all registered contexts with discovery tools.
 * @returns Typed address resolution results.
 * @throws {ValidationError} If `ownerDid` is empty or address parsing fails.
 */
export async function addressResolve(
  ownerDid: string,
  address: string,
  knownContextsJson?: string,
): Promise<AddressResolution[]> {
  try {
    const bridge = await getBridge();
    const raw = await bridge.addressResolve(ownerDid, address, knownContextsJson);
    const parsed = safeJsonParse(raw, "addressResolve") as Array<Record<string, unknown>>;
    return parsed.map((item): AddressResolution => {
      const trustLevel = parseTrustLevel(item.trust_level ?? item.trustLevel);
      const rawPath = (item.resolution_path ?? item.resolutionPath ?? {}) as Record<
        string,
        unknown
      >;
      const resolutionPath = parseResolutionPath(rawPath);
      if (item.type === "Identity") {
        return {
          type: "Identity",
          did: item.did as string,
          trustLevel,
          resolutionPath,
        };
      }
      return {
        type: "Context",
        contextId: (item.context_id ?? item.contextId) as string,
        relayUrls: (item.relay_urls ?? item.relayUrls ?? []) as readonly string[],
        mode: (item.mode ?? null) as string | null,
        trustLevel,
        resolutionPath,
      };
    });
  } catch (error) {
    throw mapBridgeError(error);
  }
}
