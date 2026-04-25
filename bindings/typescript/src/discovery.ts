/**
 * Discovery module for the SCP TypeScript SDK.
 *
 * Provides address parsing, query construction, address normalization,
 * and context discovery via the addon-level free functions
 * (`discovery_parse_address`, `discovery_create_query`,
 * `discovery_normalize_address`, `context_discover`) which are pure
 * helpers with no bridge-instance state — they remain free functions
 * on the NAPI addon.
 *
 * Petname / handle / scope / address-resolve wrappers moved onto the
 * {@link SCP} class in Phase 4 PR 4 (#1549, ADR-048):
 *
 * - `scp.petnameSet(...)`, `scp.petnameRemove(...)`,
 *   `scp.petnameResolveDid(...)`, `scp.petnameResolveContext(...)`,
 *   `scp.petnameGetForDid(...)`, `scp.petnameGetForContext(...)` —
 *   plus the `*Context` variants for context petnames.
 * - `scp.handleRegister(...)`, `scp.handleLookup(...)`,
 *   `scp.handleDeregister(...)`.
 * - `scp.scopeRegister(...)`, `scp.scopeLookup(...)`,
 *   `scp.scopeDeregister(...)`.
 * - `scp.addressResolve(...)`.
 *
 * The free-function shims that predated ADR-048 were deleted in the
 * same commit. This module keeps the pure helpers.
 *
 * See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).
 */

import { mapBridgeError, ValidationError } from "./errors";
import { getBridge } from "./internal/bridge";
import { safeJsonParse } from "./internal/json-utils";
import type { SCP } from "./scp";
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
  "HandleRegistryVerified",
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
 *
 * @throws {ValidationError} On unrecognized variants or unexpected input types.
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
// Pure addon helpers (no SCP-class equivalent — no bridge-instance state)
// ---------------------------------------------------------------------------

/**
 * Parses an SCP address string into its components.
 *
 * @param address - The address string to parse (e.g., `"alice@cooking-community"`).
 * @returns The parsed address object.
 * @throws {ValidationError} If the address is malformed.
 */
export async function parseAddress(scp: SCP, address: string): Promise<ParsedAddress> {
  try {
    const bridge = await getBridge(scp);
    const result = bridge.discoveryParseAddress(address);
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
export async function createQuery(
  scp: SCP,
  options?: {
    capabilities?: string[];
    keywords?: string[];
    minHistorySecs?: number;
  },
): Promise<string> {
  try {
    const bridge = await getBridge(scp);
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
export async function normalizeAddress(scp: SCP, address: string): Promise<string> {
  try {
    const bridge = await getBridge(scp);
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
export async function discoverContexts(scp: SCP, query: string): Promise<DiscoveryResult[]> {
  try {
    const bridge = await getBridge(scp);
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
 * Wraps {@link discoverContexts} and returns `AddressResolution[]` with the
 * discriminated union structure matching §22.2.1.
 *
 * @param query - A DID string or `scp://` URI.
 * @returns Typed address resolution results.
 * @throws {ContextError} If discovery fails.
 * @throws {ValidationError} If the query is neither a DID nor an `scp://` URI.
 */
export async function resolveAddress(scp: SCP, query: string): Promise<AddressResolution[]> {
  const results = await discoverContexts(scp, query);
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
