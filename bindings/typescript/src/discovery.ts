/**
 * Discovery module for the SCP TypeScript SDK.
 *
 * Provides functions for parsing SCP addresses, creating discovery queries,
 * normalizing addresses, discovering contexts from DIDs or `scp://` URIs,
 * and resolving addresses to typed `AddressResolution` results.
 *
 * See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).
 */

import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";
import { safeJsonParse } from "./internal/json-utils";
import type { AddressResolution, ResolutionLayer, ResolutionPath, TrustLevel } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A parsed SCP address. */
export interface ParsedAddress {
  /** Address type: `"discovery_handle"`, `"domain_handle"`, `"attestation_handle"`, or `"unscoped"`. */
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
 * Parses a `ResolutionPath` from a snake_case bridge JSON object.
 */
function parseResolutionPath(raw: Record<string, unknown>): ResolutionPath {
  return {
    layer: (raw.layer as ResolutionLayer) ?? "domain",
    source: (raw.source as string) ?? "unknown",
    sourceId: (raw.source_id ?? raw.sourceId ?? null) as string | null,
    resolvedAt: (raw.resolved_at ?? raw.resolvedAt ?? 0) as number,
  };
}

/**
 * Parses a trust level from the bridge JSON. The NAPI bridge emits trust
 * levels as `{ "kind": "..." }` objects (discriminated unions per §22.7).
 * The `multi_layer_corroborated` variant additionally carries `sources`.
 */
function parseTrustLevel(raw: unknown): TrustLevel {
  if (raw != null && typeof raw === "object" && "kind" in raw) {
    const obj = raw as Record<string, unknown>;
    const kind = obj.kind as string;
    if (kind === "multi_layer_corroborated") {
      const rawSources = (obj.sources ?? []) as Array<Record<string, unknown>>;
      return {
        kind: "multi_layer_corroborated",
        sources: rawSources.map(parseResolutionPath),
      };
    }
    return { kind } as TrustLevel;
  }
  // Fallback for unexpected input.
  return { kind: "unverified" };
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
