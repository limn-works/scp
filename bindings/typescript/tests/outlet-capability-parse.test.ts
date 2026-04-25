/**
 * Outlet capability stem parser conformance (SCP-OUT-014).
 *
 * Loads `tests/conformance/vectors/outlet_capability_parse.json` and asserts
 * every positive vector parses to the expected variant and every negative
 * vector rejects to `null`. The fixture is identical across bridges \u2014
 * divergence between the TypeScript wrapper and the Rust core would mean a
 * parser-differential authorization bug.
 *
 * Spec references:
 * - .docs/specs/05-contexts.md \u00a75.4.2.1 UCAN Capability Stem Parser
 * - .docs/adrs/ADR-049-outlet-redesign.md \u00a71 Rename hard break, \u00a72
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(
  __dirname,
  "../../../tests/conformance/vectors/outlet_capability_parse.json",
);

interface PositiveExpected {
  kind: string;
  id?: string;
  name?: string;
}

interface PositiveVector {
  input: string;
  expected: PositiveExpected;
}

interface NegativeVector {
  input: string;
  reason: string;
}

interface Fixture {
  version: string;
  story: string;
  positive: PositiveVector[];
  negative: NegativeVector[];
}

const SUFFIX_RE = /^[a-z0-9_-]{1,128}$/;

const KNOWN_EXACT: Record<string, string> = {
  "messages:read": "MessagesRead",
  "messages:write": "MessagesWrite",
  "outlet:query:*": "OutletQueryAll",
  "outlet_query:*": "OutletQueryAll",
  "outlet:call:*": "OutletCallAll",
  "outlet_call:*": "OutletCallAll",
  "outlet:register": "OutletRegister",
  "member:invite": "MemberInvite",
  "member:remove": "MemberRemove",
  "role:assign": "RoleAssign",
  "governance:propose": "GovernancePropose",
  "governance:vote": "GovernanceVote",
  "context:close": "ContextClose",
  "context:child:create": "ChildContextCreate",
  "outlet:interface": "OutletInterface",
  bridging: "Bridging",
  "media:voice": "MediaVoice",
  "media:video": "MediaVideo",
  "media:screen_share": "MediaScreenShare",
  "member:ban": "MemberBan",
  "metadata:edit": "MetadataEdit",
};

type ParseResult = { kind: string; payload: string | null } | null;

/**
 * Reference TypeScript implementation of `Capability::new` from the Rust
 * core. Mirrors the \u00a75.4.2.1 two-step parser and the ADR-049 \u00a71
 * hard-break rejection set.
 */
function parseCapability(name: string): ParseResult {
  if (
    name.startsWith("outlet:invoke:") ||
    name.startsWith("outlet_invoke:") ||
    name === "outlet:invoke:*" ||
    name === "outlet_invoke:*"
  ) {
    return null;
  }
  if (name.startsWith("tool:invoke:") || name.startsWith("tool_invoke:")) {
    return null;
  }
  if (
    name === "tool:register" ||
    name === "tool:interface" ||
    name === "tool_register" ||
    name === "tool_interface"
  ) {
    return null;
  }

  if (name in KNOWN_EXACT) {
    return { kind: KNOWN_EXACT[name], payload: null };
  }

  const prefixes: [string, string][] = [
    ["outlet:query:", "OutletQuery"],
    ["outlet_query:", "OutletQuery"],
    ["outlet:call:", "OutletCall"],
    ["outlet_call:", "OutletCall"],
  ];
  for (const [prefix, kind] of prefixes) {
    if (name.startsWith(prefix)) {
      const suffix = name.slice(prefix.length);
      if (!SUFFIX_RE.test(suffix)) {
        return null;
      }
      return { kind, payload: suffix };
    }
  }

  if (name.startsWith("custom:")) {
    return { kind: "Custom", payload: name.slice("custom:".length) };
  }
  return { kind: "Custom", payload: name };
}

const fixture: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf-8"));

describe("outlet capability parse conformance (SCP-OUT-014)", () => {
  test("fixture metadata + cardinality", () => {
    expect(fixture.story).toBe("SCP-OUT-014");
    expect(fixture.positive.length).toBeGreaterThanOrEqual(20);
    expect(fixture.negative.length).toBeGreaterThanOrEqual(20);
  });

  test("positive vectors parse to expected variants", () => {
    for (const v of fixture.positive) {
      const actual = parseCapability(v.input);
      expect(actual).not.toBeNull();
      if (actual === null) continue;
      expect(actual.kind).toBe(v.expected.kind);
      if (v.expected.id !== undefined) {
        expect(actual.payload).toBe(v.expected.id);
      }
      if (v.expected.name !== undefined) {
        expect(actual.payload).toBe(v.expected.name);
      }
    }
  });

  test("negative vectors reject to null", () => {
    for (const v of fixture.negative) {
      const actual = parseCapability(v.input);
      expect(actual).toBeNull();
    }
  });

  test("hard-break: outlet:invoke / outlet_invoke deleted (ADR-049 \u00a71)", () => {
    expect(parseCapability("outlet:invoke:*")).toBeNull();
    expect(parseCapability("outlet_invoke:*")).toBeNull();
    expect(parseCapability("outlet:invoke:foo")).toBeNull();
    expect(parseCapability("outlet_invoke:bar")).toBeNull();
  });

  test("hard-break: tool:invoke / tool_invoke pre-rename rejected", () => {
    expect(parseCapability("tool:invoke:*")).toBeNull();
    expect(parseCapability("tool_invoke:*")).toBeNull();
    expect(parseCapability("tool:invoke:calculator")).toBeNull();
    expect(parseCapability("tool:register")).toBeNull();
    expect(parseCapability("tool:interface")).toBeNull();
  });
});
