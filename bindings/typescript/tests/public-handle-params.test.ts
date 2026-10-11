/**
 * Structural test: every public `SCP` method takes the SDK handle objects the
 * SDK hands out (`Context`, `Identity`, `TransportManager`, `McpServer`,
 * `McpClient`), never a raw native handle.
 *
 * The test reads `src/scp.ts` with the TypeScript compiler API and resolves
 * each parameter's type with the type checker, so an alias that erases to
 * `unknown` (`type NativeMcpServerHandle = unknown`) fails the same way a
 * literal `unknown` does. A parameter fails when its name says it carries a
 * handle and its type is `unknown`, `any`, absent, or a raw bridge handle type.
 *
 * ADR-052 (unified construction pattern, `.docs/adrs/phase-2.md`) asks for one
 * shape across every binding; Swift and Kotlin take `ContextHandle` and
 * `TransportManager` objects, so the TypeScript surface takes `Context` and
 * `TransportManager`.
 */

import { describe, expect, test } from "bun:test";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const SCP_SOURCE = fileURLToPath(new URL("../src/scp.ts", import.meta.url));

/**
 * The parameter names that carry a handle. The criterion is "the parameter
 * passes a handle the SDK hands out"; these names are the indicators the
 * structural test can read.
 */
const HANDLE_PARAM = /^(handle|context|identity|manager|server|client)$|(Handle|Context|Identity)$/;

/** Raw bridge handle types that must never appear on a public parameter. */
const RAW_HANDLE_TYPE = /\b(Bridge\w*Handle|Native\w*Handle|Napi\w+)\b/;

interface Violation {
  readonly method: string;
  readonly param: string;
  readonly type: string;
}

function isPublicMethod(member: ts.ClassElement): member is ts.MethodDeclaration {
  if (!ts.isMethodDeclaration(member)) return false;
  if (ts.isPrivateIdentifier(member.name)) return false;
  const name = member.name.getText();
  if (name.startsWith("_")) return false;
  const modifiers = ts.getCombinedModifierFlags(member);
  return (modifiers & (ts.ModifierFlags.Private | ts.ModifierFlags.Protected)) === 0;
}

/** Returns every handle parameter of a public `SCP` method that violates the rule. */
export function findHandleParamViolations(sourcePath: string): readonly Violation[] {
  const program = ts.createProgram([sourcePath], {
    strict: true,
    target: ts.ScriptTarget.ESNext,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    noEmit: true,
    skipLibCheck: true,
    types: [],
  });
  const checker = program.getTypeChecker();
  const source = program.getSourceFile(sourcePath);
  if (source === undefined) throw new Error(`cannot read ${sourcePath}`);

  const scpClass = source.statements.find(
    (s): s is ts.ClassDeclaration => ts.isClassDeclaration(s) && s.name?.text === "SCP",
  );
  if (scpClass === undefined) throw new Error("class SCP not found in src/scp.ts");

  const violations: Violation[] = [];
  for (const member of scpClass.members) {
    if (!isPublicMethod(member)) continue;
    const method = member.name.getText();
    for (const param of member.parameters) {
      const name = param.name.getText();
      if (!HANDLE_PARAM.test(name)) continue;
      const annotation = param.type?.getText() ?? "<none>";
      const resolved = checker.getTypeAtLocation(param);
      const erased = (resolved.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) !== 0;
      if (param.type === undefined || erased || RAW_HANDLE_TYPE.test(annotation)) {
        violations.push({ method, param: name, type: annotation });
      }
    }
  }
  return violations;
}

describe("public SCP handle parameters", () => {
  test("no public SCP method takes a handle typed unknown, any, or a raw bridge type", () => {
    const violations = findHandleParamViolations(SCP_SOURCE);
    expect(violations.map((v) => `${v.method}(${v.param}: ${v.type})`)).toEqual([]);
  });

  test("the scan reaches the methods that take a Context", () => {
    // Positive control: the rule would pass vacuously if the scan found no
    // handle parameters at all, so pin that it reads the context surface.
    const program = ts.createSourceFile(
      SCP_SOURCE,
      ts.sys.readFile(SCP_SOURCE) ?? "",
      ts.ScriptTarget.ESNext,
      true,
    );
    const scpClass = program.statements.find(
      (s): s is ts.ClassDeclaration => ts.isClassDeclaration(s) && s.name?.text === "SCP",
    );
    const contextSend = scpClass?.members.find(
      (m): m is ts.MethodDeclaration =>
        ts.isMethodDeclaration(m) && m.name.getText() === "contextSend",
    );
    expect(contextSend?.parameters[0]?.name.getText()).toBe("context");
    expect(contextSend?.parameters[0]?.type?.getText()).toBe("Context");
  });

  test("the scan flags a handle parameter typed unknown", () => {
    // Negative control: feed the detector a case that must fail.
    const dir = fileURLToPath(new URL("./", import.meta.url));
    const probe = `${dir}.public-handle-params-probe.ts`;
    ts.sys.writeFile(
      probe,
      [
        "type Erased = unknown;",
        "export class SCP {",
        "  contextSend(handle: unknown): void {}",
        "  mcpServerStop(server: Erased): void {}",
        "  contextLeave(context: BridgeContextHandle): void {}",
        "  contextJoin(context): void {}",
        "  #privateOk(handle: unknown): void {}",
        "  _internalOk(handle: unknown): void {}",
        "  okString(identityDid: string): void {}",
        "}",
        "interface BridgeContextHandle { contextId: string }",
      ].join("\n"),
    );
    try {
      const found = findHandleParamViolations(probe).map((v) => `${v.method}.${v.param}`);
      expect(found).toEqual([
        "contextSend.handle",
        "mcpServerStop.server",
        "contextLeave.context",
        "contextJoin.context",
      ]);
    } finally {
      ts.sys.deleteFile?.(probe);
    }
  });
});
