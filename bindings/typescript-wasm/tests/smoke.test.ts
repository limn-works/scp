import { beforeAll, expect, test } from "bun:test";
import type { JsSocket } from "../src/index";
import { InMemoryStorage, isScpInitialized, ScpBrowserClient, scpVersion } from "../src/index";
import { loadRealWasm } from "./support/load-wasm";
import { stubCustody } from "./support/stubs";

const DID = "did:key:z6MkAlice3SurfaceExchangeFixtureKeyAAAAAAA";

/** A no-op socket: the smoke test issues no cross-client traffic. */
function nullSocket(): JsSocket {
  return { send: () => {} };
}

beforeAll(async () => {
  await loadRealWasm();
}, 120_000);

test("real wasm loads and reports a version", () => {
  expect(isScpInitialized()).toBe(true);
  expect(scpVersion()).toMatch(/^\d+\.\d+\.\d+/);
});

test("ScpBrowserClient.create drives the real wasm surface", () => {
  const client = ScpBrowserClient.create({
    custody: stubCustody(DID),
    storage: new InMemoryStorage(),
    socket: nullSocket(),
  });
  expect(client.did).toBe(DID);
  client.createContext("smoke-ctx");
  expect(client.contextIds).toEqual(["smoke-ctx"]);
  expect(client.contextStatus("smoke-ctx")).toBe("live");
  expect(client.memberDids("smoke-ctx")).toEqual([DID]);
  expect(client.eventLogLeafCount("smoke-ctx")).toBe(1n);
});
