---
name: ts-sdk-bridge-error-shape
description: TS SDK trust.ts classifies bridge errors by message regex because scp.ucanValidate/eventLogQuery bypass mapBridgeError and throw plain Error
metadata:
  type: project
---

In the TS SDK (`bindings/typescript`), `SCP.ucanValidate` and `SCP.eventLogQuery` dispatch **directly** to `this.#native.*` (scp.ts) — they do NOT pass through `mapBridgeError`. So the raw napi `Error` propagates with `.message` = the Rust `Display` string `[SCP-PERM-NNNN] permission error: <UcanError> — <advice>` (NAPI format in `crates/scp-ffi/napi/src/error.rs`, advice suffix uses em-dash U+2014).

**Why:** `evaluateTrust` (trust.ts) therefore classifies failures with a message regex `/\[SCP-PERM-\d+\]/` (and `/\[SCP-CTX-\d+\]/` for event-log) + prefix matching on the stripped core, NOT `instanceof UcanPermissionError`. A test that rejects with a typed subclass would be testing a shape the bridge never produces.

**How to apply:** When reviewing trust.ts tests, the realistic mock is `Promise.reject(new Error("[SCP-PERM-3001] permission error: ..."))` — a plain Error with the full formatted message. trust.test.ts (this branch) does this correctly. Note there are TWO eventLogQuery surfaces: the `Bridge` interface one (structured EventFilter -> Event[] with parsed `payload`) vs the `SCP` class one (pre-stringified filter, raw napi objects with `eventType` camelCase + `payloadJson` string). evaluateTrust uses the SCP-class/raw path.
