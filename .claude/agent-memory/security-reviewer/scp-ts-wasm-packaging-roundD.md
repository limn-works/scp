# @limn-works/scp-ts-wasm packaging (feat/scp-ts-wasm-packaging, HEAD 3d18bddcf) — Round D FINAL — CLEAN

ADR-057 wasm SDK tier. Diff origin/main..HEAD = new `bindings/typescript-wasm/` pkg + CI + capability matrix. Final double-zero confirmed CLEAN, zero new findings.

Security posture verified on complete state:
- WebCryptoCustody DID-ONLY: no `crypto.subtle.generateKey` on any prod path (only in doc comments explaining why it's absent). `create()` fails closed on missing crypto.subtle (type-identity precondition) + empty DID. sign/getPublicKey/generateKeypair/dhAgree are typed #1980 seams that THROW `[#1980]` — no fabricated signature/secret/nullifier. destroyKey no-op (no key held this slice).
- Adapters fail closed: InMemoryStorage is a legit ephemeral prod choice (embedder-selected, nothing masked — NOT a stand-in). IndexedDbStorage write-behind fault re-thrown on next sync call (`#pendingFault`), preload fault fails `open()`; FIFO single chain preserves crash-prefix invariant. No dev/test loopback socket (that's `#[cfg(test)]` in Rust crate).
- WebSocket pump: binary-only frames (string/Blob dropped via frameBytes), onFrame driver errors routed to onError WITHOUT killing pump, backoff capped by maxDelayMs (30s default), send() throws when not OPEN (never silent-drops). No injection/DoS.
- Release-only + debug-assertions pin HOLD: `WASM_PACK_PROFILE_FLAG=--release` single-sourced in wasm-build.ts; assertReleaseOnly (positive whitelist + forbidden-flag denylist) called by both build + guard against SAME argv. Root Cargo.toml:143 `[profile.release] debug-assertions=false`. Guarantees openmls decrypt debug_assert! compiled out → tampered ciphertext → typed [SCP-CRYPTO-4010], not tab-abort.
- No private-key leak: redacting panic hook (never reads payload), zero console.log in src/, error strings carry only codes.
- Publish surface tight: package.json files=[dist/,README,LICENSE], single "." export (no ./internal subpath); test seams (tests/support/stubs.ts, test-relay.ts) never shipped, none exported from index.ts.
- errors.ts single-sources ScpError + mapBridgeError from sibling `../typescript/src/errors` via `@scp-core/errors` tsconfig path alias (bundled, not npm dep); anchored code-regex prefix-dispatch (previously reviewed).
- check-node-free.ts = bounded positive invariant (one `node:` specifier scan over dist).
