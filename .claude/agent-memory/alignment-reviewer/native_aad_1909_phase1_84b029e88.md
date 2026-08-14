---
name: native-aad-1909-phase1-84b029e88
description: Alignment review of #1909 Phase-1 native sender-layer AAD fix (commit 84b029e88) — ALIGNED, spec-faithful code→spec convergence
metadata:
  type: project
---

# #1909 Phase-1 Native Sender-Layer AAD Fix @ 84b029e88 (2026-06-28) — ALIGNED

Commit `84b029e88` (HEAD of branch `fix/1909-native-aad-context-string`) flips native `seal`/`open` sender-layer AES-256-GCM AAD from `hex(SHA-256(context_id))` to the RAW `context_id` UTF-8 string (BE32-len-prefixed), per spec §9.16.1 + §9.5.1. Phase 1 of #1909 (#1877 WASM↔native convergence).

**Verdict: ALIGNED, correctly scoped, spec-faithful. 0 blocking, 0 material findings.**

Key facts verified:
- §9.16.1 AAD format (09-security-model.md:1252-1258) = `BE32(len(context_id)) || context_id || BE32(len(sender_did)) || sender_did || epoch(8BE) || sequence(8BE)`. The BE32-length-prefix on `context_id` is the §9.5.1 *variable-length-bytes* encoding (line 347); a [u8;32] hash would get NO length prefix (line 348). So the spec UNAMBIGUOUSLY mandates the raw STRING, not the 32-byte hash. Native was genuinely wrong; not a defensible alternative.
- Correct artifact-flow direction (code→spec convergence, not spec-follows-code). Native was the deviant.
- Shared `scp_protocol::crypto::sender_keys::encrypt::build_sender_aad(context_id: &str, ...)` (encrypt.rs:129) already BE32-prefixes the raw string. WASM (scp-ffi/wasm state.rs:77, manager.rs:2129) feeds the raw context-id string (HashMap<String,_> key) — confirmed WASM already correct, interop claim sound.
- NO §25 KAT pins the old hex form. §25 vectors (25-test-vectors.md:512-550) only pin §9.16.2 HPKE *distribution* info/aad (raw "hpke-test-context" string already). NOTHING breaks.
- GAP (informational, correctly deferrable to full #1909): §9.16.1 sender-layer MESSAGE AEAD AAD has NO §25 cross-bridge KAT, whereas §9.16.2 distribution does. A raw-string sender-layer AAD KAT would mechanically pin native==WASM and prevent regression. Phase-1-scoped change leaves it for #1909 full; not a Phase-1 blocker.
- §6 `target_context_id`/`caller_context_id` use the raw 32-byte digest (hex on wire) — DIFFERENT field (signed receipt), unrelated to sender-layer AAD. No conflict.
- Commit message claims accurate: "WASM correctly binds the raw string", "HPKE §9.16.2 info path unchanged" (commit touches no HPKE files). No phantom provenance — §9.16.1/§9.5.1 say exactly what's claimed.
- Scope clean: native provider seal/open + threaded `context_id_str` through all `open` callers (pyo3/napi testing.rs, scp-testing fullstack node/crypto, runtime messaging_helpers:2742 production path) + test fixtures derive ctx_id from real strings. Does NOT touch WASM crypto, epoch/replay logic (replay tests only updated for new `open` signature), or §25. Phase 2 (WASM/epoch/replay convergence) correctly NOT claimed.
- seal fail-closed assertion: `context_id_bytes(inner.context_id) != *context_id` → CryptoFailed (no panic/unwrap, clippy-safe). `open` retains `ctx_id_hex` solely for sender-key STORE keying (correct — store key is local, never the AAD).

GOTCHA: the harness Read-tool served a STALE pre-commit snapshot of provider.rs (showed old hex `open` 2-arg sig) even though `git show 84b029e88:` and `git diff HEAD` (clean) proved the change IS committed/on-disk. ALWAYS verify crypto-path edits with `git show <sha>:file` / `git grep <sha>`, not the Read tool, when line numbers don't match the diff.
