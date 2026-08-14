---
name: outlet-pr3-collapse-onto-main
description: Outlet re-port PR3 rebase-collapse onto origin/main (feat/outlet-report-pr3 @2f45eefa6) — holistic crypto double-zero verdict
metadata:
  type: project
---

# Outlet PR3 collapse onto main (feat/outlet-report-pr3 @2f45eefa6, base origin/main 0f26442ac) — SOUND

Full re-port landing on main (diff origin/main...HEAD, 284 files). Prior algebra review was @1ffe476e5 (see [[outlet-pr3-capability-redesign]]). This pass = holistic + rebase-integration deltas ONLY.

## VERDICT: crypto SOUND, no new finding. APPROVE.

- **Core algebra files BYTE-IDENTICAL to prior-verified 1ffe476e5** (`git diff 1ffe476e5 HEAD` = 0 lines for caveats.rs, validate.rs, mint.rs, outlets/hash.rs). So narrow() monotone attenuation, origin_kind enforcement (mixed-family reject / rule-4 (None,None)→OriginKindUnspecified / leaf stem-consistency), and REGISTRATION-V2/RFC-6962 preimages carry over UNCHANGED-SOUND. mint still hardcodes nb:None (latent-not-live value-caveat gap preserved).
- **Rebase-collapse commit 2f45eefa6 = 3 files, tiny.** (1) broadcast/mod.rs test-only ValidationContext literals +caveat_resolver:&NoCaveatResolver (subscribe/register tests, non-outlet → correct). (2) handlers/broadcast.rs: ONE production site handle_subscribe_broadcast:231 +NoCaveatResolver — subscribe is NOT outlet-invocation → CORRECT (child_is_outlet_edge=false so (None,None) arm doesn't reject; messages:read gate). Plus test nb:None on a UcanPayload literal. (3) persistence_ordering.rs test: Capability::new(...)→.expect("known capability") for messages:read/write+governance:propose (grant-set ceiling, known caps, no panic).
- **caveat_resolver classification — FULL tree audit, ZERO misclassification.** Every production outlet-invocation site → TokenNbCaveatResolver: all 6 callers of validate_outlet_invocation_ucan (napi/outlets.rs:63, ffi/outlets.rs:365, mcp.rs:752, uniffi bridge.rs:4024+4612) + saga.rs:1226 (generic validate_ucan but required_cap=CapabilityUri::new("outlet_call",..) built at saga.rs:1177 → genuine outlet-invoke gate, correct asymmetric pairing). Every generic validate/evaluate + broadcast → NoCaveatResolver: the TWO rebase-new uniffi sites bridge.rs:14709 (validate_ucan) + 14872 (evaluate_ucan) are generic per-context 11-step pipeline, each carries documenting comment, correct. napi/ucan.rs:323/433, ffi/ucan.rs:336/471 generic, correct. invoke.rs:1860 NoCaveatResolver is a NEGATIVE TEST (messages:write token rejected for outlet invoke; nb=None so resolver immaterial).
- **Signing domains.** SCP-TOOL-NNNN in diff are ERROR CODES not preimages. In-scope signing domain SCP-OUTLET-REGISTRATION-V2 = single const hash.rs:62, byte-consistent (registry.rs:1726 len-calc, registration.rs tests). SCP-TOOL-REGISTRATION-V1→V2 is intended domain version-bump (registration struct redesigned) — sound pre-release, distinct separator, no cross-version ambiguity. New streaming/credit domains (SCP-OUTLET-CHUNK-V1/CHUNK-SIG-V1/CREDIT-V1/CAVEAT-BIND-V1/CANCEL-V1 stream.rs; HOP-PAD-V1 errors.rs; IKM-ROTATE-V1 interface.rs) are const-defined, mutually distinct, belong to DEFERRED streaming slices (out of scope). NOTE stream.rs re-inlines b"..." literals at hash sites (1767/1814/1950/2030) alongside the const defs — byte-identical, minor hygiene only, deferred code.
- **§6.2.4 saga:** required_cap=outlet_call (1177), NoopNonceTracker justified (re-validate stored proof, no false replay), confused-deputy = presenting_agent_did=caller_did + step-5 AudienceMismatch. Escrow/nonce untouched by rename (core byte-identical).

Prior HIGH (post-input runtime caveat enforcement absent) is now EXPLICITLY DEFERRED — spec §7.3.8 marks it deferred AND task-giver scopes value-caveat runtime enforcement/streaming/cross-context as documented-later-slices, mint emits ONLY origin_kind. Not a finding for this pass.
