# Bug Catcher Memory

Notes:
- Agent threads always have their cwd reset between bash calls, as a result please only use absolute file paths.
- In your final response always share relevant file names and code snippets. Any file paths you return in your response MUST be absolute. Do NOT use relative paths.
- For clear communication with the user the assistant MUST avoid using emojis.
- Do not use a colon before tool calls. Text like "Let me read the file:" followed by a read tool call should just be "Let me read the file." with a period.

## SCP Project Knowledge

### Key Files
- `/Users/alec/Developer/limn/scp/.docs/specs/` — Full protocol specs.
- `/Users/alec/Developer/limn/scp/.docs/architecture.md` — Build document (~1024 lines).
- `/Users/alec/Developer/limn/scp/.docs/sketch.md` — API surfaces (~1477 lines).
- `/Users/alec/Developer/limn/scp/.docs/specs/00-open-questions.md` — Open and resolved design decisions.
- `/Users/alec/Developer/limn/scp/.docs/adrs/phase-2.md` — Phase 2 ADRs (context, roles, tools, events, transport).

### Known Bug Patterns (Feb 2026 Review)
- Stale cross-references from A2A removal (provenance discoveryMethod, resolved decisions)
- HPKE key lifecycle issue in sender-side key layer (MLS LeafNode keys rotate)
- Strict sequence gap rejection vs multi-relay and offline delivery
- Discovery context MLS scaling (MLS does not scale to open-join 10K+ contexts)
- Cover traffic fingerprinting when disabled

### Known Bug Patterns (Feb 2026 Review — PR #4, commit b66c457)
- **Governance symmetry gaps:** Self-approval check in approve_registration not carried to reject_registration or revoke_bridge. Pattern: auth guards added to one path but not parallel paths.
- **Dead ownership checks:** HashMap keyed by DID makes ownership check (entry.did != requester_did) tautological when requester_did is used as lookup key. Pattern: using same value for both lookup and authorization.
- **Misleading event fields:** BridgeRegistrationEvent.governance_did forced to operator DID for Requested events (no governance actor exists). Pattern: non-optional fields that don't apply to all enum variants.
- **Disjoint set invariant not enforced:** Writers/readers Vecs in DiscoveryContext can overlap — no cross-list dedup. Pattern: parallel collections that should be mutually exclusive but aren't validated.
- **Test masking wrong error path:** agent_update_rejects_ownership_mismatch test passes with NotRegistered instead of OwnershipMismatch. Pattern: test asserts on a supertype error that masks the real code path.
