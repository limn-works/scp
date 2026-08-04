# An App Is Not a Protocol Entity — Don't Protocol-ize a Local Permission Check

**Rule**: A capability declaration is enforced by the member's own SDK, on the member's own device. It never crosses the wire. An app has no DID, presents no signature, and app binding produces no event-log record and no protocol state. If you find yourself adding an identifier, a signature field, or a converged log entry for something that runs *inside* a member's trust boundary, stop — you are inventing a second principal that does not exist.

**Context**: Spec §8.1 has said since it was written (`1ccb61d11`, 2026-02-23):

> An app is not a protocol entity. It has no DID, is not an agent, and is not a context. The protocol has no `App` type.

Two later agent-authored commits added subsections that contradicted it four paragraphs below:

- `75b2f4ad2` (2026-03-07) added **§8.4.1 Capability Declaration Wire Format** — a JSON schema in which `app_id` is a **DID** and the declaration carries an **Ed25519 publisher signature**.
- `de00aebb2` (2026-03-08) added **§8.4.2 SDK-Level Enforcement**, which claimed *"The validated declaration is recorded in the context's event log at bind time … App binding and unbinding events are visible in the event log — silent app attachment is not possible."* That claim propagated downstream into `EventType::AppBound` / `AppUnbound`, their payloads and Merkle tags, a §25.8 test vector, an ADR-011 closure-argument source, and a new "Core Invariant" in §9.1.

Both were internally consistent and both survived ordinary review, because ordinary review checks coherence rather than premises. Neither traced to a human decision; both were written to close audit findings (`.docs/audits/spec-audit-08-10-apps-security-infra.md` `[8.4] Capability Declaration Has No Wire Format`, HIGH) that asked for a wire format for a thing that has no wire.

**Fix**: §8.4.1/§8.4.2 deleted; §8.4 restored to the human-authored conceptual contract; a §8.4.1 boundary subsection added that states the SDK-local scope explicitly and cites §8.1. The audit findings that requested the machinery were annotated with `Resolution (later)` notes so they cannot be re-actioned.

**Lesson**: Two failure modes compounded here.

1. **An audit finding is not authorization.** "The spec is missing a wire format" is a *hypothesis* that a wire format is needed. Before specifying one, check whether the data ever crosses a trust boundary. If two implementations never exchange the value, they cannot disagree about it, and there is nothing to make interoperable. Closing a HIGH finding by inventing protocol surface is worse than leaving it open.
2. **Ask who the principals are before adding a credential.** An app runs on the member's device, under the member's identity, with the member's keys. To the protocol and to every peer, an action by a member's app *is* an action by that member — the member is accountable and cannot disclaim it. Giving it a DID and a signature authenticates nothing (the member could mint any declaration they like), while making binding a converged event leaks each member's software inventory to every peer and turns a local permission check into a consensus problem.

The general form: when a downstream artifact contradicts an upstream one, the upstream one wins and the downstream one is the bug (see the artifact-flow invariant in `CLAUDE.md`). Check the section four paragraphs up before adding a subsection.
