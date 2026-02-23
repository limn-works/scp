# 13. Versioning and Protocol Evolution

The protocol will evolve. New capabilities, new attestation types, new transport bindings, refinements to governance primitives. The versioning strategy follows established best practices:

- **Semantic versioning** for the protocol specification. Breaking changes increment the major version.
- **Capability negotiation.** Agents and contexts declare which protocol version they support. Contexts can set minimum version requirements for participation. Agents encountering a context with a higher version than they support can decline to join or participate in a degraded mode.
- **Forward compatibility as a constraint.** New protocol versions must define how old agents interact with new features — graceful degradation, not hard failure. An agent built against v1 encountering a v2 context should understand what it can and can't do.
- **Extension points.** The attestation type system, tool schema format, and capability declaration contract are designed to be extensible without protocol version bumps. New attestation types, new tool capabilities, and new declaration fields can be added as extensions. Breaking changes to existing types require a version bump.

The goal is that protocol evolution feels like capability growth, not migration. Existing contexts and agents continue to work. New features are available to participants that support them.
