# SCP Licensing

SCP uses a multi-license structure designed to maximize adoption while protecting against commoditization of infrastructure. No additional terms under AGPL v3 Section 7 are applied.

## License Structure

| Component | License | SPDX | Rationale |
|---|---|---|---|
| Protocol specification (`.docs/specs/`) | [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) | — | Open protocol. Anyone can implement SCP. Attribution required. |
| Client SDK (`scp-core`, `scp-ffi`, `scp-transport`, `scp-platform`, `scp-mcp`, `scp-media`, `scp-testing`, bindings) | [Apache 2.0](LICENSE-APACHE) | `Apache-2.0` | Zero-friction adoption for agent builders and app developers. Patent grants included. |
| Application node (`scp-node`) | [AGPL v3 only](LICENSE-AGPL) | `AGPL-3.0-only` | Network copyleft. Operators offering SCP relay as a service must share source or obtain a commercial license. No "or later" clause. |
| Commercial use | [Limn Commercial License](https://limn.works/licensing) | — | Available for operators who cannot accept AGPL terms. |

## What This Means

### If you're building an app or agent using SCP

Use the SDK freely. `scp-core`, `scp-ffi`, `scp-transport`, and all language bindings are Apache 2.0. You can use them in open source or proprietary software, commercial or non-commercial, with no copyleft obligations. Keep the license notice and any NOTICE file intact, and mark files you modify.

### If you're running a relay for yourself, friends, or a community

You can run `scp-node` as-is under AGPL v3. If you haven't modified it and are only providing it as a network service (not distributing the binary), you have no source obligations — the source is already public in this repository. If you distribute the binary (e.g., in a Docker image), you must make the corresponding source available to recipients. If you've made modifications, share your modified source with the people using your relay.

### If you're offering SCP relay as a commercial service

AGPL v3 requires you to make your complete relay source available to all users of your service. If you'd prefer not to, contact [Limn](https://limn.works/licensing) for a commercial license.

### If you're implementing SCP from scratch

The protocol specification is CC-BY 4.0. You can write your own implementation in any language under any license. Attribution to SCP and Limn is required.

## FAQ

**Q: Can I use the SCP SDK in a proprietary application?**
Yes. The SDK crates (`scp-core`, `scp-ffi`, `scp-transport`, `scp-platform`, `scp-mcp`, `scp-media`, `scp-testing`, and all language bindings) are Apache 2.0. You can use them in closed-source, commercial software without restriction. Include the license notice and you're done.

**Q: Can I run a relay for my friends without open-sourcing anything?**
Yes, in most cases. If you're running unmodified `scp-node` as a service and not distributing the binary, the source is already public — this repository. Point anyone who asks to the specific version you're running. If you distribute the binary (e.g., a Docker image), you must provide corresponding source to recipients per AGPL Sections 4-6. If you've modified the code, you must make your modifications available to users who interact with your relay over the network (AGPL Section 13). You do not need to publish anything to the general public.

**Q: What triggers the AGPL's source-sharing requirement?**
Two separate triggers exist. *Distribution* (Sections 4-6): if you convey the `scp-node` binary to others, you must provide corresponding source. *Network interaction* (Section 13): if users interact with your *modified* version over a network, you must offer them the source. Running unmodified `scp-node` as a service triggers neither — the source is already public. We recommend pinning to a specific tagged release and pointing users to that tag.

**Q: Do configuration changes count as "modifications"?**
Changing environment variables, config files, or runtime flags does not modify the source code and is not a "modification" under the AGPL. However, writing custom plugins, transport adapters, or storage backends that link against `scp-node` code (not just the Apache 2.0 SDK crates) does create a combined work that must be licensed under AGPL v3.

**Q: What about plugins or extensions for the relay?**
Code that links against `scp-node` (AGPL) becomes part of a combined work under AGPL Section 5(c) and must be licensed under AGPL v3. Code that only depends on Apache 2.0 SDK crates (`scp-core`, `scp-transport`, etc.) is not affected by the AGPL. If your extension only uses the SDK's public APIs, it stays under whatever license you choose.

**Q: Does AGPL apply if I just use the SDK to connect to someone else's relay?**
No. The SDK is Apache 2.0. AGPL only applies to `scp-node` (the application node). Connecting to a relay as a client has no copyleft implications.

**Q: What if I want to build a competing relay implementation from scratch?**
The protocol specification is CC-BY 4.0. You can implement a conforming relay in any language under any license you choose. AGPL only applies to code derived from `scp-node`.

**Q: What does the commercial license cover?**
The commercial license lets you run a modified `scp-node` (or derivative) as a service without AGPL's source-sharing obligations. It also provides enterprise support, SLAs, and indemnification. Contact [Limn](https://limn.works/licensing) for terms.

**Q: Do I need a CLA to contribute?**
Yes. Contributors sign a Contributor License Agreement granting Limn the right to offer contributions under both AGPL and commercial licenses. This means Limn can include your contributions in the commercially-licensed version. This is standard practice for dual-licensed projects (MySQL, Qt, GitLab, MongoDB, MinIO) and is a prerequisite for the dual-licensing model to function. Without it, we couldn't offer the commercial license option.

**Q: Why not just use MIT or Apache 2.0 for everything?**
Permissive licenses allow cloud providers to take the relay implementation, run it as a managed service, and contribute nothing back. AGPL on the relay ensures that operators either contribute their improvements to the community or support SCP's development through a commercial license. The SDK remains fully permissive because adoption friction there directly hurts the ecosystem.

**Q: Why not use AGPL for the SDK too?**
AGPL on the SDK would require every proprietary application using SCP to release its source code. That kills adoption in exactly the ecosystem we're building for — agent builders, startups, and enterprises integrating SCP into their products. Apache 2.0 on the SDK removes all friction.

**Q: Why "AGPL v3 only" and not "AGPL v3 or later"?**
The "only" qualifier means `scp-node` is licensed under exactly AGPL version 3, with no automatic upgrade to future versions. This gives Limn and the community explicit control over any future license version transitions rather than delegating that decision to the FSF.

**Q: I'm a solo developer / small nonprofit / educational institution. Do I need a commercial license?**
Almost certainly not. If you're running an unmodified relay as a service, the source is already public. If you've modified the relay, you only need to share source with your users, not the public. The commercial license exists for operators who run proprietary relay forks as a commercial service and don't want to share source.

## License Files

- [LICENSE-APACHE](LICENSE-APACHE) — Apache License 2.0 (SDK crates and bindings)
- [LICENSE-AGPL](LICENSE-AGPL) — GNU Affero General Public License v3.0 only (application node)
- Protocol specification: [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/)

## Attribution

SCP is created and maintained by [Limn](https://limn.works). The protocol specification, reference implementation, and all documentation are Copyright Limn Works LLC unless otherwise noted.
