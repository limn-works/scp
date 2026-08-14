# MLS group_context scp_context_params extension (0xFF02) — FFI-02, spec §5.13.3

scp-mls glue landed on branch feat/adr049-2j-ffi-slice (commit 5c19deb26).
Reads/writes ScpContextExtension (scp_protocol::context, RFC 8785 JCS bytes)
into an MLS group's group_context.

## Files
- crates/scp-mls/src/context_extension.rs (new): make_context_params_extension,
  group_context_extensions -> Extensions<GroupContext>, extract_context_params,
  scp_capabilities_with_context_params (declares BOTH 0xFF01+0xFF02),
  impl ScpMlsGroup::group_context_extension (reader).
- group.rs: create_group_with_context (writer), generate_key_package_with_context_params
  (joiner KP), + private create_group_inner / generate_key_package_inner shared cores.
  Existing create_group_with_wrapping_key / generate_key_package_with_wrapping_key
  signatures + behavior UNCHANGED (scp-runtime imports them; do not rename).

## Key OpenMLS 0.8.1 behavior (verified empirically + in source)
- 0xFF02 is a GROUP_CONTEXT extension (Extensions<GroupContext>), not a LeafNode
  ext like 0xFF01. Config: MlsGroupCreateConfig::builder().with_group_context_extensions(exts)
  returns Self (NOT Result). Read via MlsGroup::extensions() -> &Extensions<GroupContext>.
- ExtensionType::Unknown(_) is_valid_in_group_context() == true. GroupContext NOT in
  openmls::prelude; import openmls::group::GroupContext explicitly.
- SURPRISE (valn0502, public_group/validation.rs:395): an added member's LEAF must
  support (advertise in Capabilities) EVERY extension in the group's group_context.
  So a context-group joiner's KeyPackage leaf MUST declare 0xFF02 or add_member fails
  with AddMemberFailed("The capabilities of the add proposal are insufficient for this
  group."). This is enforced ALWAYS, independent of RequiredCapabilities. => joiners
  must use generate_key_package_with_context_params (declares 0xFF02); a wrapping-key-
  only KP (0xFF01 only) is rejected. Regression test pins this.
- Deliberately DO NOT add 0xFF02 to RequiredCapabilitiesExtension: valn0502 already
  forces per-member support, so it'd be redundant and pull 0xFF02 into the stricter
  GroupContextExtensions-proposal machinery. (My earlier assumption that unknown gc
  exts pass joiners freely was WRONG — corrected in module docs.)
- group_context extension survives later epoch-advancing commits (add member #2, joiner
  processes the commit): verified by test context_extension_survives_later_commits.

## Soundness
- Extension bytes = ScpContextExtension::to_canonical_bytes() (JCS). group_context is
  folded into the MLS key schedule + confirmation tag, so committed params are bound to
  the group and read identically by every member (this is the FFI-02 fix substrate).
  verify_against (rules 2-6) is called by scp-runtime steps 4/5, NOT here.
- 117 scp-mls tests pass; scp-runtime builds.
