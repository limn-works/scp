# OpenMLS Key Material Lifecycle (SCP-171)

**Discovery**: OpenMLS manages cryptographic key material deletion internally. The `EpochGraceStore` does NOT hold key material -- it only tracks epoch numbers and grace window deadlines.

**Key facts (openmls 0.8)**:

1. `MlsGroup::merge_staged_commit()` and `merge_pending_commit()` automatically call `delete_previous_epoch_keypairs()`, removing the previous epoch's encryption key pairs from the storage provider.
2. Past epoch message secrets are managed by OpenMLS's `MessageSecretsStore`, a bounded `VecDeque` controlled by `max_past_epochs` config (default: 0, meaning no past epoch secrets are retained).
3. Forward secrecy of cryptographic key material is enforced by OpenMLS, not by the SCP layer.

**Implication**: When adding security features around epoch management:
- Do NOT assume you need to explicitly delete key material after epoch expiry -- OpenMLS does this.
- The `EpochGraceStore`'s role is to tell the SCP decrypt path whether to *attempt* decryption, not to manage keys.
- If you need to react to epoch closures (logging, metrics), use the `OnEpochExpired` callback on `EpochGraceStore`.
- The `MlsGroupCreateConfig` default of `max_past_epochs = 0` means SCP groups retain zero past epoch secrets. Do not change this without careful security review.

**Verified by tests**: `forward_secrecy_old_epoch_ciphertext_undecryptable_after_advance` and `forward_secrecy_survives_multiple_epoch_advances` in `ratchet.rs`.
