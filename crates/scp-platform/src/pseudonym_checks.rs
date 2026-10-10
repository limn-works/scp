//! The pseudonym check every software custody's tests run.

use crate::error::PlatformError;
use crate::traits::{KeyCustody, KeyType};

/// Checks that a destroyed identity derives no pseudonym (§9.10.4.A): after
/// identity `u` is destroyed, its v1 and v2 derivations fail with
/// `KeyNotFound`, and bystander identity `v` still derives the same v1 and v2
/// points it derived before the destroy.
pub async fn check_destroyed_identity_derives_no_pseudonym<C: KeyCustody>(
    custody: &C,
) -> Result<(), PlatformError> {
    let u = custody.generate_keypair(KeyType::Ed25519).await?;
    let v = custody.generate_keypair(KeyType::Ed25519).await?;
    let v_static = custody.derive_pseudonym(&v, b"ctx").await?;
    let v_rotatable = custody.derive_rotatable_pseudonym(&v, b"ctx", 7).await?;
    custody.derive_pseudonym(&u, b"ctx").await?;

    custody.destroy_key(&u).await?;

    let v1 = custody.derive_pseudonym(&u, b"ctx").await;
    assert!(matches!(v1, Err(PlatformError::KeyNotFound)), "v1: {v1:?}");
    let v2 = custody.derive_rotatable_pseudonym(&u, b"ctx", 7).await;
    assert!(matches!(v2, Err(PlatformError::KeyNotFound)), "v2: {v2:?}");

    assert_eq!(custody.derive_pseudonym(&v, b"ctx").await?, v_static);
    assert_eq!(
        custody.derive_rotatable_pseudonym(&v, b"ctx", 7).await?,
        v_rotatable
    );
    Ok(())
}
