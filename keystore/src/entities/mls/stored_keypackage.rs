use zeroize::Zeroize;

/// Entity representing a persisted `KeyPackage`
///
/// This entity cannot be updated in the DB: the primary key is the OpenMLS hash reference of the
/// key package itself, so two rows sharing a key necessarily share their contents. A save which
/// disagrees is a bug, and reports
/// [`CryptoKeystoreError::AlreadyExists`][crate::CryptoKeystoreError::AlreadyExists] instead of
/// silently replacing the stored key package.
#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
#[entity(table_name = "mls_key_packages", no_upsert)]
pub struct StoredKeyPackage {
    #[entity(id)]
    pub key_package_ref: Vec<u8>,
    #[sensitive]
    pub key_package: Vec<u8>,
}
