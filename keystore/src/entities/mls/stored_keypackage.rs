use zeroize::Zeroize;

/// Entity representing a persisted `KeyPackage`
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
#[entity(table_name = "mls_keypackages")]
pub struct StoredKeyPackage {
    #[entity(id)]
    pub key_package_ref: Vec<u8>,
    #[sensitive]
    pub key_package: Vec<u8>,
}
