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
#[entity(collection_name = "mls_keypackages")]
pub struct StoredKeypackage {
    #[entity(id)]
    pub keypackage_ref: Vec<u8>,
    #[sensitive]
    pub keypackage: Vec<u8>,
}
