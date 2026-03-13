use zeroize::Zeroize;

/// Entity representing a list of [StoredEncryptionKeyPair]
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
#[entity(collection_name = "mls_epoch_encryption_keypairs")]
pub struct StoredEpochEncryptionKeypair {
    pub id: Vec<u8>,
    #[sensitive]
    pub keypairs: Vec<u8>,
}
