use zeroize::Zeroize;

/// This type exists so that we can efficiently search for the children of a given group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::From, derive_more::Into, derive_more::AsRef)]
pub struct ParentGroupId<'a>(&'a [u8]);

/// Entity representing a persisted `MlsGroup`
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
#[entity(table_name = "mls_groups")]
#[sensitive]
pub struct PersistedMlsGroup {
    pub id: Vec<u8>,
    pub state: Vec<u8>,
}
