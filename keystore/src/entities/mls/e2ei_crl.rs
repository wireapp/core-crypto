use zeroize::Zeroize;

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
pub struct X509Crl {
    #[entity(id)]
    pub distribution_point: String,
    /// A DER-encoded certificate list
    pub content: Vec<u8>,
}
