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
pub struct E2eiCrl {
    #[entity(id)]
    pub distribution_point: String,
    pub content: Vec<u8>,
}
