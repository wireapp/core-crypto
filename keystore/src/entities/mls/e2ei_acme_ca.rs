use zeroize::Zeroize;

#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    serde::Serialize,
    serde::Deserialize,
    core_crypto_macros::Entity,
)]
#[zeroize(drop)]
#[entity(table_name = "e2ei_acme_ca")]
pub struct E2eiAcmeCA {
    #[entity(id)]
    pub fingerprint: Vec<u8>,
    pub content: Vec<u8>,
}
