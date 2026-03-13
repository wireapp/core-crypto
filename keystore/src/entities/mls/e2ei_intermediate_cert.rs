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
pub struct E2eiIntermediateCert {
    // key to identify the CA cert; Using a combination of SKI & AKI extensions concatenated like so is suitable:
    // `SKI[+AKI]`
    #[entity(id)]
    pub ski_aki_pair: String,
    pub content: Vec<u8>,
}
