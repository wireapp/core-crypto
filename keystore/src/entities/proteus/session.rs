use zeroize::Zeroize;

#[derive(
    core_crypto_macros::Debug,
    Clone,
    Zeroize,
    PartialEq,
    Eq,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
pub struct ProteusSession {
    pub id: String,
    pub session: Vec<u8>,
}
