use zeroize::Zeroize;

/// Entity representing a trust anchor certificate.
///
/// This entity cannot be updated in the DB: the primary key is the fingerprint of the very key the
/// certificate carries. `PkiEnvironment::add_trust_anchor` also refuses a fingerprint it already
/// holds, so a save which reaches the uniqueness constraint has slipped past that check, and
/// reports [`CryptoKeystoreError::AlreadyExists`][crate::CryptoKeystoreError::AlreadyExists]
/// rather than replacing an anchor other certificates are already validated against.
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
#[entity(table_name = "x509_trust_anchor", no_upsert)]
pub struct X509TrustAnchor {
    #[entity(id)]
    pub fingerprint: Vec<u8>,
    pub content: Vec<u8>,
}
