use zeroize::Zeroize;

#[cfg(not(target_os = "unknown"))]
use crate::traits::EntityBase as _;

/// Entity representing an enrollment instance used to fetch a x509 certificate and persisted when
/// context switches and the memory it lives in is about to be erased
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
#[entity(collection_name = "e2ei_enrollment", no_upsert)]
pub struct StoredE2eiEnrollment {
    pub id: Vec<u8>,
    pub content: Vec<u8>,
}
