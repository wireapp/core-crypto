#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, derive_more::From, derive_more::Into)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
pub struct NewCrlDistributionPoints(Option<Vec<String>>);

#[cfg(not(target_family = "wasm"))]
uniffi::custom_newtype!(NewCrlDistributionPoints, Option<Vec<String>>);

impl From<core_crypto::e2e_identity::NewCrlDistributionPoints> for NewCrlDistributionPoints {
    fn from(value: core_crypto::e2e_identity::NewCrlDistributionPoints) -> Self {
        let value = value.into_iter().collect::<Vec<_>>();
        let value = (!value.is_empty()).then_some(value);
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
/// Supporting struct for CRL registration result
pub struct CrlRegistration {
    /// Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
    pub dirty: bool,
    /// Optional expiration timestamp
    pub expiration: Option<u64>,
}

impl From<core_crypto::e2e_identity::CrlRegistration> for CrlRegistration {
    fn from(value: core_crypto::e2e_identity::CrlRegistration) -> Self {
        Self {
            dirty: value.dirty,
            expiration: value.expiration,
        }
    }
}
