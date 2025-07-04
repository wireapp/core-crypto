#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

pub(crate) type NewCrlDistributionPoints = Option<Vec<String>>;

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

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CrlRegistration {
    #[wasm_bindgen(constructor)]
    pub fn new(dirty: bool, expiration: Option<u64>) -> Self {
        Self { dirty, expiration }
    }
}
