#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::CoreCryptoError;

/// Type of Credential
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Enum))]
#[repr(u8)]
pub enum CredentialType {
    /// Basic credential i.e. a KeyPair
    #[default]
    Basic = 0x01,
    /// A x509 certificate generally obtained through e2e identity enrollment process
    X509 = 0x02,
}

impl TryFrom<core_crypto::CredentialType> for CredentialType {
    type Error = CoreCryptoError;
    fn try_from(value: core_crypto::CredentialType) -> Result<CredentialType, CoreCryptoError> {
        match value {
            core_crypto::CredentialType::Basic => Ok(Self::Basic),
            core_crypto::CredentialType::X509 => Ok(Self::X509),
            core_crypto::CredentialType::Unknown(_) => Err(CoreCryptoError::ad_hoc("unknown credential type")),
        }
    }
}

impl From<CredentialType> for core_crypto::CredentialType {
    fn from(value: CredentialType) -> core_crypto::CredentialType {
        match value {
            CredentialType::Basic => core_crypto::CredentialType::Basic,
            CredentialType::X509 => core_crypto::CredentialType::X509,
        }
    }
}
