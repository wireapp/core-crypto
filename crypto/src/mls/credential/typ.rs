use std::unreachable;

use openmls::prelude::CredentialType;

/// Lists all the supported Credential types. Could list in the future some types not supported by
/// openmls such as Verifiable Presentation
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MlsCredentialType {
    /// Basic credential i.e. a KeyPair
    #[default]
    Basic = 0x01,
    /// A x509 certificate generally obtained through e2e identity enrollment process
    X509 = 0x02,
}

impl From<CredentialType> for MlsCredentialType {
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::Basic => MlsCredentialType::Basic,
            CredentialType::X509 => MlsCredentialType::X509,
            _ => unreachable!("Unknown credential type"),
        }
    }
}

impl From<MlsCredentialType> for CredentialType {
    fn from(value: MlsCredentialType) -> Self {
        match value {
            MlsCredentialType::Basic => CredentialType::Basic,
            MlsCredentialType::X509 => CredentialType::X509,
        }
    }
}
