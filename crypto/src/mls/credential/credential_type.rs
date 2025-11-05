use openmls::prelude::CredentialType as MlsCredentialType;

use super::Error;

/// All supported Credential types.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize)]
pub enum CredentialType {
    /// Basic credential i.e. a KeyPair
    #[default]
    Basic,
    /// A x509 certificate generally obtained through e2e identity enrollment process
    X509,
}

impl TryFrom<MlsCredentialType> for CredentialType {
    type Error = Error;
    fn try_from(value: MlsCredentialType) -> Result<Self, Self::Error> {
        match value {
            MlsCredentialType::Basic => Ok(CredentialType::Basic),
            MlsCredentialType::X509 => Ok(CredentialType::X509),
            _ => Err(Error::UnsupportedCredentialType(value.into())),
        }
    }
}

impl From<CredentialType> for MlsCredentialType {
    #[inline]
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::Basic => MlsCredentialType::Basic,

            CredentialType::X509 => MlsCredentialType::X509,
        }
    }
}

impl From<CredentialType> for u16 {
    #[inline]
    fn from(value: CredentialType) -> Self {
        MlsCredentialType::from(value).into()
    }
}

impl PartialEq<MlsCredentialType> for CredentialType {
    fn eq(&self, other: &MlsCredentialType) -> bool {
        u16::from(*self) == u16::from(*other)
    }
}
