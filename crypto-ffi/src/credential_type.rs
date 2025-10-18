/// Type of Credential
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Enum)]
#[repr(u8)]
pub enum CredentialType {
    /// Basic credential i.e. a KeyPair
    #[default]
    Basic = 0x01,
    /// A x509 certificate generally obtained through e2e identity enrollment process
    X509 = 0x02,
}

impl From<core_crypto::MlsCredentialType> for CredentialType {
    fn from(value: core_crypto::MlsCredentialType) -> Self {
        match value {
            core_crypto::MlsCredentialType::Basic => Self::Basic,
            core_crypto::MlsCredentialType::X509 => Self::X509,
        }
    }
}

impl From<CredentialType> for core_crypto::MlsCredentialType {
    fn from(value: CredentialType) -> core_crypto::MlsCredentialType {
        match value {
            CredentialType::Basic => core_crypto::MlsCredentialType::Basic,
            CredentialType::X509 => core_crypto::MlsCredentialType::X509,
        }
    }
}
