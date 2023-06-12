use crate::prelude::{CryptoError, CryptoResult, MlsCredentialType, WireIdentity};
use openmls::prelude::{Credential, CredentialType};

pub(crate) trait CredentialExt {
    fn get_type(&self) -> CryptoResult<MlsCredentialType>;
    fn extract_identity(&self) -> CryptoResult<Option<WireIdentity>>;
    fn extract_public_key(&self) -> CryptoResult<Option<Vec<u8>>>;
    fn is_basic(&self) -> bool;
}

impl CredentialExt for Credential {
    fn get_type(&self) -> CryptoResult<MlsCredentialType> {
        match self.credential_type() {
            CredentialType::Basic => Ok(MlsCredentialType::Basic),
            CredentialType::X509 => Ok(MlsCredentialType::X509),
            CredentialType::Unknown(_) => Err(CryptoError::ImplementationError),
        }
    }

    fn extract_identity(&self) -> CryptoResult<Option<WireIdentity>> {
        match self.mls_credential() {
            openmls::prelude::MlsCredentialType::X509(openmls::prelude::Certificate { cert_data, .. }) => {
                let leaf = cert_data.get(0).ok_or(CryptoError::InvalidIdentity)?;
                use wire_e2e_identity::prelude::WireIdentityReader as _;
                let identity = leaf
                    .as_slice()
                    .extract_identity()
                    .map_err(|_| CryptoError::InvalidIdentity)?;
                Ok(Some(identity.into()))
            }
            _ => Ok(None),
        }
    }

    fn extract_public_key(&self) -> CryptoResult<Option<Vec<u8>>> {
        match self.mls_credential() {
            openmls::prelude::MlsCredentialType::X509(openmls::prelude::Certificate { cert_data, .. }) => {
                let leaf = cert_data.get(0).ok_or(CryptoError::InvalidIdentity)?;
                use wire_e2e_identity::prelude::WireIdentityReader as _;
                let pk = leaf
                    .as_slice()
                    .extract_public_key()
                    .map_err(|_| CryptoError::InvalidIdentity)?;
                Ok(Some(pk))
            }
            _ => Ok(None),
        }
    }

    fn is_basic(&self) -> bool {
        self.credential_type() == openmls::prelude::CredentialType::Basic
    }
}
