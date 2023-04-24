use crate::prelude::{CryptoError, CryptoResult, MlsCredentialType};
use openmls::prelude::{Credential, CredentialType};

pub(crate) trait CredentialExt {
    fn get_type(&self) -> CryptoResult<MlsCredentialType>;
}

impl CredentialExt for Credential {
    fn get_type(&self) -> CryptoResult<MlsCredentialType> {
        match self.credential_type() {
            CredentialType::Basic => Ok(MlsCredentialType::Basic),
            CredentialType::X509 => Ok(MlsCredentialType::X509),
            CredentialType::Unknown(_) => Err(CryptoError::ImplementationError),
        }
    }
}
