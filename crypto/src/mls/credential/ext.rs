use crate::{
    mls::credential::CredentialBundle,
    prelude::{CryptoResult, MlsCredentialType},
    CryptoError,
};
use openmls::prelude::{Credential, CredentialType};

pub(crate) trait CredentialExt {
    fn get_type(&self) -> CryptoResult<MlsCredentialType>;
    // fn extract_identity(&self) -> Option<WireIdentity>;
}

impl CredentialExt for CredentialBundle {
    fn get_type(&self) -> CryptoResult<MlsCredentialType> {
        self.credential.get_type()
    }

    // fn extract_identity(&self) -> Option<WireIdentity> {
    //     self.credential.extract_identity()
    // }
}

impl CredentialExt for Credential {
    fn get_type(&self) -> CryptoResult<MlsCredentialType> {
        match self.credential_type() {
            CredentialType::Basic => Ok(MlsCredentialType::Basic),
            CredentialType::X509 => Ok(MlsCredentialType::X509),
            CredentialType::Unknown(_) => Err(CryptoError::ImplementationError),
        }
    }

    // fn extract_identity(&self) -> Option<WireIdentity> {
    //     match &self.mls_credential() {
    //         openmls::prelude::MlsCredentialType::X509(c) => {
    //             let leaf = c.cert_data.get(0)?;
    //             Some(leaf.as_slice().extract_identity().ok()?.into())
    //         }
    //         _ => None,
    //     }
    // }
}
