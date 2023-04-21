use crate::prelude::{CryptoResult, MlsCredentialType, MlsError};
use openmls::prelude::{Credential, CredentialBundle};
use tls_codec::Serialize;

pub(crate) trait CredentialExt {
    fn keystore_key(&self) -> CryptoResult<Vec<u8>>;
    fn get_type(&self) -> MlsCredentialType;
}

impl CredentialExt for CredentialBundle {
    #[inline(always)]
    fn keystore_key(&self) -> CryptoResult<Vec<u8>> {
        self.credential().keystore_key()
    }

    fn get_type(&self) -> MlsCredentialType {
        self.credential().get_type()
    }
}

impl CredentialExt for Credential {
    fn keystore_key(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.signature_key().tls_serialize_detached().map_err(MlsError::from)?)
    }

    fn get_type(&self) -> MlsCredentialType {
        match self.credential {
            openmls::prelude::MlsCredentialType::Basic(_) => MlsCredentialType::Basic,
            openmls::prelude::MlsCredentialType::X509(_) => MlsCredentialType::X509,
        }
    }
}
