use crate::prelude::{CryptoResult, MlsCredentialType, MlsError, WireIdentity};
use openmls::prelude::{Credential, CredentialBundle};
use tls_codec::Serialize;
use wire_e2e_identity::prelude::WireIdentityReader;

pub(crate) trait CredentialExt {
    fn keystore_key(&self) -> CryptoResult<Vec<u8>>;
    fn get_type(&self) -> MlsCredentialType;
    fn extract_identity(&self) -> Option<WireIdentity>;
}

impl CredentialExt for CredentialBundle {
    #[inline(always)]
    fn keystore_key(&self) -> CryptoResult<Vec<u8>> {
        self.credential().keystore_key()
    }

    fn get_type(&self) -> MlsCredentialType {
        self.credential().get_type()
    }

    fn extract_identity(&self) -> Option<WireIdentity> {
        self.credential().extract_identity()
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

    fn extract_identity(&self) -> Option<WireIdentity> {
        match &self.credential {
            openmls::prelude::MlsCredentialType::X509(c) => {
                let leaf = c.cert_chain.get(0)?;
                Some(leaf.as_slice().extract_identity().ok()?.into())
            }
            _ => None,
        }
    }
}
