use crate::prelude::{CryptoError, CryptoResult, MlsCredentialType, WireIdentity};
use openmls::prelude::{Credential, CredentialType};
use x509_cert::der::Decode;
use x509_cert::Certificate;

pub(crate) trait CredentialExt {
    fn parse_leaf_cert(&self) -> CryptoResult<Option<Certificate>>;
    fn get_type(&self) -> CryptoResult<MlsCredentialType>;
    fn extract_identity(&self) -> CryptoResult<Option<WireIdentity>>;
    fn extract_public_key(&self) -> CryptoResult<Option<Vec<u8>>>;
    fn is_basic(&self) -> bool;
}

impl CredentialExt for Credential {
    fn parse_leaf_cert(&self) -> CryptoResult<Option<Certificate>> {
        match self.mls_credential() {
            openmls::prelude::MlsCredentialType::X509(cert) => cert.parse_leaf_cert(),
            _ => Ok(None),
        }
    }

    fn get_type(&self) -> CryptoResult<MlsCredentialType> {
        match self.credential_type() {
            CredentialType::Basic => Ok(MlsCredentialType::Basic),
            CredentialType::X509 => Ok(MlsCredentialType::X509),
            CredentialType::Unknown(_) => Err(CryptoError::ImplementationError),
        }
    }

    fn extract_identity(&self) -> CryptoResult<Option<WireIdentity>> {
        match self.mls_credential() {
            openmls::prelude::MlsCredentialType::X509(cert) => cert.extract_identity(),
            _ => Ok(None),
        }
    }

    fn extract_public_key(&self) -> CryptoResult<Option<Vec<u8>>> {
        match self.mls_credential() {
            openmls::prelude::MlsCredentialType::X509(cert) => cert.extract_public_key(),
            _ => Ok(None),
        }
    }

    fn is_basic(&self) -> bool {
        self.credential_type() == openmls::prelude::CredentialType::Basic
    }
}

impl CredentialExt for openmls::prelude::Certificate {
    fn parse_leaf_cert(&self) -> CryptoResult<Option<Certificate>> {
        let leaf = self.certificates.first().ok_or(CryptoError::InvalidIdentity)?;
        let leaf = Certificate::from_der(leaf.as_slice())?;
        Ok(Some(leaf))
    }

    fn get_type(&self) -> CryptoResult<MlsCredentialType> {
        Ok(MlsCredentialType::X509)
    }

    fn extract_identity(&self) -> CryptoResult<Option<WireIdentity>> {
        let leaf = self.certificates.first().ok_or(CryptoError::InvalidIdentity)?;
        let leaf = leaf.as_slice();
        use wire_e2e_identity::prelude::WireIdentityReader as _;
        let identity = leaf.extract_identity().map_err(|_| CryptoError::InvalidIdentity)?;
        let identity = WireIdentity::try_from((identity, leaf))?;
        Ok(Some(identity))
    }

    fn extract_public_key(&self) -> CryptoResult<Option<Vec<u8>>> {
        let leaf = self.certificates.first().ok_or(CryptoError::InvalidIdentity)?;
        use wire_e2e_identity::prelude::WireIdentityReader as _;
        let pk = leaf
            .as_slice()
            .extract_public_key()
            .map_err(|_| CryptoError::InvalidIdentity)?;
        Ok(Some(pk))
    }

    fn is_basic(&self) -> bool {
        false
    }
}
