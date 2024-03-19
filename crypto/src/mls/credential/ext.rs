use crate::prelude::{CryptoError, CryptoResult, DeviceStatus, MlsCiphersuite, MlsCredentialType, WireIdentity};
use openmls::prelude::{Credential, CredentialType, CredentialWithKey};
use openmls_traits::types::{HashType, SignatureScheme};
use wire_e2e_identity::prelude::{compute_raw_key_thumbprint, HashAlgorithm, JwsAlgorithm};
use x509_cert::{der::Decode, Certificate};

pub(crate) trait CredentialExt {
    fn parse_leaf_cert(&self) -> CryptoResult<Option<Certificate>>;
    fn get_type(&self) -> CryptoResult<MlsCredentialType>;
    fn extract_identity(
        &self,
        cs: MlsCiphersuite,
        env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> CryptoResult<WireIdentity>;
    fn extract_public_key(&self) -> CryptoResult<Option<Vec<u8>>>;
    fn is_basic(&self) -> bool;
}

impl CredentialExt for CredentialWithKey {
    fn parse_leaf_cert(&self) -> CryptoResult<Option<Certificate>> {
        self.credential.parse_leaf_cert()
    }

    fn get_type(&self) -> CryptoResult<MlsCredentialType> {
        self.credential.get_type()
    }

    fn extract_identity(
        &self,
        cs: MlsCiphersuite,
        env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> CryptoResult<WireIdentity> {
        match self.credential.mls_credential() {
            openmls::prelude::MlsCredentialType::X509(cert) => cert.extract_identity(cs, env),
            openmls::prelude::MlsCredentialType::Basic(_) => {
                // in case the ClientId is not a Wire identifier, just returning an empty String is
                // fine since this is simply informative and for Wire only
                let client_id = std::str::from_utf8(self.credential.identity())
                    .unwrap_or_default()
                    .to_string();

                let thumbprint = compute_thumbprint(cs, self.signature_key.as_slice())?;

                Ok(WireIdentity {
                    client_id,
                    credential_type: MlsCredentialType::Basic,
                    thumbprint,
                    status: DeviceStatus::Valid,
                    x509_identity: None,
                })
            }
        }
    }

    fn extract_public_key(&self) -> CryptoResult<Option<Vec<u8>>> {
        self.credential.extract_public_key()
    }

    fn is_basic(&self) -> bool {
        self.credential.is_basic()
    }
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

    fn extract_identity(
        &self,
        _cs: MlsCiphersuite,
        _env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> CryptoResult<WireIdentity> {
        // This should not be called directly because one does not have the signature public key and hence
        // cannot compute the MLS thumbprint for a Basic credential.
        // [CredentialWithKey::extract_identity] should be preferred
        Err(CryptoError::ImplementationError)
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

    fn extract_identity(
        &self,
        _cs: MlsCiphersuite,
        env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> CryptoResult<WireIdentity> {
        let leaf = self.certificates.first().ok_or(CryptoError::InvalidIdentity)?;
        let leaf = leaf.as_slice();
        use wire_e2e_identity::prelude::WireIdentityReader as _;
        let identity = leaf.extract_identity(env).map_err(|_| CryptoError::InvalidIdentity)?;
        let identity = WireIdentity::try_from((identity, leaf))?;
        Ok(identity)
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

fn compute_thumbprint(cs: MlsCiphersuite, raw_key: &[u8]) -> CryptoResult<String> {
    let sign_alg = match cs.signature_algorithm() {
        SignatureScheme::ED25519 => JwsAlgorithm::Ed25519,
        SignatureScheme::ECDSA_SECP256R1_SHA256 => JwsAlgorithm::P256,
        SignatureScheme::ECDSA_SECP384R1_SHA384 => JwsAlgorithm::P384,
        SignatureScheme::ED448 | SignatureScheme::ECDSA_SECP521R1_SHA512 => return Err(CryptoError::Unsupported),
    };
    let hash_alg = match cs.hash_algorithm() {
        HashType::Sha2_256 => HashAlgorithm::SHA256,
        HashType::Sha2_384 => HashAlgorithm::SHA384,
        HashType::Sha2_512 => return Err(CryptoError::Unsupported),
    };

    // return an empty string when it fails. Not worth failing for this, it's just informative
    Ok(compute_raw_key_thumbprint(sign_alg, hash_alg, raw_key).unwrap_or_default())
}
