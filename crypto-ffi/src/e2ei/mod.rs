use std::sync::Arc;

use async_lock::Mutex;
use jwt_simple::prelude::{ES256KeyPair, ES384KeyPair, ES512KeyPair, Ed25519KeyPair};
use x509_cert::der::Encode as _;

use crate::{Ciphersuite as FfiCiphersuite, ClientId, CoreCryptoError, CoreCryptoResult, Credential, PkiEnvironment};

/// The end-to-end identity verification state of a conversation.
///
/// Note: this does not check pending state (pending commit, pending proposals), so it does not
/// consider members about to be added or removed.
#[derive(Debug, Copy, Clone, uniffi::Enum)]
#[repr(u8)]
pub enum E2eiConversationState {
    /// All clients have a valid E2EI certificate.
    Verified = 1,
    /// Some clients are either still using Basic credentials or their certificate has expired.
    NotVerified,
    /// All clients are still using Basic credentials.
    ///
    /// Note: if all clients have expired certificates, `NotVerified` is returned instead.
    NotEnabled,
}

impl From<core_crypto::E2eiConversationState> for E2eiConversationState {
    fn from(value: core_crypto::E2eiConversationState) -> Self {
        match value {
            core_crypto::E2eiConversationState::Verified => Self::Verified,
            core_crypto::E2eiConversationState::NotVerified => Self::NotVerified,
            core_crypto::E2eiConversationState::NotEnabled => Self::NotEnabled,
        }
    }
}

/// Signing algorithm used for certificate acquisition.
#[derive(Debug, Copy, Clone, uniffi::Enum)]
pub enum E2eiJwsAlgorithm {
    /// Ed25519 / EdDSA
    Ed25519,
    /// ECDSA P-256 / ES256
    P256,
    /// ECDSA P-384 / ES384
    P384,
    /// ECDSA P-521 / ES512
    P521,
}

impl From<E2eiJwsAlgorithm> for wire_e2e_identity::JwsAlgorithm {
    fn from(value: E2eiJwsAlgorithm) -> Self {
        match value {
            E2eiJwsAlgorithm::Ed25519 => Self::Ed25519,
            E2eiJwsAlgorithm::P256 => Self::P256,
            E2eiJwsAlgorithm::P384 => Self::P384,
            E2eiJwsAlgorithm::P521 => Self::P521,
        }
    }
}

impl E2eiJwsAlgorithm {
    fn hash_alg(self) -> wire_e2e_identity::HashAlgorithm {
        match self {
            E2eiJwsAlgorithm::Ed25519 | E2eiJwsAlgorithm::P256 => wire_e2e_identity::HashAlgorithm::SHA256,
            E2eiJwsAlgorithm::P384 => wire_e2e_identity::HashAlgorithm::SHA384,
            E2eiJwsAlgorithm::P521 => wire_e2e_identity::HashAlgorithm::SHA512,
        }
    }

    fn ciphersuite(self) -> core_crypto::Ciphersuite {
        let ciphersuite = match self {
            E2eiJwsAlgorithm::Ed25519 => FfiCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            E2eiJwsAlgorithm::P256 => FfiCiphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            E2eiJwsAlgorithm::P384 => FfiCiphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            E2eiJwsAlgorithm::P521 => FfiCiphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        };
        ciphersuite.into()
    }
}

/// Configuration for an X509 credential acquisition flow.
#[derive(Debug, Clone, uniffi::Record)]
pub struct X509CredentialAcquisitionConfiguration {
    /// ACME server hostname.
    pub acme_url: String,
    /// OIDC identity provider URL.
    pub idp_url: String,
    /// Signing algorithm for the credential keypair.
    pub sign_alg: E2eiJwsAlgorithm,
    /// User-visible display name.
    pub display_name: String,
    /// Wire client id for the device acquiring the credential.
    pub client_id: Arc<ClientId>,
    /// Wire handle without the domain suffix.
    pub handle: String,
    /// Wire domain.
    pub domain: String,
    /// Optional Wire team id.
    pub team: Option<String>,
    /// Certificate validity period in seconds.
    pub validity_period_secs: u64,
}

impl X509CredentialAcquisitionConfiguration {
    fn try_into_core(self) -> CoreCryptoResult<wire_e2e_identity::acquisition::X509CredentialConfiguration> {
        let client_id = std::str::from_utf8(self.client_id.as_ref().0.as_ref()).map_err(CoreCryptoError::generic())?;
        let client_id =
            wire_e2e_identity::E2eiClientId::try_from_qualified(client_id).map_err(CoreCryptoError::generic())?;

        Ok(wire_e2e_identity::acquisition::X509CredentialConfiguration {
            acme_url: self.acme_url,
            idp_url: self.idp_url,
            sign_alg: self.sign_alg.into(),
            hash_alg: self.sign_alg.hash_alg(),
            display_name: self.display_name,
            client_id,
            handle: self.handle,
            domain: self.domain,
            team: self.team,
            validity_period: std::time::Duration::from_secs(self.validity_period_secs),
        })
    }
}

/// Initial state of the X509 credential acquisition flow.
#[derive(uniffi::Object)]
pub struct X509CredentialAcquisition {
    inner: Mutex<Option<wire_e2e_identity::X509CredentialAcquisition>>,
    sign_alg: E2eiJwsAlgorithm,
    ciphersuite: core_crypto::Ciphersuite,
}

fn acquisition_consumed_error() -> CoreCryptoError {
    CoreCryptoError::ad_hoc("x509 credential acquisition instance has already been consumed")
}

fn signing_key_bytes(sign_alg: E2eiJwsAlgorithm, signing_key_pem: &str) -> CoreCryptoResult<Vec<u8>> {
    match sign_alg {
        E2eiJwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(signing_key_pem).map(|key| key.to_bytes()),
        E2eiJwsAlgorithm::P256 => ES256KeyPair::from_pem(signing_key_pem).map(|key| key.to_bytes()),
        E2eiJwsAlgorithm::P384 => ES384KeyPair::from_pem(signing_key_pem).map(|key| key.to_bytes()),
        E2eiJwsAlgorithm::P521 => ES512KeyPair::from_pem(signing_key_pem).map(|key| key.to_bytes()),
    }
    .map_err(CoreCryptoError::generic())
}

#[uniffi::export]
impl X509CredentialAcquisition {
    /// Create a new credential acquisition
    #[uniffi::constructor]
    pub fn new(
        pki_environment: Arc<PkiEnvironment>,
        config: X509CredentialAcquisitionConfiguration,
    ) -> CoreCryptoResult<Self> {
        let sign_alg = config.sign_alg;
        let ciphersuite = config.sign_alg.ciphersuite();
        let inner = wire_e2e_identity::X509CredentialAcquisition::try_new(
            Arc::new(pki_environment.as_ref().clone().into()),
            config.try_into_core()?,
        )?;

        Ok(Self {
            inner: Mutex::new(Some(inner)),
            sign_alg,
            ciphersuite,
        })
    }

    /// Complete the DPoP and OIDC challenges and return the acquired X509 credential.
    pub async fn finalize(&self) -> CoreCryptoResult<Credential> {
        let inner = self.inner.lock().await.take().ok_or_else(acquisition_consumed_error)?;
        let inner = inner
            .complete_dpop_challenge()
            .await
            .map_err(|err| CoreCryptoError::E2ei {
                e2ei_error: err.to_string(),
            })?;
        let (signing_key_pem, certificate_chain) =
            inner
                .complete_oidc_challenge()
                .await
                .map_err(|err| CoreCryptoError::E2ei {
                    e2ei_error: err.to_string(),
                })?;
        let signing_key = signing_key_bytes(self.sign_alg, signing_key_pem.as_str())?;
        let certificate_chain = certificate_chain
            .into_iter()
            .map(|cert| cert.to_der().map_err(CoreCryptoError::generic()))
            .collect::<CoreCryptoResult<Vec<_>>>()?;

        let certificate_bundle = core_crypto::CertificateBundle::from_raw(
            certificate_chain,
            signing_key,
            self.ciphersuite.signature_algorithm(),
        );

        core_crypto::Credential::x509(self.ciphersuite, certificate_bundle)
            .map(Credential)
            .map_err(Into::into)
    }
}
