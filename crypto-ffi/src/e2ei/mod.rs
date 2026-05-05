use std::sync::Arc;

use async_lock::Mutex;
use jwt_simple::prelude::{ES256KeyPair, ES384KeyPair, ES512KeyPair, Ed25519KeyPair};
use wire_e2e_identity::{HashAlgorithm, JwsAlgorithm, acquisition::states};
use x509_cert::der::Encode as _;

use crate::{CipherSuite as FfiCiphersuite, ClientId, CoreCryptoError, CoreCryptoResult, Credential, PkiEnvironment};

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

impl TryFrom<FfiCiphersuite> for JwsAlgorithm {
    type Error = CoreCryptoError;

    fn try_from(value: FfiCiphersuite) -> Result<Self, Self::Error> {
        match value {
            FfiCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => Ok(Self::Ed25519),
            FfiCiphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(Self::P256),
            FfiCiphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => Ok(Self::P384),
            FfiCiphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => Ok(Self::P521),
            _ => Err(CoreCryptoError::ad_hoc(
                "ciphersuite is not supported for certificate acquisition",
            )),
        }
    }
}

impl From<JwsAlgorithm> for FfiCiphersuite {
    fn from(value: JwsAlgorithm) -> Self {
        match value {
            JwsAlgorithm::Ed25519 => FfiCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            JwsAlgorithm::P256 => FfiCiphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            JwsAlgorithm::P384 => FfiCiphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            JwsAlgorithm::P521 => FfiCiphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        }
    }
}

/// Configuration for an X509 credential acquisition flow.
#[derive(Debug, Clone, uniffi::Record)]
pub struct X509CredentialAcquisitionConfiguration {
    /// ACME server hostname.
    pub acme_url: String,
    /// OIDC identity provider URL.
    pub idp_url: String,
    /// Ciphersuite of the acquired credential.
    pub ciphersuite: FfiCiphersuite,
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
        let sign_alg: JwsAlgorithm = self.ciphersuite.try_into()?;

        Ok(wire_e2e_identity::acquisition::X509CredentialConfiguration {
            acme_url: self.acme_url,
            idp_url: self.idp_url,
            sign_alg,
            hash_alg: HashAlgorithm::SHA256,
            display_name: self.display_name,
            client_id,
            handle: self.handle,
            domain: self.domain,
            team: self.team,
            validity_period: std::time::Duration::from_secs(self.validity_period_secs),
        })
    }
}

/// X509 credential acquisition flow.
///
/// This allows acquiring a X509 credential for a CoreCrypto client.
#[derive(uniffi::Object)]
pub struct X509CredentialAcquisition {
    state: Mutex<AcquisitionState>,
    ciphersuite: FfiCiphersuite,
}

enum AcquisitionState {
    Initialized(Box<wire_e2e_identity::X509CredentialAcquisition>),
    DpopChallengeCompleted(Box<wire_e2e_identity::X509CredentialAcquisition<states::DpopChallengeCompleted>>),
    InProgress,
    Finalized,
}

fn signing_key_bytes(sign_alg: wire_e2e_identity::JwsAlgorithm, signing_key_pem: &str) -> CoreCryptoResult<Vec<u8>> {
    match sign_alg {
        JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(signing_key_pem).map(|key| key.to_bytes()),
        JwsAlgorithm::P256 => ES256KeyPair::from_pem(signing_key_pem).map(|key| key.to_bytes()),
        JwsAlgorithm::P384 => ES384KeyPair::from_pem(signing_key_pem).map(|key| key.to_bytes()),
        JwsAlgorithm::P521 => ES512KeyPair::from_pem(signing_key_pem).map(|key| key.to_bytes()),
    }
    .map_err(CoreCryptoError::generic())
}

fn credential_from_acquisition_result(
    ciphersuite: FfiCiphersuite,
    signing_key_pem: &str,
    certificate_chain: Vec<x509_cert::Certificate>,
) -> CoreCryptoResult<Credential> {
    let sign_alg = ciphersuite.try_into()?;
    let signing_key = signing_key_bytes(sign_alg, signing_key_pem)?;
    let certificate_chain = certificate_chain
        .into_iter()
        .map(|cert| {
            cert.to_der().map_err(|err| CoreCryptoError::E2ei {
                e2ei_error: err.to_string(),
            })
        })
        .collect::<CoreCryptoResult<Vec<_>>>()?;

    let certificate_bundle = core_crypto::CertificateBundle::from_raw(
        certificate_chain,
        signing_key,
        core_crypto::CipherSuite::from(ciphersuite).signature_algorithm(),
    );

    core_crypto::Credential::x509(ciphersuite.into(), certificate_bundle)
        .map(Credential)
        .map_err(Into::into)
}

#[uniffi::export]
impl X509CredentialAcquisition {
    /// Create a new credential acquisition
    #[uniffi::constructor]
    pub fn new(
        pki_environment: Arc<PkiEnvironment>,
        config: X509CredentialAcquisitionConfiguration,
    ) -> CoreCryptoResult<Self> {
        let ciphersuite = config.ciphersuite;
        let inner = wire_e2e_identity::X509CredentialAcquisition::try_new(
            pki_environment.clone_inner(),
            config.try_into_core()?,
        )?;

        Ok(Self {
            state: Mutex::new(AcquisitionState::Initialized(inner.into())),
            ciphersuite,
        })
    }

    /// Deserialize a credential acquisition flow.
    #[uniffi::constructor(name = "fromBytes")]
    pub fn from_bytes(pki_environment: Arc<PkiEnvironment>, bytes: &[u8]) -> CoreCryptoResult<Self> {
        let snapshot = wire_e2e_identity::X509CredentialAcquisition::<states::DpopChallengeCompleted>::deserialize(
            pki_environment.clone_inner(),
            bytes,
        )
        .map_err(CoreCryptoError::generic())?;

        let ciphersuite: FfiCiphersuite = snapshot.sign_alg().into();

        Ok(Self {
            state: Mutex::new(AcquisitionState::DpopChallengeCompleted(snapshot.into())),
            ciphersuite,
        })
    }

    /// Complete the DPoP and OIDC challenges and return the acquired X509 credential.
    pub async fn finalize(&self) -> CoreCryptoResult<Credential> {
        let state = {
            let mut state = self.state.lock().await;
            std::mem::replace(&mut *state, AcquisitionState::InProgress)
        };

        let result = match state {
            AcquisitionState::Initialized(inner) => inner
                .complete_dpop_challenge()
                .await
                .map_err(|err| CoreCryptoError::E2ei {
                    e2ei_error: err.to_string(),
                })?
                .complete_oidc_challenge()
                .await
                .map_err(|err| CoreCryptoError::E2ei {
                    e2ei_error: err.to_string(),
                }),
            AcquisitionState::DpopChallengeCompleted(inner) => {
                inner
                    .complete_oidc_challenge()
                    .await
                    .map_err(|err| CoreCryptoError::E2ei {
                        e2ei_error: err.to_string(),
                    })
            }
            AcquisitionState::InProgress => {
                return Err(CoreCryptoError::ad_hoc(
                    "x509 credential acquisition is already in progress",
                ));
            }
            AcquisitionState::Finalized => {
                return Err(CoreCryptoError::ad_hoc(
                    "x509 credential acquisition has already been finalized",
                ));
            }
        };

        *self.state.lock().await = AcquisitionState::Finalized;
        let (signing_key_pem, certificate_chain) = result?;
        credential_from_acquisition_result(self.ciphersuite, signing_key_pem.as_str(), certificate_chain)
    }
}
