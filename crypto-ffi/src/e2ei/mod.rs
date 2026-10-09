pub(crate) mod x509_credential_acquisition_from_credential_ref;

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
        // This match is deliberately exhaustive, so that adding a ciphersuite requires deciding
        // whether it supports certificate acquisition.
        match value {
            FfiCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | FfiCiphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | FfiCiphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519
            | FfiCiphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519
            | FfiCiphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519 => Ok(Self::Ed25519),
            FfiCiphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | FfiCiphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256
            | FfiCiphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256
            | FfiCiphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256 => Ok(Self::P256),
            FfiCiphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | FfiCiphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384
            | FfiCiphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384 => Ok(Self::P384),
            FfiCiphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => Ok(Self::P521),
            // There is no JWS algorithm for Ed448.
            FfiCiphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | FfiCiphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            // We don't yet support ML-DSA signatures with x509 credentials.
            | FfiCiphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44
            | FfiCiphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65
            | FfiCiphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 => Err(CoreCryptoError::ad_hoc(
                "cipher_suite is not supported for certificate acquisition",
            )),
        }
    }
}

/// Restore the ciphersuite of a deserialized acquisition.
fn cipher_suite_from_snapshot(cipher_suite: Option<u16>, sign_alg: JwsAlgorithm) -> CoreCryptoResult<FfiCiphersuite> {
    let Some(cipher_suite) = cipher_suite else {
        // Acquisitions serialized before the ciphersuite was stored could only use these.
        return Ok(match sign_alg {
            JwsAlgorithm::Ed25519 => FfiCiphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            JwsAlgorithm::P256 => FfiCiphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            JwsAlgorithm::P384 => FfiCiphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            JwsAlgorithm::P521 => FfiCiphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        });
    };

    let cipher_suite = FfiCiphersuite::try_from(cipher_suite).map_err(CoreCryptoError::generic())?;
    if JwsAlgorithm::try_from(cipher_suite)? != sign_alg {
        return Err(CoreCryptoError::ad_hoc(
            "acquisition cipher suite doesn't match its signing algorithm",
        ));
    }
    Ok(cipher_suite)
}

/// Configuration for an X509 credential acquisition flow.
#[derive(Debug, Clone, uniffi::Record)]
pub struct X509CredentialAcquisitionConfiguration {
    /// ACME directory URL.
    pub acme_directory_url: String,
    /// Ciphersuite of the acquired credential.
    pub cipher_suite: FfiCiphersuite,
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
        let sign_alg: JwsAlgorithm = self.cipher_suite.try_into()?;

        Ok(wire_e2e_identity::acquisition::X509CredentialConfiguration {
            acme_directory_url: self.acme_directory_url,
            sign_alg,
            hash_alg: HashAlgorithm::SHA256,
            display_name: self.display_name,
            client_id: self.client_id.as_e2ei_client_id()?,
            handle: self.handle,
            domain: self.domain,
            team: self.team,
            validity_period: std::time::Duration::from_secs(self.validity_period_secs),
            cipher_suite: Some(self.cipher_suite as u16),
        })
    }
}

/// X509 credential acquisition flow.
///
/// This allows acquiring a X509 credential for a CoreCrypto client.
#[derive(uniffi::Object)]
pub struct X509CredentialAcquisition {
    state: Mutex<AcquisitionState>,
    cipher_suite: FfiCiphersuite,
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
    cipher_suite: FfiCiphersuite,
    signing_key_pem: &str,
    certificate_chain: Vec<x509_cert::Certificate>,
) -> CoreCryptoResult<Credential> {
    let sign_alg = cipher_suite.try_into()?;
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
        core_crypto::CipherSuite::from(cipher_suite).signature_algorithm(),
    );

    core_crypto::Credential::x509(cipher_suite.into(), certificate_bundle)
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
        let cipher_suite = config.cipher_suite;
        let inner = wire_e2e_identity::X509CredentialAcquisition::try_new(
            pki_environment.clone_inner(),
            config.try_into_core()?,
        )?;

        Ok(Self {
            state: Mutex::new(AcquisitionState::Initialized(inner.into())),
            cipher_suite,
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

        let cipher_suite = cipher_suite_from_snapshot(snapshot.cipher_suite(), snapshot.sign_alg())?;

        Ok(Self {
            state: Mutex::new(AcquisitionState::DpopChallengeCompleted(snapshot.into())),
            cipher_suite,
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
        credential_from_acquisition_result(self.cipher_suite, signing_key_pem.as_str(), certificate_chain)
    }
}
