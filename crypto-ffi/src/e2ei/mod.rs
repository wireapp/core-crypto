pub(crate) mod x509_credential_acquisition_from_credential_ref;

use std::sync::Arc;

use async_lock::Mutex;
use wire_e2e_identity::{CiphersuiteExt as _, JwsAlgorithm, acquisition::states};
use x509_cert::der::Encode as _;

use crate::{
    CipherSuite as FfiCiphersuite, ClientId, CoreCryptoError, CoreCryptoResult, Credential, E2eiError, PkiEnvironment,
};

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

/// The signing algorithm used for certificate acquisition with this ciphersuite.
fn jws_algorithm(cipher_suite: FfiCiphersuite) -> CoreCryptoResult<JwsAlgorithm> {
    core_crypto::MlsCiphersuite::from(cipher_suite)
        .jws_algorithm()
        .ok_or_else(|| E2eiError::UnsupportedCipherSuite { cipher_suite }.into())
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
        Ok(wire_e2e_identity::acquisition::X509CredentialConfiguration {
            acme_directory_url: self.acme_directory_url,
            cipher_suite: self.cipher_suite.into(),
            display_name: self.display_name,
            client_id: self.client_id.as_e2ei_client_id()?,
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
    cipher_suite: FfiCiphersuite,
}

enum AcquisitionState {
    Initialized(Box<wire_e2e_identity::X509CredentialAcquisition>),
    DpopChallengeCompleted(Box<wire_e2e_identity::X509CredentialAcquisition<states::DpopChallengeCompleted>>),
    InProgress,
    Finalized,
}

fn credential_from_acquisition_result(
    cipher_suite: FfiCiphersuite,
    signing_key: Vec<u8>,
    certificate_chain: Vec<x509_cert::Certificate>,
) -> CoreCryptoResult<Credential> {
    let certificate_chain = certificate_chain
        .into_iter()
        .map(|cert| {
            cert.to_der()
                .map_err(|err| E2eiError::InvalidCertificate { msg: err.to_string() }.into())
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
        )?;

        let cipher_suite = snapshot.cipher_suite().into();

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
            AcquisitionState::Initialized(inner) => match inner.complete_dpop_challenge().await {
                Ok(inner) => inner.complete_oidc_challenge().await.map_err(CoreCryptoError::from),
                // We don't want to return before setting the state to finalized below.
                Err(err) => Err(err.into()),
            },
            AcquisitionState::DpopChallengeCompleted(inner) => {
                inner.complete_oidc_challenge().await.map_err(Into::into)
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
        let signing_key = jws_algorithm(self.cipher_suite)?
            .keypair_to_bytes(&signing_key_pem)
            .map_err(|err| E2eiError::Other { msg: err.to_string() })?;
        credential_from_acquisition_result(self.cipher_suite, signing_key.to_vec(), certificate_chain)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        Database, DeviceId, HttpHeader, HttpMethod, HttpResponse, PkiEnvironmentHooks, Uuid,
        pki_env::PkiEnvironmentHooksError,
    };

    /// Hooks that fail every call, so the acquisition fails at its first request.
    struct FailingHooks;

    #[async_trait::async_trait]
    impl PkiEnvironmentHooks for FailingHooks {
        async fn http_request(
            &self,
            _method: HttpMethod,
            _url: String,
            _headers: Vec<HttpHeader>,
            _body: Vec<u8>,
        ) -> Result<HttpResponse, PkiEnvironmentHooksError> {
            Err(PkiEnvironmentHooksError::Error {
                reason: "http request failed".to_owned(),
            })
        }

        async fn authenticate(
            &self,
            _idp: String,
            _key_auth: String,
            _acme_aud: String,
            _acquisition_snapshot: Vec<u8>,
        ) -> Result<String, PkiEnvironmentHooksError> {
            unreachable!("the DPoP challenge fails before authentication")
        }

        async fn get_backend_nonce(&self) -> Result<String, PkiEnvironmentHooksError> {
            unreachable!("the DPoP challenge fails before fetching a nonce")
        }

        async fn fetch_backend_access_token(&self, _dpop: String) -> Result<String, PkiEnvironmentHooksError> {
            unreachable!("the DPoP challenge fails before fetching an access token")
        }
    }

    /// A failed DPoP challenge consumes the acquisition, so it must end up finalized rather than stuck in progress.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn failed_dpop_challenge_finalizes_the_acquisition() {
        let database = Arc::new(Database::in_memory().unwrap());
        let pki_environment = Arc::new(PkiEnvironment::new(Arc::new(FailingHooks), database).await.unwrap());
        let client_id = Arc::new(ClientId::new(
            Arc::new(Uuid::new("b01ec765-db9d-4502-9859-a9fa8c437c6f").unwrap()),
            Arc::new(DeviceId::new(1)),
            "wire.com".to_owned(),
        ));
        let config = X509CredentialAcquisitionConfiguration {
            acme_directory_url: "https://acme.wire.com/acme/wire/directory".to_owned(),
            cipher_suite: FfiCiphersuite::default(),
            display_name: "Alice Smith".to_owned(),
            client_id,
            handle: "alice_wire".to_owned(),
            domain: "wire.com".to_owned(),
            team: None,
            validity_period_secs: 3600,
        };
        let acquisition = X509CredentialAcquisition::new(pki_environment, config).unwrap();

        acquisition
            .finalize()
            .await
            .expect_err("the DPoP challenge should fail");

        let err = acquisition
            .finalize()
            .await
            .expect_err("a finalized acquisition can't be finalized again");
        assert!(
            matches!(&err, CoreCryptoError::Other { msg } if msg.contains("already been finalized")),
            "expected the acquisition to be finalized, got {err:?}"
        );
    }
}
