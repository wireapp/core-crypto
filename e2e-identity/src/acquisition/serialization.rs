use std::sync::Arc;

use jwt_simple::prelude::Jwk;
use rusty_jwt_tools::prelude::{ClientId, Pem};
use uuid::Uuid;

use super::{Result, X509CredentialAcquisition, X509CredentialConfiguration, states};
use crate::pki_env::PkiEnvironment;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(remote = "ClientId")]
pub struct ClientIdDef {
    /// base64url encoded UUIDv4 unique user identifier
    pub user_id: Uuid,
    /// the device id assigned by the backend in hex
    pub device_id: u64,
    /// the backend domain of the client
    pub domain: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct X509CredentialAcquisitionSerialisationHelper<T: std::fmt::Debug> {
    config: X509CredentialConfiguration,
    sign_kp: Pem,
    acme_kp: Pem,
    acme_jwk: Jwk,
    data: T,
}

impl X509CredentialAcquisition<states::DpopChallengeCompleted> {
    pub fn deserialize(pki_env: Arc<PkiEnvironment>, bytes: &[u8]) -> Result<Self> {
        let helper: X509CredentialAcquisitionSerialisationHelper<states::DpopChallengeCompleted> =
            serde_json::from_slice(bytes)?;

        Ok(Self {
            pki_env,
            config: helper.config,
            sign_kp: helper.sign_kp,
            acme_kp: helper.acme_kp,
            acme_jwk: helper.acme_jwk,
            data: helper.data,
        })
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{ConnectionType, Database, DatabaseKey};
    use rusty_jwt_tools::prelude::{HashAlgorithm, JwsAlgorithm};

    use super::*;
    use crate::{
        acme::{AcmeAccount, AcmeChallenge, AcmeOrder},
        pki_env::hooks::{HttpHeader, HttpMethod, HttpResponse, PkiEnvironmentHooks, PkiEnvironmentHooksError},
    };

    #[derive(Debug)]
    struct UnusedPkiEnvironmentHooks;

    #[async_trait::async_trait]
    impl PkiEnvironmentHooks for UnusedPkiEnvironmentHooks {
        async fn http_request(
            &self,
            _method: HttpMethod,
            _url: String,
            _headers: Vec<HttpHeader>,
            _body: Vec<u8>,
        ) -> std::result::Result<HttpResponse, PkiEnvironmentHooksError> {
            unreachable!("serialization round-trip should not perform HTTP requests")
        }

        async fn authenticate(
            &self,
            _idp: String,
            _key_auth: String,
            _acme_aud: String,
            _acquisition_snapshot: Vec<u8>,
        ) -> std::result::Result<String, PkiEnvironmentHooksError> {
            unreachable!("serialization round-trip should not authenticate")
        }

        async fn get_backend_nonce(&self) -> std::result::Result<String, PkiEnvironmentHooksError> {
            unreachable!("serialization round-trip should not request backend nonces")
        }

        async fn fetch_backend_access_token(
            &self,
            _dpop: String,
        ) -> std::result::Result<String, PkiEnvironmentHooksError> {
            unreachable!("serialization round-trip should not fetch backend access tokens")
        }
    }

    #[tokio::test]
    async fn can_serialize_and_deserialize_dpop_challenge_completed_acquisition() {
        let pki_env = Arc::new(
            PkiEnvironment::new(
                Arc::new(UnusedPkiEnvironmentHooks),
                Database::open(ConnectionType::InMemory, &DatabaseKey::generate())
                    .await
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        let client_id = ClientId::try_new(Uuid::new_v4().to_string(), 1, "wire.example").unwrap();
        let config = X509CredentialConfiguration {
            acme_url: "acme.example".into(),
            idp_url: "idp.example".into(),
            sign_alg: JwsAlgorithm::P256,
            hash_alg: HashAlgorithm::SHA256,
            display_name: "Alice".into(),
            client_id,
            handle: "alice".into(),
            domain: "wire.example".into(),
            team: Some("team".into()),
            validity_period: std::time::Duration::from_secs(3600),
        };
        let initialized = X509CredentialAcquisition::try_new(pki_env.clone(), config).unwrap();
        let acquisition = X509CredentialAcquisition::<states::DpopChallengeCompleted> {
            pki_env: initialized.pki_env,
            config: initialized.config,
            sign_kp: initialized.sign_kp,
            acme_kp: initialized.acme_kp,
            acme_jwk: initialized.acme_jwk,
            data: states::DpopChallengeCompleted {
                nonce: "acme-nonce".into(),
                acme_account: AcmeAccount::default(),
                order: AcmeOrder::default(),
                oidc_challenge: AcmeChallenge::new_user(),
            },
        };

        let serialized = serde_json::to_vec(&acquisition).unwrap();
        let deserialized =
            X509CredentialAcquisition::<states::DpopChallengeCompleted>::deserialize(pki_env, &serialized).unwrap();

        assert_eq!(
            serde_json::to_value(&acquisition).unwrap(),
            serde_json::to_value(&deserialized).unwrap()
        );
    }
}
