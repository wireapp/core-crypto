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
