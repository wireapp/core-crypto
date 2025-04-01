use std::collections::HashMap;

use tls_codec::Deserialize;

use self::context::CoreCryptoContext;
use crate::{
    Ciphersuite, Ciphersuites, ClientId, CoreCrypto, CoreCryptoError, CoreCryptoResult, CredentialType, WireIdentity,
    proteus_impl,
};
use core_crypto::mls::conversation::Conversation as _;
pub use core_crypto::prelude::ConversationId;
use core_crypto::{RecursiveError, prelude::VerifiableGroupInfo};

pub mod context;
mod epoch_observer;

#[derive(Debug, Clone, uniffi::Record)]
/// Dummy comment
pub struct E2eiDumpedPkiEnv {
    pub root_ca: String,
    pub intermediates: Vec<String>,
    pub crls: Vec<String>,
}

impl From<core_crypto::e2e_identity::E2eiDumpedPkiEnv> for E2eiDumpedPkiEnv {
    fn from(value: core_crypto::e2e_identity::E2eiDumpedPkiEnv) -> Self {
        Self {
            root_ca: value.root_ca,
            intermediates: value.intermediates,
            crls: value.crls,
        }
    }
}

#[allow(dead_code, unused_variables)]
#[uniffi::export]
impl CoreCrypto {
    /// See [core_crypto::mls::conversation::ImmutableConversation::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<ClientId>> {
        Ok(self
            .inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .get_client_ids()
            .await
            .into_iter()
            .map(ClientId)
            .collect())
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::export_secret_key]
    pub async fn export_secret_key(&self, conversation_id: Vec<u8>, key_length: u32) -> CoreCryptoResult<Vec<u8>> {
        self.inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .export_secret_key(key_length as usize)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .get_external_sender()
            .await?)
    }
}

#[derive(Debug, Copy, Clone, uniffi::Enum)]
#[repr(u8)]
pub enum E2eiConversationState {
    /// All clients have a valid E2EI certificate
    Verified = 1,
    /// Some clients are either still Basic or their certificate is expired
    NotVerified,
    /// All clients are still Basic. If all client have expired certificates, [E2eiConversationState::NotVerified] is returned.
    NotEnabled,
}

impl From<core_crypto::prelude::E2eiConversationState> for E2eiConversationState {
    fn from(value: core_crypto::prelude::E2eiConversationState) -> Self {
        match value {
            core_crypto::prelude::E2eiConversationState::Verified => Self::Verified,
            core_crypto::prelude::E2eiConversationState::NotVerified => Self::NotVerified,
            core_crypto::prelude::E2eiConversationState::NotEnabled => Self::NotEnabled,
        }
    }
}

#[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
#[uniffi::export]
impl CoreCrypto {
    /// See [core_crypto::proteus::ProteusCentral::session_exists]
    pub async fn proteus_session_exists(&self, session_id: String) -> CoreCryptoResult<bool> {
        proteus_impl!({ Ok(self.inner.proteus_session_exists(&session_id).await?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
    pub fn proteus_last_resort_prekey_id(&self) -> CoreCryptoResult<u16> {
        proteus_impl!({ Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id()) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint]
    pub async fn proteus_fingerprint(&self) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(self.inner.proteus_fingerprint().await?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_local]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(self.inner.proteus_fingerprint_local(&session_id).await?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_remote]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(self.inner.proteus_fingerprint_remote(&session_id).await?) })
    }

    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    /// NOTE: uniffi doesn't support associated functions, so we have to have the self here
    pub fn proteus_fingerprint_prekeybundle(&self, prekey: Vec<u8>) -> CoreCryptoResult<String> {
        proteus_impl!({ Ok(core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey)?) })
    }
}

// End-to-end identity methods
#[allow(dead_code, unused_variables)]
#[uniffi::export]
impl CoreCrypto {
    pub async fn e2ei_dump_pki_env(&self) -> CoreCryptoResult<Option<E2eiDumpedPkiEnv>> {
        let dumped_pki_env = self
            .inner
            .e2ei_dump_pki_env()
            .await
            .map(|option| option.map(Into::into))
            .map_err(RecursiveError::mls_client("dumping pki env"))?;
        Ok(dumped_pki_env)
    }

    /// See [core_crypto::mls::Client::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.inner.e2ei_is_pki_env_setup().await
    }

    /// See [core_crypto::mls::Client::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let sc = core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
            .signature_algorithm();
        self.inner
            .e2ei_is_enabled(sc)
            .await
            .map_err(RecursiveError::mls_client("is e2ei enabled on client?"))
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::get_device_identities]
    pub async fn get_device_identities(
        &self,
        conversation_id: Vec<u8>,
        device_ids: Vec<ClientId>,
    ) -> CoreCryptoResult<Vec<WireIdentity>> {
        let device_ids = device_ids.into_iter().map(|cid| cid.0).collect::<Vec<_>>();
        Ok(self
            .inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .get_device_identities(&device_ids[..])
            .await?
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>())
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::get_user_identities]
    pub async fn get_user_identities(
        &self,
        conversation_id: Vec<u8>,
        user_ids: Vec<String>,
    ) -> CoreCryptoResult<HashMap<String, Vec<WireIdentity>>> {
        Ok(self
            .inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .get_user_identities(&user_ids[..])
            .await?
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
            .collect::<HashMap<String, Vec<WireIdentity>>>())
    }

    /// See [core_crypto::mls::Client::get_credential_in_use]
    pub async fn get_credential_in_use(
        &self,
        group_info: Vec<u8>,
        credential_type: CredentialType,
    ) -> CoreCryptoResult<E2eiConversationState> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(core_crypto::mls::conversation::Error::tls_deserialize(
                "verifiable group info",
            ))
            .map_err(RecursiveError::mls_conversation("deserializing veriable group info"))?;
        let credential = self
            .inner
            .get_credential_in_use(group_info, credential_type.into())
            .await
            .map_err(RecursiveError::mls_client("getting credential in use"))?
            .into();
        Ok(credential)
    }
}

#[derive(Debug, uniffi::Object)]
/// See [core_crypto::e2e_identity::E2eiEnrollment]
pub struct E2eiEnrollment(std::sync::Arc<async_lock::RwLock<core_crypto::prelude::E2eiEnrollment>>);

#[uniffi::export]
impl E2eiEnrollment {
    /// See [core_crypto::e2e_identity::E2eiEnrollment::directory_response]
    pub async fn directory_response(&self, directory: Vec<u8>) -> CoreCryptoResult<AcmeDirectory> {
        Ok(self
            .0
            .write()
            .await
            .directory_response(directory)
            .map(AcmeDirectory::from)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_request]
    pub async fn new_account_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.new_account_request(previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_response]
    pub async fn new_account_response(&self, account: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self.0.write().await.new_account_response(account)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_request]
    #[allow(clippy::too_many_arguments)]
    pub async fn new_order_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.new_order_request(previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_response]
    pub async fn new_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<NewAcmeOrder> {
        Ok(self.0.read().await.new_order_response(order)?.into())
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_request]
    pub async fn new_authz_request(&self, url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.new_authz_request(url, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_response]
    pub async fn new_authz_response(&self, authz: Vec<u8>) -> CoreCryptoResult<NewAcmeAuthz> {
        Ok(self.0.write().await.new_authz_response(authz)?.into())
    }

    #[allow(clippy::too_many_arguments)]
    /// See [core_crypto::e2e_identity::E2eiEnrollment::create_dpop_token]
    pub async fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> CoreCryptoResult<String> {
        Ok(self.0.read().await.create_dpop_token(expiry_secs, backend_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_request]
    pub async fn new_dpop_challenge_request(
        &self,
        access_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .0
            .read()
            .await
            .new_dpop_challenge_request(access_token, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_response]
    pub async fn new_dpop_challenge_response(&self, challenge: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self.0.read().await.new_dpop_challenge_response(challenge)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_request]
    pub async fn new_oidc_challenge_request(
        &self,
        id_token: String,
        refresh_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .0
            .write()
            .await
            .new_oidc_challenge_request(id_token, refresh_token, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_response]
    pub async fn context_new_oidc_challenge_response(
        &self,
        cc: std::sync::Arc<CoreCryptoContext>,
        challenge: Vec<u8>,
    ) -> CoreCryptoResult<()> {
        self.0
            .write()
            .await
            .new_oidc_challenge_response(&cc.context.mls_provider().await?, challenge)
            .await?;
        Ok(())
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_request]
    pub async fn check_order_request(&self, order_url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.read().await.check_order_request(order_url, previous_nonce)?)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_response]
    pub async fn check_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<String> {
        Ok(self.0.write().await.check_order_response(order)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::finalize_request]
    pub async fn finalize_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.write().await.finalize_request(previous_nonce)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::finalize_response]
    pub async fn finalize_response(&self, finalize: Vec<u8>) -> CoreCryptoResult<String> {
        Ok(self.0.write().await.finalize_response(finalize)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::certificate_request]
    pub async fn certificate_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        Ok(self.0.write().await.certificate_request(previous_nonce)?)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::get_refresh_token]
    pub async fn get_refresh_token(&self) -> CoreCryptoResult<String> {
        Ok(self.0.read().await.get_refresh_token().map(Into::into)?)
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiAcmeDirectory]
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
}

impl From<core_crypto::prelude::E2eiAcmeDirectory> for AcmeDirectory {
    fn from(directory: core_crypto::prelude::E2eiAcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}

impl From<AcmeDirectory> for core_crypto::prelude::E2eiAcmeDirectory {
    fn from(directory: AcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiNewAcmeOrder]
pub struct NewAcmeOrder {
    pub delegate: Vec<u8>,
    pub authorizations: Vec<String>,
}

impl From<core_crypto::prelude::E2eiNewAcmeOrder> for NewAcmeOrder {
    fn from(new_order: core_crypto::prelude::E2eiNewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}

impl From<NewAcmeOrder> for core_crypto::prelude::E2eiNewAcmeOrder {
    fn from(new_order: NewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiNewAcmeAuthz]
pub struct NewAcmeAuthz {
    pub identifier: String,
    pub keyauth: Option<String>,
    pub challenge: AcmeChallenge,
}

impl From<core_crypto::prelude::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(new_authz: core_crypto::prelude::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::prelude::E2eiNewAcmeAuthz {
    fn from(new_authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}

#[derive(Debug, uniffi::Record)]
/// See [core_crypto::e2e_identity::types::E2eiAcmeChallenge]
pub struct AcmeChallenge {
    pub delegate: Vec<u8>,
    pub url: String,
    pub target: String,
}

impl From<core_crypto::prelude::E2eiAcmeChallenge> for AcmeChallenge {
    fn from(chall: core_crypto::prelude::E2eiAcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}

impl From<AcmeChallenge> for core_crypto::prelude::E2eiAcmeChallenge {
    fn from(chall: AcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{DatabaseKey, MlsError};

    use super::*;
    use core_crypto::LeafError;
    use log::Level;

    #[test]
    fn test_error_mapping() {
        let duplicate_message_error = RecursiveError::mls_conversation("test duplicate message error")(
            core_crypto::mls::conversation::Error::DuplicateMessage,
        );
        let mapped_error = CoreCryptoError::from(duplicate_message_error);
        assert!(matches!(mapped_error, CoreCryptoError::Mls(MlsError::DuplicateMessage)));

        let conversation_exists_error = RecursiveError::mls_conversation("test conversation exists error")(
            core_crypto::mls::conversation::Error::Leaf(LeafError::ConversationAlreadyExists(
                "test conversation id".into(),
            )),
        );
        let mapped_error = CoreCryptoError::from(conversation_exists_error);
        assert!(matches!(
            mapped_error,
            CoreCryptoError::Mls(MlsError::ConversationAlreadyExists(_))
        ));
    }

    #[tokio::test]
    async fn test_error_is_logged() {
        testing_logger::setup();
        // we shouldn't be able to create a SQLite DB in `/root` unless we are running this test as root
        // Don't do that!
        let key = DatabaseKey(core_crypto_keystore::DatabaseKey::generate());
        let result = CoreCrypto::new("/root/asdf".into(), key, None, None, None, None).await;
        assert!(
            result.is_err(),
            "result must be an error in order to verify that something was logged"
        );
        testing_logger::validate(|captured_logs| {
            assert!(
                captured_logs.iter().any(|log| log.level == log::Level::Warn
                    && log.target == "core-crypto"
                    && log.body.contains("returning this error across ffi")),
                "log message did not appear within the captured logs"
            )
        });
    }
}
