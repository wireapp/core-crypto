use core_crypto::{
    RecursiveError,
    mls::conversation::Conversation as _,
    prelude::{ClientIdentifier, KeyPackageIn, MlsConversationConfiguration, VerifiableGroupInfo},
    transaction_context::Error as TransactionError,
};
use tls_codec::{Deserialize as _, Serialize as _};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Ciphersuite, ClientId, ConversationConfiguration, ConversationId, CoreCryptoContext, CoreCryptoError,
    CoreCryptoResult, CredentialType, CustomConfiguration, DecryptedMessage, WelcomeBundle,
    bytes_wrapper::bytes_wrapper, ciphersuite::CiphersuitesMaybeArc, client_id::ClientIdMaybeArc, conversation_id_vec,
    crl::NewCrlDistributionPoints,
};

#[cfg(not(target_family = "wasm"))]
type KeyPackages = Vec<Vec<u8>>;

#[cfg(target_family = "wasm")]
type KeyPackages = super::array_of_byte_array::ArrayOfByteArray;

bytes_wrapper!(SecretKey);

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCryptoContext {
    /// See [core_crypto::transaction_context::TransactionContext::mls_init]
    pub async fn mls_init(
        &self,
        client_id: ClientIdMaybeArc,
        ciphersuites: CiphersuitesMaybeArc,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<()> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CoreCryptoError::generic())?;
        self.inner
            .mls_init(
                ClientIdentifier::Basic(client_id.as_cc()),
                ciphersuites.as_cc(),
                nb_key_package,
            )
            .await?;
        Ok(())
    }

    /// See [core_crypto::transaction_context::TransactionContext::client_public_key]
    pub async fn client_public_key(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> CoreCryptoResult<Vec<u8>> {
        Ok(self
            .inner
            .client_public_key(ciphersuite.into(), credential_type.into())
            .await?)
    }

    /// See [core_crypto::mls::conversation::Conversation::epoch]
    pub async fn conversation_epoch(&self, conversation_id: &ConversationId) -> CoreCryptoResult<u64> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self.inner.conversation(&conversation_id).await?;
        Ok(conversation.epoch().await)
    }

    /// See [core_crypto::mls::conversation::Conversation::ciphersuite]
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let cs = self.inner.conversation(&conversation_id).await?.ciphersuite().await;
        Ok(Ciphersuite::from(core_crypto::prelude::CiphersuiteName::from(cs)))
    }

    /// See [core_crypto::prelude::Session::conversation_exists]
    pub async fn conversation_exists(&self, conversation_id: &ConversationId) -> CoreCryptoResult<bool> {
        let conversation_id = conversation_id_vec!(conversation_id);
        self.inner
            .conversation_exists(&conversation_id)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<ClientIdMaybeArc>> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self.inner.conversation(&conversation_id).await?;
        let client_ids = conversation
            .get_client_ids()
            .await
            .into_iter()
            .map(ClientId::from_cc)
            .collect();
        Ok(client_ids)
    }

    /// See [core_crypto::mls::conversation::Conversation::export_secret_key]
    pub async fn export_secret_key(
        &self,
        conversation_id: &ConversationId,
        key_length: u32,
    ) -> CoreCryptoResult<SecretKey> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self.inner.conversation(&conversation_id).await?;
        conversation
            .export_secret_key(key_length as usize)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<u8>> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self.inner.conversation(&conversation_id).await?;
        conversation.get_external_sender().await.map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::get_or_create_client_keypackages]
    pub async fn client_keypackages(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
        amount_requested: u32,
    ) -> CoreCryptoResult<KeyPackages> {
        let kps = self
            .inner
            .get_or_create_client_keypackages(ciphersuite.into(), credential_type.into(), amount_requested as usize)
            .await
            .map_err(RecursiveError::transaction("getting or creating client keypackages"))?;

        kps.into_iter()
            .map(|kp| {
                kp.tls_serialize_detached()
                    .map_err(core_crypto::mls::conversation::Error::tls_serialize("keypackage"))
                    .map_err(RecursiveError::mls_conversation("serializing keypackage"))
                    .map_err(Into::into)
            })
            .collect::<CoreCryptoResult<KeyPackages>>()
    }

    /// See [core_crypto::transaction_context::TransactionContext::client_valid_key_packages_count]
    pub async fn client_valid_keypackages_count(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> CoreCryptoResult<u64> {
        let count = self
            .inner
            .client_valid_key_packages_count(ciphersuite.into(), credential_type.into())
            .await
            .map_err(RecursiveError::transaction("counting client valid keypackages"))?;

        Ok(count.try_into().unwrap_or(0))
    }

    /// See [core_crypto::transaction_context::TransactionContext::new_conversation]
    pub async fn create_conversation(
        &self,
        conversation_id: &ConversationId,
        creator_credential_type: CredentialType,
        config: ConversationConfiguration,
    ) -> CoreCryptoResult<()> {
        let conversation_id = conversation_id_vec!(conversation_id);

        let mut lower_cfg = MlsConversationConfiguration {
            custom: config.custom.into(),
            ciphersuite: config.ciphersuite.map(Into::into).unwrap_or_default(),
            ..Default::default()
        };

        self.inner
            .set_raw_external_senders(&mut lower_cfg, config.external_senders)
            .await?;

        self.inner
            .new_conversation(&conversation_id, creator_credential_type.into(), lower_cfg)
            .await?;
        Ok(())
    }

    /// See [core_crypto::transaction_context::TransactionContext::process_raw_welcome_message]
    pub async fn process_welcome_message(
        &self,
        welcome_message: Vec<u8>,
        custom_configuration: CustomConfiguration,
    ) -> CoreCryptoResult<WelcomeBundle> {
        let result = self
            .inner
            .process_raw_welcome_message(welcome_message, custom_configuration.into())
            .await?
            .into();
        Ok(result)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::add_members]
    pub async fn add_clients_to_conversation(
        &self,
        conversation_id: &ConversationId,
        key_packages: KeyPackages,
    ) -> CoreCryptoResult<NewCrlDistributionPoints> {
        let conversation_id = conversation_id_vec!(conversation_id);

        #[cfg(target_family = "wasm")]
        let key_packages = key_packages.into_inner();
        let key_packages = key_packages
            .into_iter()
            .map(|kp| {
                KeyPackageIn::tls_deserialize(&mut kp.as_slice())
                    .map_err(core_crypto::mls::conversation::Error::tls_deserialize("keypackage"))
                    .map_err(RecursiveError::mls_conversation("adding members to conversation"))
                    .map_err(Into::into)
            })
            .collect::<CoreCryptoResult<Vec<_>>>()?;

        let mut conversation = self.inner.conversation(&conversation_id).await?;
        let distribution_points: Option<Vec<_>> = conversation.add_members(key_packages).await?.into();
        Ok(distribution_points.into())
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::remove_members]
    pub async fn remove_clients_from_conversation(
        &self,
        conversation_id: &ConversationId,
        clients: Vec<ClientIdMaybeArc>,
    ) -> CoreCryptoResult<()> {
        let clients: Vec<core_crypto::prelude::ClientId> = clients.into_iter().map(|c| c.as_cc()).collect();
        let conversation_id = conversation_id_vec!(conversation_id);
        let mut conversation = self.inner.conversation(&conversation_id).await?;
        conversation.remove_members(&clients).await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::mark_as_child_of]
    pub async fn mark_conversation_as_child_of(
        &self,
        child_id: &ConversationId,
        parent_id: &ConversationId,
    ) -> CoreCryptoResult<()> {
        let parent_id = conversation_id_vec!(parent_id);
        let child_id = conversation_id_vec!(child_id);
        let mut conversation = self.inner.conversation(&child_id).await?;
        conversation.mark_as_child_of(&parent_id).await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::update_key_material]
    pub async fn update_keying_material(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let mut conversation = self.inner.conversation(&conversation_id).await?;
        conversation.update_key_material().await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::commit_pending_proposals]
    pub async fn commit_pending_proposals(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let mut conversation = self.inner.conversation(&conversation_id).await?;
        conversation.commit_pending_proposals().await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::wipe]
    pub async fn wipe_conversation(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let mut conversation = self.inner.conversation(&conversation_id).await?;
        conversation.wipe().await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::decrypt_message]
    pub async fn decrypt_message(
        &self,
        conversation_id: &ConversationId,
        payload: Vec<u8>,
    ) -> CoreCryptoResult<DecryptedMessage> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation_result = self.inner.conversation(&conversation_id).await;
        let decrypted_message = match conversation_result {
            Err(TransactionError::PendingConversation(mut pending)) => {
                pending.try_process_own_join_commit(&payload).await?
            }
            Ok(mut conversation) => conversation.decrypt_message(&payload).await?,
            Err(e) => Err(e)?,
        };

        decrypted_message.try_into()
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::encrypt_message]
    pub async fn encrypt_message(
        &self,
        conversation_id: &ConversationId,
        message: Vec<u8>,
    ) -> CoreCryptoResult<Vec<u8>> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let mut conversation = self.inner.conversation(&conversation_id).await?;
        conversation.encrypt_message(message).await.map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::join_by_external_commit]
    pub async fn join_by_external_commit(
        &self,
        group_info: Vec<u8>,
        custom_configuration: CustomConfiguration,
        credential_type: CredentialType,
    ) -> CoreCryptoResult<WelcomeBundle> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(core_crypto::mls::conversation::Error::tls_deserialize(
                "verifiable group info",
            ))
            .map_err(RecursiveError::mls_conversation("joining by external commmit"))?;
        let welcome_bundle = self
            .inner
            .join_by_external_commit(group_info, custom_configuration.into(), credential_type.into())
            .await?;
        Ok(welcome_bundle.into())
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::enable_history_sharing]
    pub async fn enable_history_sharing(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let mut conversation = self.inner.conversation(&conversation_id).await?;
        conversation.enable_history_sharing().await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::disable_history_sharing]
    pub async fn disable_history_sharing(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let mut conversation = self.inner.conversation(&conversation_id).await?;
        conversation.disable_history_sharing().await.map_err(Into::into)
    }
}
