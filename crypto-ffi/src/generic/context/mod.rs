use crate::{
    Ciphersuite, Ciphersuites, ClientId, ConversationConfiguration, CoreCryptoContext, CoreCryptoError,
    CoreCryptoResult, CredentialType, CustomConfiguration, DecryptedMessage, NewCrlDistributionPoints, WelcomeBundle,
};

use core_crypto::{
    RecursiveError,
    mls::conversation::{Conversation as _, Error as ConversationError},
    prelude::{
        ClientIdentifier, ConversationId, KeyPackageIn, KeyPackageRef, MlsConversationConfiguration,
        VerifiableGroupInfo,
    },
};
use tls_codec::{Deserialize, Serialize};

pub mod e2ei;
pub mod proteus;

#[uniffi::export]
impl CoreCryptoContext {
    /// See [core_crypto::context::CentralContext::set_data].
    pub async fn set_data(&self, data: Vec<u8>) -> CoreCryptoResult<()> {
        self.inner.set_data(data).await.map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::get_data].
    pub async fn get_data(&self) -> CoreCryptoResult<Option<Vec<u8>>> {
        self.inner.get_data().await.map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::mls_init]
    pub async fn mls_init(
        &self,
        client_id: ClientId,
        ciphersuites: Ciphersuites,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<()> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CoreCryptoError::generic())?;
        self.inner
            .mls_init(
                ClientIdentifier::Basic(client_id.0),
                (&ciphersuites).into(),
                nb_key_package,
            )
            .await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::mls_generate_keypairs]
    pub async fn mls_generate_keypairs(&self, ciphersuites: Ciphersuites) -> CoreCryptoResult<Vec<ClientId>> {
        Ok(self
            .inner
            .mls_generate_keypairs((&ciphersuites).into())
            .await
            .map(|cids| cids.into_iter().map(ClientId).collect())?)
    }

    /// See [core_crypto::context::CentralContext::mls_init_with_client_id]
    pub async fn mls_init_with_client_id(
        &self,
        client_id: ClientId,
        tmp_client_ids: Vec<ClientId>,
        ciphersuites: Ciphersuites,
    ) -> CoreCryptoResult<()> {
        Ok(self
            .inner
            .mls_init_with_client_id(
                client_id.0,
                tmp_client_ids.into_iter().map(|cid| cid.0).collect(),
                (&ciphersuites).into(),
            )
            .await?)
    }

    /// See [core_crypto::mls::Client::client_public_key]
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

    /// See [core_crypto::mls::conversation::ConversationGuard::epoch]
    pub async fn conversation_epoch(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<u64> {
        let conversation = self.inner.conversation(&conversation_id).await?;
        Ok(conversation.epoch().await)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::ciphersuite]
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let cs = self.inner.conversation(conversation_id).await?.ciphersuite().await;
        Ok(Ciphersuite::from(core_crypto::prelude::CiphersuiteName::from(cs)))
    }

    /// See [core_crypto::mls::Client::conversation_exists]
    pub async fn conversation_exists(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<bool> {
        Ok(self.inner.conversation_exists(&conversation_id).await?)
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<ClientId>> {
        let client_ids = self
            .inner
            .conversation(&conversation_id)
            .await?
            .get_client_ids()
            .await
            .into_iter()
            .map(ClientId)
            .collect();
        Ok(client_ids)
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::export_secret_key]
    pub async fn export_secret_key(&self, conversation_id: Vec<u8>, key_length: u32) -> CoreCryptoResult<Vec<u8>> {
        self.inner
            .conversation(&conversation_id)
            .await?
            .export_secret_key(key_length as usize)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ImmutableConversation::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        self.inner
            .conversation(&conversation_id)
            .await?
            .get_external_sender()
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::get_or_create_client_keypackages]
    pub async fn client_keypackages(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
        amount_requested: u32,
    ) -> CoreCryptoResult<Vec<Vec<u8>>> {
        let kps = self
            .inner
            .get_or_create_client_keypackages(ciphersuite.into(), credential_type.into(), amount_requested as usize)
            .await
            .map_err(RecursiveError::mls_client("getting or creating client keypackages"))?;

        kps.into_iter()
            .map(|kp| {
                kp.tls_serialize_detached()
                    .map_err(core_crypto::mls::conversation::Error::tls_serialize("keypackage"))
                    .map_err(RecursiveError::mls_conversation("serializing keypackage"))
                    .map_err(Into::into)
            })
            .collect::<CoreCryptoResult<Vec<Vec<u8>>>>()
    }

    /// See [core_crypto::context::CentralContext::client_valid_key_packages_count]
    pub async fn client_valid_keypackages_count(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> CoreCryptoResult<u64> {
        let count = self
            .inner
            .client_valid_key_packages_count(ciphersuite.into(), credential_type.into())
            .await
            .map_err(RecursiveError::mls_client("counting client valid keypackages"))?;

        Ok(count.try_into().unwrap_or(0))
    }

    /// See [core_crypto::context::CentralContext::delete_keypackages]
    pub async fn delete_keypackages(&self, refs: Vec<Vec<u8>>) -> CoreCryptoResult<()> {
        let refs = refs
            .into_iter()
            .map(|r| KeyPackageRef::from_slice(&r))
            .collect::<Vec<_>>();

        self.inner
            .delete_keypackages(&refs[..])
            .await
            .map_err(RecursiveError::mls_client("deleting keypackages"))?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::new_conversation]
    pub async fn create_conversation(
        &self,
        conversation_id: Vec<u8>,
        creator_credential_type: CredentialType,
        config: ConversationConfiguration,
    ) -> CoreCryptoResult<()> {
        let mut lower_cfg = MlsConversationConfiguration {
            custom: config.custom.into(),
            ciphersuite: config.ciphersuite.into(),
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

    /// See [core_crypto::context::CentralContext::process_raw_welcome_message]
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

    /// See [core_crypto::mls::conversation::conversation_guard::ConversationGuard::add_members]
    pub async fn add_clients_to_conversation(
        &self,
        conversation_id: Vec<u8>,
        key_packages: Vec<Vec<u8>>,
    ) -> CoreCryptoResult<NewCrlDistributionPoints> {
        let key_packages = key_packages
            .into_iter()
            .map(|kp| {
                KeyPackageIn::tls_deserialize(&mut kp.as_slice())
                    .map_err(core_crypto::mls::conversation::Error::tls_deserialize("keypackage"))
                    .map_err(RecursiveError::mls_conversation("adding members to conversation"))
                    .map_err(Into::into)
            })
            .collect::<CoreCryptoResult<Vec<_>>>()?;

        let distribution_points: Option<Vec<_>> = self
            .inner
            .conversation(&conversation_id)
            .await?
            .add_members(key_packages)
            .await?
            .into();
        Ok(distribution_points.into())
    }

    /// See [core_crypto::context::CentralContext::remove_members_from_conversation]
    pub async fn remove_clients_from_conversation(
        &self,
        conversation_id: Vec<u8>,
        clients: Vec<ClientId>,
    ) -> CoreCryptoResult<()> {
        let clients: Vec<core_crypto::prelude::ClientId> = clients.into_iter().map(|c| c.0).collect();
        self.inner
            .conversation(&conversation_id)
            .await?
            .remove_members(&clients)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::mark_as_child_of]
    pub async fn mark_conversation_as_child_of(&self, child_id: Vec<u8>, parent_id: Vec<u8>) -> CoreCryptoResult<()> {
        self.inner
            .conversation(&child_id)
            .await?
            .mark_as_child_of(&parent_id)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::update_keying_material]
    pub async fn update_keying_material(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        self.inner
            .conversation(&conversation_id)
            .await?
            .update_key_material()
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::conversation_guard::ConversationGuard::commit_pending_proposals]
    pub async fn commit_pending_proposals(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        self.inner
            .conversation(&conversation_id)
            .await?
            .commit_pending_proposals()
            .await
            .map_err(Into::into)
    }

    /// see [core_crypto::context::CentralContext::wipe_conversation]
    pub async fn wipe_conversation(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        self.inner.wipe_conversation(&conversation_id).await?;
        Ok(())
    }

    /// See [core_crypto::mls::conversation::conversation_guard::ConversationGuard::decrypt_message]
    pub async fn decrypt_message(
        &self,
        conversation_id: Vec<u8>,
        payload: Vec<u8>,
    ) -> CoreCryptoResult<DecryptedMessage> {
        let result = self
            .inner
            .conversation(&conversation_id)
            .await?
            .decrypt_message(&payload)
            .await;
        let decrypted_message = if let Err(ConversationError::PendingConversation(mut pending)) = result {
            pending.try_process_own_join_commit(&payload).await
        } else {
            result
        }?;

        decrypted_message.try_into()
    }

    /// See [core_crypto::mls::conversation::conversation_guard::ConversationGuard::encrypt_message]
    pub async fn encrypt_message(&self, conversation_id: Vec<u8>, message: Vec<u8>) -> CoreCryptoResult<Vec<u8>> {
        self.inner
            .conversation(&conversation_id)
            .await?
            .encrypt_message(message)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::join_by_external_commit]
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
        Ok(self
            .inner
            .join_by_external_commit(group_info, custom_configuration.into(), credential_type.into())
            .await?
            .into())
    }
}
