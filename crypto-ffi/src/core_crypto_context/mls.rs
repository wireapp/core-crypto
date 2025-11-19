use std::time::Duration;

use core_crypto::{
    Ciphersuite as CryptoCiphersuite, ClientIdentifier, CredentialFindFilters, KeyPackageIn,
    MlsConversationConfiguration, RecursiveError, VerifiableGroupInfo, mls::conversation::Conversation as _,
    transaction_context::Error as TransactionError,
};
use tls_codec::{Deserialize as _, Serialize as _};

use crate::{
    Ciphersuite, ClientId, ConversationConfiguration, ConversationId, CoreCryptoContext, CoreCryptoResult,
    CredentialRef, CredentialType, CustomConfiguration, DecryptedMessage, WelcomeBundle, bytes_wrapper::bytes_wrapper,
    client_id::ClientIdMaybeArc, credential::CredentialMaybeArc, credential_ref::CredentialRefMaybeArc,
    crl::NewCrlDistributionPoints,
};

bytes_wrapper!(
    /// A secret key derived from the group secret.
    ///
    /// This is intended to be used for AVS.
    SecretKey
);
bytes_wrapper!(
    /// The raw public key of an external sender.
    ///
    /// This can be used to initialize a subconversation.
    #[derive(Debug, Clone)]
    ExternalSenderKey
);
bytes_wrapper!(
    /// MLS Group Information
    ///
    /// This is used when joining by external commit.
    /// It can be found within the `GroupInfoBundle` within a `CommitBundle`.
    #[derive(Debug, Clone)]
    GroupInfo
);
bytes_wrapper!(
    /// A signed object describing a client's identity and capabilities.
    ///
    /// Includes a public key that can be used to encrypt to that client.
    /// Other clients can use a client's KeyPackage to introduce that client to a new group.
    KeyPackage
);

impl KeyPackage {
    pub(crate) fn from_cc(kp: &core_crypto::KeyPackage) -> CoreCryptoResult<KeyPackageMaybeArc> {
        kp.tls_serialize_detached()
            .map(key_package_coerce_maybe_arc)
            .map_err(core_crypto::mls::conversation::Error::tls_serialize("keypackage"))
            .map_err(RecursiveError::mls_conversation("serializing keypackage"))
            .map_err(Into::into)
    }
}

bytes_wrapper!(
    /// A lightweight distinct reference to a `KeyPackage` sufficient to uniquely identify it
    KeyPackageRef
);

impl KeyPackageRef {
    pub(crate) fn from_cc(kp_ref: &core_crypto::KeyPackageRef) -> KeyPackageRefMaybeArc {
        key_package_ref_coerce_maybe_arc(kp_ref.as_slice())
    }
}

bytes_wrapper!(
    /// A TLS-serialized Welcome message.
    ///
    /// This structure is defined in RFC 9420:
    /// <https://www.rfc-editor.org/rfc/rfc9420.html#joining-via-welcome-message>.
    #[derive(Debug, Clone)]
    Welcome
);

#[uniffi::export]
impl CoreCryptoContext {
    /// See [core_crypto::transaction_context::TransactionContext::mls_init]
    pub async fn mls_init(&self, client_id: &ClientIdMaybeArc, ciphersuites: Vec<Ciphersuite>) -> CoreCryptoResult<()> {
        self.inner
            .mls_init(
                ClientIdentifier::Basic(client_id.as_cc()),
                &ciphersuites
                    .into_iter()
                    .map(CryptoCiphersuite::from)
                    .collect::<Vec<_>>(),
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
        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        Ok(conversation.epoch().await)
    }

    /// See [core_crypto::mls::conversation::Conversation::ciphersuite]
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let cs = self
            .inner
            .conversation(conversation_id.as_ref())
            .await?
            .ciphersuite()
            .await;
        Ok(Ciphersuite::from(cs))
    }

    /// See [core_crypto::Session::conversation_exists]
    pub async fn conversation_exists(&self, conversation_id: &ConversationId) -> CoreCryptoResult<bool> {
        self.inner
            .conversation_exists(conversation_id.as_ref())
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<ClientIdMaybeArc>> {
        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
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
        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation
            .export_secret_key(key_length as usize)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: &ConversationId) -> CoreCryptoResult<ExternalSenderKey> {
        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation
            .get_external_sender()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::get_or_create_client_keypackages]
    pub async fn client_keypackages(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
        amount_requested: u32,
    ) -> CoreCryptoResult<Vec<KeyPackageMaybeArc>> {
        let kps = self
            .inner
            .get_or_create_client_keypackages(ciphersuite.into(), credential_type.into(), amount_requested as usize)
            .await
            .map_err(RecursiveError::transaction("getting or creating client keypackages"))?;

        kps.into_iter()
            .map(|kp| {
                kp.tls_serialize_detached()
                    .map(key_package_coerce_maybe_arc)
                    .map_err(core_crypto::mls::conversation::Error::tls_serialize("keypackage"))
                    .map_err(RecursiveError::mls_conversation("serializing keypackage"))
                    .map_err(Into::into)
            })
            .collect::<CoreCryptoResult<_>>()
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
        let mut lower_cfg = MlsConversationConfiguration {
            custom: config.custom.into(),
            ciphersuite: config.ciphersuite.map(Into::into).unwrap_or_default(),
            ..Default::default()
        };

        self.inner
            .set_raw_external_senders(
                &mut lower_cfg,
                config
                    .external_senders
                    .into_iter()
                    .map(|external_sender| external_sender.copy_bytes()),
            )
            .await?;

        self.inner
            .new_conversation(conversation_id.as_ref(), creator_credential_type.into(), lower_cfg)
            .await?;
        Ok(())
    }

    /// See [core_crypto::transaction_context::TransactionContext::process_raw_welcome_message]
    pub async fn process_welcome_message(
        &self,
        welcome_message: WelcomeMaybeArc,
        custom_configuration: CustomConfiguration,
    ) -> CoreCryptoResult<WelcomeBundle> {
        let result = self
            .inner
            .process_raw_welcome_message(welcome_message.as_slice(), custom_configuration.into())
            .await?
            .into();
        Ok(result)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::add_members]
    pub async fn add_clients_to_conversation(
        &self,
        conversation_id: &ConversationId,
        key_packages: Vec<KeyPackageMaybeArc>,
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

        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        let distribution_points = conversation.add_members(key_packages).await?.into();
        Ok(distribution_points)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::remove_members]
    pub async fn remove_clients_from_conversation(
        &self,
        conversation_id: &ConversationId,
        clients: Vec<ClientIdMaybeArc>,
    ) -> CoreCryptoResult<()> {
        let clients: Vec<core_crypto::ClientId> = clients.into_iter().map(|c| c.as_cc()).collect();
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.remove_members(&clients).await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::mark_as_child_of]
    pub async fn mark_conversation_as_child_of(
        &self,
        child_id: &ConversationId,
        parent_id: &ConversationId,
    ) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(child_id.as_ref()).await?;
        conversation
            .mark_as_child_of(parent_id.as_ref())
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::update_key_material]
    pub async fn update_keying_material(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.update_key_material().await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::commit_pending_proposals]
    pub async fn commit_pending_proposals(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.commit_pending_proposals().await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::wipe]
    pub async fn wipe_conversation(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.wipe().await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::decrypt_message]
    pub async fn decrypt_message(
        &self,
        conversation_id: &ConversationId,
        payload: Vec<u8>,
    ) -> CoreCryptoResult<DecryptedMessage> {
        let conversation_result = self.inner.conversation(conversation_id.as_ref()).await;
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
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.encrypt_message(message).await.map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::join_by_external_commit]
    pub async fn join_by_external_commit(
        &self,
        group_info: GroupInfoMaybeArc,
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
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.enable_history_sharing().await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::disable_history_sharing]
    pub async fn disable_history_sharing(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.disable_history_sharing().await.map_err(Into::into)
    }

    /// Add a [`Credential`][crate::Credential] to this client.
    ///
    /// Note that while an arbitrary number of credentials can be generated,
    /// those which are added to a CC instance must be distinct in credential type,
    /// signature scheme, and the timestamp of creation. This timestamp has only
    /// 1 second of resolution, limiting the number of credentials which
    /// can be added. This is a known limitation and will be relaxed in the future.
    pub async fn add_credential(&self, credential: CredentialMaybeArc) -> CoreCryptoResult<CredentialRef> {
        let credential = std::sync::Arc::unwrap_or_clone(credential);
        let credential_ref = self.inner.add_credential(credential.0).await?;
        Ok(credential_ref.into())
    }

    /// Remove a [`Credential`][crate::Credential] from this client.
    pub async fn remove_credential(&self, credential_ref: &CredentialRefMaybeArc) -> CoreCryptoResult<()> {
        let credential_ref = credential_ref.as_ref();
        self.inner.remove_credential(&credential_ref.0).await?;
        Ok(())
    }

    /// Get all credentials from this client.
    pub async fn get_credentials(&self) -> CoreCryptoResult<Vec<CredentialRefMaybeArc>> {
        self.inner
            .get_credentials()
            .await
            .map(|credentials| {
                credentials
                    .into_iter()
                    .map(CredentialRef::from)
                    .map(CredentialRef::into_maybe_arc)
                    .collect()
            })
            .map_err(Into::into)
    }

    /// Get all credentials from this client which match the provided parameters.
    ///
    /// Parameters which are unset or `None` match anything. Those with a particular value find only credentials matching that value.
    pub async fn find_credentials(
        &self,
        client_id: Option<ClientIdMaybeArc>,
        public_key: Option<Vec<u8>>,
        ciphersuite: Option<Ciphersuite>,
        credential_type: Option<CredentialType>,
        earliest_validity: Option<u64>,
    ) -> CoreCryptoResult<Vec<CredentialRefMaybeArc>> {
        let client_id = client_id.as_ref().map(|client_id| client_id.as_cc());
        let client_id = client_id.as_ref().map(|client_id| client_id.as_ref());

        let ciphersuite = ciphersuite.map(CryptoCiphersuite::from);

        let credential_type = credential_type.map(core_crypto::CredentialType::from);

        let find_filters = CredentialFindFilters {
            client_id,
            public_key: public_key.as_deref(),
            ciphersuite,
            credential_type,
            earliest_validity,
        };

        self.inner
            .find_credentials(find_filters)
            .await
            .map(|credentials| {
                credentials
                    .into_iter()
                    .map(CredentialRef::from)
                    .map(CredentialRef::into_maybe_arc)
                    .collect()
            })
            .map_err(Into::into)
    }

    /// Generate a `KeyPackage` from the referenced credential.
    ///
    /// Makes no attempt to look up or prune existing keypackges.
    ///
    /// If `lifetime` is set, the keypackages will expire that span into the future.
    /// If it is unset, a default lifetime of approximately 3 months is used.
    pub async fn generate_keypackage(
        &self,
        credential_ref: &CredentialRefMaybeArc,
        lifetime: Option<Duration>,
    ) -> CoreCryptoResult<KeyPackageMaybeArc> {
        let credential_ref = &credential_ref.0;
        self.inner
            .generate_keypackage(credential_ref, lifetime)
            .await
            .map_err(Into::into)
            .and_then(|kp| KeyPackage::from_cc(&kp))
    }

    /// Get a reference to each `KeyPackage` in the database.
    pub async fn get_keypackages(&self) -> CoreCryptoResult<Vec<KeyPackageRefMaybeArc>> {
        self.inner
            .get_keypackage_refs()
            .await
            .map(|kp_refs| kp_refs.iter().map(KeyPackageRef::from_cc).collect())
            .map_err(Into::into)
    }

    /// Remove a [`KeyPackage`] from the database.
    pub async fn remove_keypackage(&self, kp_ref: &KeyPackageRefMaybeArc) -> CoreCryptoResult<()> {
        let kp_ref = core_crypto::KeyPackageRef::from(kp_ref.0.as_slice());
        self.inner.remove_keypackage(&kp_ref).await.map_err(Into::into)
    }

    /// Remove all [`KeyPackage`]s associated with this ref.
    pub async fn remove_keypackages_for(&self, credential_ref: &CredentialRefMaybeArc) -> CoreCryptoResult<()> {
        self.inner
            .remove_keypackages_for(&credential_ref.0)
            .await
            .map_err(Into::into)
    }
}
