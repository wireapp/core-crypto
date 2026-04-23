use std::{sync::Arc, time::Duration};

use core_crypto::{
    Ciphersuite as CryptoCiphersuite, CredentialFindFilters, MlsConversationConfiguration,
    mls::conversation::Conversation as _, transaction_context::Error as TransactionError,
};
use core_crypto_keystore::Sha256Hash;

use crate::{
    Ciphersuite, ClientId, ConversationId, CoreCryptoContext, CoreCryptoError, CoreCryptoResult, Credential,
    CredentialRef, CredentialType, DecryptedMessage, KeyPackage, KeyPackageRef, MlsTransport,
    bytes_wrapper::{bytes_wrapper, impl_display_via_hex},
    core_crypto::mls_transport::callback_shim,
};

bytes_wrapper!(
    /// A secret key derived from the group secret.
    ///
    /// This is intended to be used for AVS.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    #[uniffi::export(Eq, Hash, Display)]
    SecretKey infallibly wraps core_crypto::mls::conversation::SecretKey; copy_bytes
);
impl_display_via_hex!(SecretKey);

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
    /// A TLS-serialized Welcome message.
    ///
    /// This structure is defined in RFC 9420:
    /// <https://www.rfc-editor.org/rfc/rfc9420.html#joining-via-welcome-message>.
    #[derive(Debug, Clone)]
    Welcome
);

#[uniffi::export]
impl CoreCryptoContext {
    /// Initializes the MLS client with the given client ID and message transport.
    pub async fn mls_init(&self, client_id: &Arc<ClientId>, transport: Arc<dyn MlsTransport>) -> CoreCryptoResult<()> {
        let transport = callback_shim(transport);
        self.inner
            .mls_init(client_id.as_ref().as_ref().to_owned(), transport)
            .await?;
        Ok(())
    }

    /// Returns the current MLS epoch of the given conversation.
    pub async fn conversation_epoch(&self, conversation_id: &ConversationId) -> CoreCryptoResult<u64> {
        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        Ok(conversation.epoch().await)
    }

    /// Returns the ciphersuite in use for the given conversation.
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let cs = self
            .inner
            .conversation(conversation_id.as_ref())
            .await?
            .ciphersuite()
            .await;
        Ok(Ciphersuite::from(cs))
    }

    /// Get the credential ref for the given conversation.
    pub async fn conversation_credential(&self, conversation_id: &ConversationId) -> CoreCryptoResult<CredentialRef> {
        self.inner
            .conversation(conversation_id.as_ref())
            .await?
            .credential_ref()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Set the credential ref for the given conversation.
    pub async fn set_conversation_credential(
        &self,
        conversation_id: &ConversationId,
        credential_ref: Arc<CredentialRef>,
    ) -> CoreCryptoResult<()> {
        self.inner
            .conversation(conversation_id.as_ref())
            .await?
            .set_credential_by_ref(&credential_ref.0)
            .await
            .map_err(Into::into)
    }

    /// Returns true if a conversation with the given id exists in the local state.
    pub async fn conversation_exists(&self, conversation_id: &ConversationId) -> CoreCryptoResult<bool> {
        self.inner
            .conversation_exists(conversation_id.as_ref())
            .await
            .map_err(Into::into)
    }

    /// Returns the client ids of all members of the given conversation.
    pub async fn get_client_ids(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<Arc<ClientId>>> {
        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        let client_ids = conversation
            .get_client_ids()
            .await
            .into_iter()
            .map(Into::into)
            .map(Arc::new)
            .collect();
        Ok(client_ids)
    }

    /// Derives and exports a secret of `key_length` bytes for the given conversation.
    ///
    /// The secret is derived from the MLS key schedule's exporter mechanism (RFC 9420 §8.5),
    /// which produces output bound to the current group state and epoch. The exported value
    /// changes whenever the epoch advances.
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

    /// Returns the serialized public key of the external sender for the given conversation.
    pub async fn get_external_sender(&self, conversation_id: &ConversationId) -> CoreCryptoResult<ExternalSenderKey> {
        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation
            .get_external_sender()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Creates a new MLS group with the given conversation ID, using the specified credential.
    #[uniffi::method(default(external_sender = None))]
    pub async fn create_conversation(
        &self,
        conversation_id: &ConversationId,
        credential_ref: &CredentialRef,
        external_sender: Option<Arc<ExternalSenderKey>>,
    ) -> CoreCryptoResult<()> {
        let mut lower_cfg = MlsConversationConfiguration {
            ciphersuite: credential_ref.ciphersuite().into(),
            ..Default::default()
        };

        lower_cfg
            .set_raw_external_senders(
                &self.inner.mls_provider().await?,
                external_sender
                    .into_iter()
                    .map(|external_sender| external_sender.copy_bytes()),
            )
            .await?;

        self.inner
            .new_conversation(conversation_id.as_ref(), &credential_ref.0, lower_cfg)
            .await?;
        Ok(())
    }

    /// Joins a conversation by processing an MLS Welcome message, returning the new conversation's ID.
    pub async fn process_welcome_message(&self, welcome_message: Arc<Welcome>) -> CoreCryptoResult<ConversationId> {
        let result = self
            .inner
            .process_raw_welcome_message(welcome_message.as_slice())
            .await?
            .into();
        Ok(result)
    }

    /// Adds members to the conversation using their key packages, sending the resulting commit via the transport.
    pub async fn add_clients_to_conversation(
        &self,
        conversation_id: &ConversationId,
        key_packages: Vec<Arc<KeyPackage>>,
    ) -> CoreCryptoResult<()> {
        let keypackages = key_packages
            .into_iter()
            .map(std::sync::Arc::unwrap_or_clone)
            .map(Into::into)
            .collect();

        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.add_members(keypackages).await.map_err(Into::into)
    }

    /// Removes the specified clients from the conversation, sending the resulting commit via the transport.
    pub async fn remove_clients_from_conversation(
        &self,
        conversation_id: &ConversationId,
        clients: Vec<Arc<ClientId>>,
    ) -> CoreCryptoResult<()> {
        let clients: Vec<&core_crypto::ClientIdRef> = clients.iter().map(|c| c.as_ref().as_ref()).collect();
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.remove_members(&clients).await.map_err(Into::into)
    }

    /// Updates this client's key material in the conversation by sending an update commit.
    pub async fn update_keying_material(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.update_key_material().await.map_err(Into::into)
    }

    /// Commits all pending proposals in the conversation, sending the resulting commit via the transport.
    pub async fn commit_pending_proposals(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.commit_pending_proposals().await.map_err(Into::into)
    }

    /// Destroys the local state of the given conversation; it can no longer be used locally after this call.
    pub async fn wipe_conversation(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.wipe().await.map_err(Into::into)
    }

    /// Decrypts an MLS message received in the given conversation.
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

        Ok(decrypted_message.into())
    }

    /// Encrypts a plaintext message for all members of the given conversation.
    pub async fn encrypt_message(
        &self,
        conversation_id: &ConversationId,
        message: Vec<u8>,
    ) -> CoreCryptoResult<Vec<u8>> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.encrypt_message(message).await.map_err(Into::into)
    }

    /// Joins an existing conversation by constructing an external commit from the given group info.
    pub async fn join_by_external_commit(
        &self,
        group_info: Arc<GroupInfo>,
        credential_ref: Arc<CredentialRef>,
    ) -> CoreCryptoResult<ConversationId> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(core_crypto::mls::conversation::Error::tls_deserialize(
                "verifiable group info",
            ))
            .map_err(RecursiveError::mls_conversation("joining by external commmit"))?;
        let conversation_id = self
            .inner
            .join_by_external_commit(group_info, &credential_ref.0)
            .await?;
        Ok(conversation_id.into())
    }

    /// Enables history sharing for the given conversation.
    pub async fn enable_history_sharing(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.enable_history_sharing().await.map_err(Into::into)
    }

    /// Disables history sharing for the given conversation.
    pub async fn disable_history_sharing(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation.disable_history_sharing().await.map_err(Into::into)
    }

    /// Adds a `Credential` to this client.
    ///
    /// Note that while an arbitrary number of credentials can be generated,
    /// those which are added to a CoreCrypto instance must be distinct in credential type,
    /// signature scheme, and the timestamp of creation. This timestamp has only
    /// 1 second of resolution, limiting the number of credentials which
    /// can be added. This is a known limitation and will be relaxed in the future.
    pub async fn add_credential(&self, credential: Arc<Credential>) -> CoreCryptoResult<CredentialRef> {
        let credential = std::sync::Arc::unwrap_or_clone(credential);
        let credential_ref = self.inner.add_credential(credential.0).await?;
        Ok(credential_ref.into())
    }

    /// Removes a `Credential` from this client.
    pub async fn remove_credential(&self, credential_ref: &Arc<CredentialRef>) -> CoreCryptoResult<()> {
        let credential_ref = credential_ref.as_ref();
        self.inner.remove_credential(&credential_ref.0).await?;
        Ok(())
    }

    /// Get all credentials from this client.
    pub async fn get_credentials(&self) -> CoreCryptoResult<Vec<Arc<CredentialRef>>> {
        self.inner
            .get_credentials()
            .await
            .map(|credentials| credentials.into_iter().map(CredentialRef::from).map(Arc::new).collect())
            .map_err(Into::into)
    }

    /// Generate a `KeyPackage` from the referenced credential.
    ///
    /// Makes no attempt to look up or prune existing keypackages.
    ///
    /// If `lifetime` is set, the keypackages will expire that span into the future.
    /// If it is unset, a default lifetime of approximately 3 months is used.
    #[uniffi::method(default(lifetime = None))]
    pub async fn generate_key_package(
        &self,
        credential_ref: &Arc<CredentialRef>,
        lifetime: Option<Duration>,
    ) -> CoreCryptoResult<Arc<KeyPackage>> {
        let credential_ref = &credential_ref.0;
        self.inner
            .generate_key_package(credential_ref, lifetime)
            .await
            .map(KeyPackage::coerce_arc)
            .map_err(Into::into)
    }

    /// Get a reference to each `KeyPackage` in the database.
    pub async fn get_key_packages(&self) -> CoreCryptoResult<Vec<Arc<KeyPackageRef>>> {
        self.inner
            .get_key_package_refs()
            .await
            .map(|kp_refs| kp_refs.into_iter().map(KeyPackageRef::coerce_arc).collect())
            .map_err(Into::into)
    }

    /// Remove a `KeyPackage` from the database.
    pub async fn remove_key_package(&self, kp_ref: &Arc<KeyPackageRef>) -> CoreCryptoResult<()> {
        self.inner.remove_key_package(kp_ref.as_cc()).await.map_err(Into::into)
    }

    /// Remove all `KeyPackage`s associated with this credential ref.
    pub async fn remove_key_packages_for(&self, credential_ref: &Arc<CredentialRef>) -> CoreCryptoResult<()> {
        self.inner
            .remove_key_packages_for(&credential_ref.0)
            .await
            .map_err(Into::into)
    }
}

#[cfg_attr(any(feature = "wasm", feature = "napi"), uniffi::export)]
impl CoreCryptoContext {
    /// Get all credentials from this client which match the provided parameters.
    ///
    /// Parameters which are unset or `None` match anything. Those with a particular value find only credentials
    /// matching that value.
    #[uniffi::method(default(
        client_id = None,
        public_key = None,
        ciphersuite = None,
        credential_type = None,
        earliest_validity = None,
    ))]
    pub async fn find_credentials_ffi(
        &self,
        client_id: Option<Arc<ClientId>>,
        public_key: Option<Vec<u8>>,
        ciphersuite: Option<Ciphersuite>,
        credential_type: Option<CredentialType>,
        earliest_validity: Option<u64>,
    ) -> CoreCryptoResult<Vec<Arc<CredentialRef>>> {
        self.find_credentials_inner(client_id, public_key, ciphersuite, credential_type, earliest_validity)
            .await
    }
}

#[cfg_attr(not(any(feature = "wasm", feature = "napi")), uniffi::export)]
impl CoreCryptoContext {
    /// Get all credentials from this client which match the provided parameters.
    ///
    /// Parameters which are unset or `None` match anything. Those with a particular value find only credentials
    /// matching that value.
    #[uniffi::method(default(
        client_id = None,
        public_key = None,
        ciphersuite = None,
        credential_type = None,
        earliest_validity = None,
    ))]
    pub async fn find_credentials(
        &self,
        client_id: Option<Arc<ClientId>>,
        public_key: Option<Vec<u8>>,
        ciphersuite: Option<Ciphersuite>,
        credential_type: Option<CredentialType>,
        earliest_validity: Option<u64>,
    ) -> CoreCryptoResult<Vec<Arc<CredentialRef>>> {
        self.find_credentials_inner(client_id, public_key, ciphersuite, credential_type, earliest_validity)
            .await
    }
}

impl CoreCryptoContext {
    /// Get all credentials from this client which match the provided parameters.
    ///
    /// Parameters which are unset or `None` match anything. Those with a particular value find only credentials
    /// matching that value.
    async fn find_credentials_inner(
        &self,
        client_id: Option<Arc<ClientId>>,
        public_key: Option<Vec<u8>>,
        ciphersuite: Option<Ciphersuite>,
        credential_type: Option<CredentialType>,
        earliest_validity: Option<u64>,
    ) -> CoreCryptoResult<Vec<Arc<CredentialRef>>> {
        let client_id = client_id.as_ref().map(|c| c.as_ref().as_ref());

        let ciphersuite = ciphersuite.map(CryptoCiphersuite::from);

        let credential_type = credential_type.map(core_crypto::CredentialType::from);

        let find_filters = CredentialFindFilters {
            client_id,
            public_key_hash: public_key.map(Sha256Hash::hash_from),
            ciphersuite,
            credential_type,
            earliest_validity,
        };

        self.inner
            .find_credentials(find_filters)
            .await
            .map(|credentials| credentials.into_iter().map(CredentialRef::from).map(Arc::new).collect())
            .map_err(Into::into)
    }
}
