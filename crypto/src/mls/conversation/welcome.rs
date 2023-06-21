use crate::group_store::GroupStore;
use crate::prelude::{
    ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsConversationConfiguration,
    MlsCustomConfiguration, MlsError,
};
use core_crypto_keystore::entities::PersistedMlsPendingGroup;
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{MlsGroup, MlsMessageIn, MlsMessageInBody, Welcome};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::Deserialize;

impl MlsCentral {
    /// Create a conversation from a TLS serialized MLS Welcome message. The `MlsConversationConfiguration` used in this function will be the default implementation.
    ///
    /// # Arguments
    /// * `welcome` - a TLS serialized welcome message
    /// * `configuration` - configuration of the MLS conversation fetched from the Delivery Service
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// see [MlsCentral::process_welcome_message]
    pub async fn process_raw_welcome_message(
        &mut self,
        welcome: Vec<u8>,
        custom_cfg: MlsCustomConfiguration,
    ) -> CryptoResult<ConversationId> {
        let mut cursor = std::io::Cursor::new(welcome);
        let welcome = MlsMessageIn::tls_deserialize(&mut cursor).map_err(MlsError::from)?;
        self.process_welcome_message(welcome, custom_cfg).await
    }

    /// Create a conversation from a received MLS Welcome message
    ///
    /// # Arguments
    /// * `welcome` - a `Welcome` message received as a result of a commit adding new members to a group
    /// * `configuration` - configuration of the group/conversation
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// Errors can be originating from the KeyStore of from OpenMls:
    /// * if no [openmls::key_packages::KeyPackage] can be read from the KeyStore
    /// * if the message can't be decrypted
    pub async fn process_welcome_message(
        &mut self,
        welcome: MlsMessageIn,
        custom_cfg: MlsCustomConfiguration,
    ) -> CryptoResult<ConversationId> {
        let welcome = match welcome.extract() {
            MlsMessageInBody::Welcome(welcome) => welcome,
            _ => return Err(CryptoError::ImplementationError),
        };
        let cs = welcome.ciphersuite().into();
        let configuration = MlsConversationConfiguration {
            ciphersuite: cs,
            custom: custom_cfg,
            ..Default::default()
        };
        let conversation =
            MlsConversation::from_welcome_message(welcome, configuration, &mut self.mls_backend, &mut self.mls_groups)
                .await?;

        let conversation_id = conversation.id.clone();
        self.mls_groups.insert(conversation_id.clone(), conversation);

        Ok(conversation_id)
    }
}

impl MlsConversation {
    // ? Do we need to provide the ratchet_tree to the MlsGroup? Does everything crumble down if we can't actually get it?
    /// Create the MLS conversation from an MLS Welcome message
    ///
    /// # Arguments
    /// * `welcome` - welcome message to create the group from
    /// * `config` - group configuration
    /// * `backend` - the KeyStore to persist the group
    ///
    /// # Errors
    /// Errors can happen from OpenMls or from the KeyStore
    async fn from_welcome_message(
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
        backend: &mut MlsCryptoProvider,
        mls_groups: &mut GroupStore<MlsConversation>,
    ) -> CryptoResult<Self> {
        let mls_group_config = configuration.as_openmls_default_configuration(backend)?;
        let group = MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, None)
            .await
            .map_err(MlsError::from)?;

        let id = ConversationId::from(group.group_id().as_slice());
        let existing_conversation = mls_groups.get_fetch(&id[..], backend.borrow_keystore_mut(), None).await;
        let conversation_exists = existing_conversation.ok().flatten().is_some();

        let pending_group = backend.key_store().find::<PersistedMlsPendingGroup>(&id[..]).await;
        let pending_group_exists = pending_group.ok().flatten().is_some();

        if conversation_exists || pending_group_exists {
            return Err(CryptoError::ConversationAlreadyExists(id));
        }

        Self::from_mls_group(group, configuration, backend).await
    }
}
