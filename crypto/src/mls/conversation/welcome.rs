use super::{Error, Result};
use crate::{
    LeafError, MlsError,
    e2e_identity::NewCrlDistributionPoints,
    group_store::GroupStore,
    prelude::{ConversationId, MlsConversation, MlsConversationConfiguration},
};
use core_crypto_keystore::{connection::FetchFromDatabase, entities::PersistedMlsPendingGroup};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{MlsGroup, Welcome};
use openmls_traits::OpenMlsCryptoProvider;

/// Contains everything client needs to know after decrypting an (encrypted) Welcome message
#[derive(Debug)]
pub struct WelcomeBundle {
    /// MLS Group Id
    pub id: ConversationId,
    /// New CRL distribution points that appeared by the introduction of a new credential
    pub crl_new_distribution_points: NewCrlDistributionPoints,
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
    pub(crate) async fn from_welcome_message(
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
        mls_groups: &mut GroupStore<MlsConversation>,
    ) -> Result<Self> {
        let mls_group_config = configuration.as_openmls_default_configuration()?;

        let group = MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, None).await;

        let group = match group {
            Err(openmls::prelude::WelcomeError::NoMatchingKeyPackage)
            | Err(openmls::prelude::WelcomeError::NoMatchingEncryptionKey) => return Err(Error::OrphanWelcome),
            _ => group.map_err(MlsError::wrap("group could not be created from welcome"))?,
        };

        let id = ConversationId::from(group.group_id().as_slice());
        let existing_conversation = mls_groups.get_fetch(&id[..], &backend.keystore(), None).await;
        let conversation_exists = existing_conversation.ok().flatten().is_some();

        let pending_group = backend.key_store().find::<PersistedMlsPendingGroup>(&id[..]).await;
        let pending_group_exists = pending_group.ok().flatten().is_some();

        if conversation_exists || pending_group_exists {
            return Err(LeafError::ConversationAlreadyExists(id).into());
        }

        Self::from_mls_group(group, configuration, backend).await
    }
}
