use core_crypto_keystore::{Database, entities::PersistedMlsPendingGroup, traits::FetchFromDatabase};
use openmls::prelude::{MlsGroup, Welcome};
use openmls_traits::OpenMlsCryptoProvider;
use wire_e2e_identity::NewCrlDistributionPoints;

use super::{Error, Result};
use crate::{
    ConversationId, LeafError, MlsConversation, MlsConversationConfiguration, MlsError, group_store::GroupStore,
    mls_provider::MlsCryptoProvider,
};

/// Contains everything client needs to know after decrypting an (encrypted) Welcome message
#[derive(Debug)]
pub struct WelcomeBundle {
    /// MLS Group Id
    pub id: ConversationId,
    /// New CRL distribution points that appeared by the introduction of a new credential
    pub crl_new_distribution_points: NewCrlDistributionPoints,
}

impl MlsConversation {
    // ? Do we need to provide the ratchet_tree to the MlsGroup? Does everything crumble down if we can't actually get
    // it?
    /// Create the MLS conversation from an MLS Welcome message
    pub(crate) async fn from_welcome_message(
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
        provider: &MlsCryptoProvider,
        database: &Database,
        mls_groups: &mut GroupStore<MlsConversation>,
    ) -> Result<Self> {
        let mls_group_config = configuration.as_openmls_default_configuration()?;

        let group = MlsGroup::new_from_welcome(provider, &mls_group_config, welcome, None)
            .await
            .map_err(|err| {
                use openmls::prelude::WelcomeError;
                match err {
                    WelcomeError::NoMatchingKeyPackage | WelcomeError::NoMatchingEncryptionKey => Error::OrphanWelcome,
                    _ => MlsError::wrap("group could not be created from welcome")(err).into(),
                }
            })?;

        let id = ConversationId::from(group.group_id().as_slice());
        let existing_conversation = mls_groups.get_fetch(&id, database, None).await;
        let conversation_exists = existing_conversation.ok().flatten().is_some();

        let pending_group = provider
            .key_store()
            .get_borrowed::<PersistedMlsPendingGroup>(id.as_ref())
            .await;
        let pending_group_exists = pending_group.ok().flatten().is_some();

        if conversation_exists || pending_group_exists {
            return Err(LeafError::ConversationAlreadyExists(id).into());
        }

        Self::from_mls_group(group, configuration, database).await
    }
}
