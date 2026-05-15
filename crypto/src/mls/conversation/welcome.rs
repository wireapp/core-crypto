use core_crypto_keystore::{Database, entities::PersistedMlsPendingGroup, traits::FetchFromDatabase};
use openmls::prelude::{MlsGroup, MlsMessageIn, MlsMessageOut, Welcome};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Deserialize as _, Serialize as _};

use super::{Error, Result};
use crate::{
    ConversationId, LeafError, MlsConversation, MlsConversationConfiguration, MlsError,
    mls::conversation_cache::MlsConversationCache, mls_provider::MlsCryptoProvider,
};

/// A Welcome Message as defined in RFC 9420.
///
/// This type is fallibly parseable from raw bytes.
#[derive(Debug, Clone, derive_more::From, derive_more::Into)]
pub struct WelcomeMessage(pub(crate) MlsMessageIn);

impl TryFrom<&[u8]> for WelcomeMessage {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        MlsMessageIn::tls_deserialize_exact(bytes)
            .map(Self)
            .map_err(Error::tls_deserialize("deserializing welcome message as MlsMessageIn"))
    }
}

impl TryFrom<Vec<u8>> for WelcomeMessage {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        value.as_slice().try_into()
    }
}

impl From<MlsMessageOut> for WelcomeMessage {
    fn from(value: MlsMessageOut) -> Self {
        Self(value.into())
    }
}

impl WelcomeMessage {
    /// Serialize this message per the TLS encoding in the spec
    pub fn serialize(&self) -> Result<Vec<u8>> {
        MlsMessageOut::from(self.0.clone())
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("serializing welcome message as MlsMessageOut"))
    }
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
        mls_groups: &mut MlsConversationCache,
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
        let existing_conversation = mls_groups.get_or_fetch(&id, database).await;
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
