use std::collections::HashMap;

use core_crypto_keystore::{entities::PersistedMlsGroup, traits::FetchFromDatabase};
use openmls::group::MlsGroup;

use super::Result;
use crate::{
    ConversationId, KeystoreError, MlsConversationConfiguration, Session, mls::conversation::ImmutableConversation,
};

impl ImmutableConversation {
    /// restore the conversation from a persistence-saved serialized Group State.
    fn from_serialized_state(session: Session, buf: Vec<u8>) -> Result<Self> {
        let group: MlsGroup =
            core_crypto_keystore::deser(&buf).map_err(KeystoreError::wrap("deserializing group state"))?;
        let id = ConversationId::from(group.group_id().as_slice());
        let configuration = MlsConversationConfiguration {
            ciphersuite: group.ciphersuite().into(),
            ..Default::default()
        };

        Ok(Self {
            id,
            group,
            configuration,
            session,
        })
    }

    /// Load a conversation from the database
    pub(crate) async fn load(session: Session, id: impl AsRef<[u8]>) -> Result<Option<Self>> {
        let group = session
            .database()
            .get_borrowed::<PersistedMlsGroup>(id.as_ref())
            .await
            .map_err(KeystoreError::wrap("finding a persisted mls group"))?;
        let Some(mut group) = group else { return Ok(None) };
        let conversation = Self::from_serialized_state(session, std::mem::take(&mut group.state))?;
        Ok(Some(conversation))
    }

    /// Effectively [`Database::mls_groups_restore`] but with better types
    pub(crate) async fn load_all(session: Session) -> Result<HashMap<ConversationId, Self>> {
        let groups = session
            .database()
            .load_all::<PersistedMlsGroup>()
            .await
            .map_err(KeystoreError::wrap("finding all persisted mls groups"))?;
        groups
            .into_iter()
            .map(|group| {
                // we can't just destructure the fields straight out of the group, because we derive `Zeroize`, which
                // zeroizes on drop, which means we are forced to clone all the group's fields, because
                // otherwise the drop impl couldn't run.
                let conversation = Self::from_serialized_state(session.clone(), group.state.clone())?;
                Ok((group.id.clone().into(), conversation))
            })
            .collect()
    }
}
