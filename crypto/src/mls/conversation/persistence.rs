use std::collections::HashMap;

use core_crypto_keystore::{
    CryptoKeystoreMls as _,
    connection::FetchFromDatabase as _,
    entities::{EntityFindParams, PersistedMlsGroup},
};
use mls_crypto_provider::Database;
use openmls::group::{InnerState, MlsGroup};

use super::Result;
use crate::{ConversationId, KeystoreError, MlsConversation, MlsConversationConfiguration};

impl MlsConversation {
    pub(crate) async fn persist_group_when_changed(&mut self, keystore: &Database, force: bool) -> Result<()> {
        if force || self.group.state_changed() == InnerState::Changed {
            keystore
                .mls_group_persist(
                    &self.id,
                    &core_crypto_keystore::ser(&self.group).map_err(KeystoreError::wrap("serializing group state"))?,
                    self.parent_id.as_ref().map(|id| id.as_ref()),
                )
                .await
                .map_err(KeystoreError::wrap("persisting mls group"))?;

            self.group.set_state(InnerState::Persisted);
        }

        Ok(())
    }

    /// restore the conversation from a persistence-saved serialized Group State.
    pub(crate) fn from_serialized_state(buf: Vec<u8>, parent_id: Option<ConversationId>) -> Result<Self> {
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
            parent_id,
            configuration,
        })
    }

    /// Effectively [`Database::mls_groups_restore`] but with better types
    pub(crate) async fn load_all(keystore: &Database) -> Result<HashMap<ConversationId, Self>> {
        let groups = keystore
            .find_all::<PersistedMlsGroup>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all persisted mls groups"))?;
        groups
            .into_iter()
            .map(|group| {
                // we can't just destructure the fields straight out of the group, because we derive `Zeroize`, which zeroizes on drop,
                // which means we are forced to clone all the group's fields, because otherwise the drop impl couldn't run.
                let conversation =
                    Self::from_serialized_state(group.state.clone(), group.parent_id.clone().map(Into::into))?;
                Ok((group.id.clone().into(), conversation))
            })
            .collect()
    }
}
