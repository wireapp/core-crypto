use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};

use core_crypto_keystore::{ancillary::ConversationIdRef, entities::PersistedMlsGroup, traits::FetchFromDatabase};
use openmls::group::MlsGroup;

use super::Result;
use crate::{
    ConversationConfiguration, ConversationId, KeystoreError, Session,
    mls::conversation::{Conversation, MlsGroupState},
};

impl Conversation {
    /// restore the conversation from a persisted group
    fn from_persisted(session: Weak<Session>, persisted: &PersistedMlsGroup) -> Result<Self> {
        let group: MlsGroup =
            core_crypto_keystore::deser(&persisted.state).map_err(KeystoreError::wrap("deserializing group state"))?;
        let id = ConversationId::from(group.group_id().as_slice());
        let configuration = ConversationConfiguration {
            cipher_suite: group.ciphersuite().into(),
            ..Default::default()
        };

        // The tnt message counter is stored in the same row as the rest of the group.
        let group = MlsGroupState::new(group, persisted.tnt_tx_counter.into()).into();

        Ok(Self {
            id,
            group,
            configuration,
            session,
        })
    }

    /// Load a conversation from the database
    ///
    /// A row marked `is_pending` is a join-by-external-commit awaiting confirmation, not a usable
    /// conversation yet, so it's treated the same as not found here — callers fall back to
    /// [`crate::transaction_context::TransactionContext::pending_conversation`] for that case.
    pub(crate) async fn load(session: &Arc<Session>, id: impl AsRef<[u8]>) -> Result<Option<Self>> {
        let group = session
            .database()
            .get_borrowed::<PersistedMlsGroup>(ConversationIdRef::new(id.as_ref()))
            .await
            .map_err(KeystoreError::wrap("finding a persisted mls group"))?;
        let Some(group) = group.filter(|group| !group.is_pending) else {
            return Ok(None);
        };
        let conversation = Self::from_persisted(Arc::downgrade(session), &group)?;
        Ok(Some(conversation))
    }

    /// Replace the group state with the one in the database, in place, so every handle sees it.
    ///
    /// Returns `false`, changing nothing, if the conversation is no longer in the database.
    pub(crate) async fn reload(&self) -> Result<bool> {
        let session = self.session()?;
        let Some(persisted) = Self::load(&session, self.id.as_ref()).await? else {
            return Ok(false);
        };
        *self.group.write().await = persisted.group.into_inner();
        Ok(true)
    }

    /// Effectively `Database::load_all::<PersistedMlsGroup>` but with better types
    ///
    /// Skips rows marked `is_pending`, for the same reason [`Self::load`] does.
    pub(crate) async fn load_all(session: &Arc<Session>) -> Result<HashMap<ConversationId, Self>> {
        let groups = session
            .database()
            .load_all::<PersistedMlsGroup>()
            .await
            .map_err(KeystoreError::wrap("finding all persisted mls groups"))?;
        groups
            .into_iter()
            .filter(|group| !group.is_pending)
            .map(|group| {
                // we can't just destructure the fields straight out of the group, because we derive `Zeroize`, which
                // zeroizes on drop, which means we are forced to clone all the group's fields, because
                // otherwise the drop impl couldn't run.
                let conversation = Self::from_persisted(Arc::downgrade(session), &group)?;
                Ok((conversation.id.clone(), conversation))
            })
            .collect()
    }
}
