use std::{collections::HashMap, sync::Arc};

use core_crypto_keystore::{
    CryptoKeystoreError, ancillary::ConversationIdRef, entities::PersistedMlsGroup, traits::FetchFromDatabase,
};
use openmls::group::{GroupId, MlsGroup};
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};

use super::{Error, Result};
use crate::{
    ConversationConfiguration, ConversationId, KeystoreError, Session,
    mls::conversation::{Conversation, MlsGroupState},
};

impl Conversation {
    /// Restore the conversation of a persisted group, loading openmls's state of it from `storage`.
    fn from_persisted(
        session: &Arc<Session>,
        storage: &impl StorageProvider<CURRENT_VERSION, Error = CryptoKeystoreError>,
        persisted: &PersistedMlsGroup,
    ) -> Result<Self> {
        let group = MlsGroup::load(storage, &GroupId::from_slice(persisted.id.bytes()))
            .map_err(KeystoreError::wrap("loading mls group"))?
            // openmls only loads a group when every piece of its state is there. A row without them was written by the
            // old openmls fork and hasn't been converted.
            .ok_or(Error::MlsGroupInvalidState(
                "the group's row has no openmls state; it may still be in the old openmls fork's format",
            ))?;
        let id = ConversationId::from(group.group_id().as_slice());
        let configuration = ConversationConfiguration {
            cipher_suite: group.ciphersuite().into(),
            ..Default::default()
        };

        // The tnt message counter is stored in the same row as the rest of the group.
        let group = MlsGroupState::new(group, persisted.tnt_tx_counter.into(), persisted.is_pending).into();

        Ok(Self {
            id,
            group,
            configuration,
            session: Arc::downgrade(session),
        })
    }

    /// Load a conversation from the database, even if it is pending.
    ///
    /// The conversation cache loads conversations through this, so it can
    /// produce pending ones also. [`TransactionContext::conversation`] excludes
    /// them for callers who don't want to deal with pending conversations. But
    /// decryption reaches them through [`TransactionContext::decrypt_message`].
    ///
    /// [`TransactionContext::conversation`]:
    ///     crate::transaction_context::TransactionContext::conversation
    /// [`TransactionContext::decrypt_message`]:
    ///     crate::transaction_context::TransactionContext::decrypt_message
    pub(crate) async fn load_including_pending(session: &Arc<Session>, id: impl AsRef<[u8]>) -> Result<Option<Self>> {
        let group = session
            .database()
            .get_borrowed::<PersistedMlsGroup>(ConversationIdRef::new(id.as_ref()))
            .await
            .map_err(KeystoreError::wrap("finding a persisted mls group"))?;
        let Some(group) = group else {
            return Ok(None);
        };
        let connection = session.database().mls_read_connection().await;
        let conversation = Self::from_persisted(session, &connection.storage(), &group)?;
        Ok(Some(conversation))
    }

    /// Load a conversation from the database
    ///
    /// A row marked `is_pending` is a join-by-external-commit awaiting confirmation, not a usable
    /// conversation yet, so it's treated the same as not found here — callers fall back to
    /// [`Self::load_including_pending`] for that case.
    pub(crate) async fn load(session: &Arc<Session>, id: impl AsRef<[u8]>) -> Result<Option<Self>> {
        let Some(conversation) = Self::load_including_pending(session, id).await? else {
            return Ok(None);
        };
        if conversation.group().await.is_pending {
            return Ok(None);
        }
        Ok(Some(conversation))
    }

    /// Replace the group state with the one in the database, in place, so every handle sees it.
    ///
    /// Returns `false`, changing nothing, if the conversation is no longer in the database.
    pub(crate) async fn reload(&self) -> Result<bool> {
        let session = self.session()?;
        let Some(persisted) = Self::load_including_pending(&session, self.id.as_ref()).await? else {
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
        let connection = session.database().mls_read_connection().await;
        let storage = connection.storage();
        groups
            .into_iter()
            .filter(|group| !group.is_pending)
            .map(|group| {
                // we can't just destructure the fields straight out of the group, because we derive `Zeroize`, which
                // zeroizes on drop, which means we are forced to clone all the group's fields, because
                // otherwise the drop impl couldn't run.
                let conversation = Self::from_persisted(session, &storage, &group)?;
                Ok((conversation.id.clone(), conversation))
            })
            .collect()
    }
}
