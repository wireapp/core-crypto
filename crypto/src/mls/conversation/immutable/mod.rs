mod clients;
mod commit_delay;
mod credential;
mod duplicate;
mod e2ei;
mod history_sharing;
mod persistence;

use async_lock::{RwLock, RwLockReadGuard};
use core_crypto_keystore::{
    Transaction,
    ancillary::ConversationIdRef as KeystoreConversationIdRef,
    entities::{PersistedMlsGroup, TntMessageTxCounter},
    traits::{EntityDatabaseMutation as _, EntityDeleteBorrowed as _, FetchFromDatabase},
};
use openmls::group::{InnerState, MlsGroup};

use super::{ConversationIdRef, Error, Result, SecretKey, group_metadata};
use crate::{
    CipherSuite, ConversationConfiguration, ConversationId, CredentialRef, ExternalSender, KeystoreError, OpenMlsError,
    Session, mls::TntMessageCounter,
};

#[derive(derive_more::Constructor, derive_more::Deref, derive_more::DerefMut, derive_more::Debug)]
pub(crate) struct MlsGroupState {
    #[deref]
    #[deref_mut]
    group: MlsGroup,
    /// The count of transient messages plus targeted messages sent (hereafter `tx`) this epoch.
    /// Supposed to be used when encrypting tnt messages only, and to be reset whenever the mls epoch is
    /// incremented. Do not access this field directly, use [MlsGroupState::obtain_tnt_message_tx_counter] and
    /// [MlsGroupState::reset_tnt_message_tx_counter] only.
    ///
    /// The purpose of these counters is replay protection on the recipient side: we provide the count when sending a
    /// message to a receiver, and they check if the counter is greater than any they've seen before.
    tnt_message_tx_counter: TntMessageCounter,
}

impl MlsGroupState {
    pub(in crate::mls::conversation) fn mls_group(&self) -> &MlsGroup {
        &self.group
    }

    pub(in crate::mls::conversation) fn mls_group_mut(&mut self) -> &mut MlsGroup {
        &mut self.group
    }

    /// Get the transient message sender (tx) counter bound to this conversation after incrementing it.
    ///
    /// If the counter hasn't been used yet for this conversation, it is loaded from the database or initialized
    /// freshly.
    pub(in crate::mls::conversation) async fn obtain_tnt_message_tx_counter(
        &mut self,
        database: &impl FetchFromDatabase,
    ) -> Result<TntMessageCounter> {
        let mut counter = self.tnt_message_tx_counter;

        if counter.is_zero() {
            counter = database
                .get_borrowed::<TntMessageTxCounter>(KeystoreConversationIdRef::new(self.group_id().as_slice()))
                .await
                .map_err(KeystoreError::wrap("searching for tnt message counters for group"))?
                .map(|counter| counter.count)
                .unwrap_or_default()
                .into();
        }

        counter.increment()?;
        self.tnt_message_tx_counter = counter;
        self.group.set_state(InnerState::Changed);

        Ok(counter)
    }

    pub(in crate::mls::conversation) async fn reset_tnt_message_tx_counter(&mut self, tx: &Transaction) -> Result<()> {
        self.tnt_message_tx_counter = Default::default();
        let id = KeystoreConversationIdRef::new(self.group.group_id().as_slice());
        TntMessageTxCounter::delete_borrowed(tx, id)
            .map_err(KeystoreError::wrap("removing transient message tx counter"))?;
        Ok(())
    }

    pub(crate) async fn persist(&mut self, tx: &Transaction) -> Result<()> {
        // We must change the mls group persisted state before persisting, otherwise it will never reach the DB.
        self.mls_group_mut().set_state(InnerState::Persisted);
        let id = self.group.group_id();
        let group = self.mls_group();

        // While we are an active member the group itself tells us which credential we present. Once
        // we have been evicted it no longer does: our leaf is gone from the ratchet tree, and our
        // former slot may even have been recycled by a member added in the same commit, in which
        // case `own_leaf_index` resolves to *their* leaf and we would link this conversation to
        // their credential. We deliberately keep persisting evicted conversations, so rather than
        // derive, reuse what the row already records — the credential we held while we were a
        // member is still the one we used, and being evicted does not change that.
        let (credential_id, credential_type) = if group.is_active() {
            let current_credential = group_metadata::current_credential_pk(group, tx).await?;
            (current_credential.public_key_hash, current_credential.credential_type)
        } else {
            let persisted = tx
                .get_borrowed::<PersistedMlsGroup>(KeystoreConversationIdRef::new(id.as_slice()))
                .await
                .map_err(KeystoreError::wrap("finding the existing row of an evicted conversation"))?
                // We can only have been evicted from a conversation we were a member of, and
                // joining one always persists it, so the row is always already there: the only
                // other caller of this function performs the first persist of a group we have just
                // joined or created, which is necessarily still active.
                .ok_or(Error::MlsGroupInvalidState(
                    "an evicted conversation must already have been persisted",
                ))?;
            (persisted.credential_id, persisted.credential_type)
        };

        PersistedMlsGroup {
            id: id.as_slice().into(),
            state: core_crypto_keystore::ser(group).map_err(KeystoreError::wrap("serializing group state"))?,
            epoch: group.epoch().as_u64(),
            ciphersuite: group.ciphersuite() as u16,
            credential_id: current_credential.as_ref().map(|credential| credential.public_key_hash),
            credential_type: current_credential.as_ref().map(|credential| credential.credential_type),
            own_leaf_index: group.own_leaf_index().u32(),
            // `persist` is reached either by an established conversation persisting a normal
            // change, or by `persist_conversation_from_mls_group` once an external commit has
            // already been merged — either way, this group is no longer pending by the time this
            // runs.
            is_pending: false,
        }
        .save(tx)
        .map_err(KeystoreError::wrap("persisting mls group"))?;

        TntMessageTxCounter {
            conversation_id: id.as_slice().into(),
            count: self.tnt_message_tx_counter.into(),
        }
        .save(tx)
        .map_err(KeystoreError::wrap("saving transient message tx counter"))?;

        Ok(())
    }
}

/// A Conversation exposes the read-only interface of an MLS conversation.
#[derive(Debug, derive_more::Constructor)]
pub struct Conversation {
    pub(in crate::mls::conversation) id: ConversationId,
    pub(in crate::mls::conversation) group: RwLock<MlsGroupState>,
    pub(in crate::mls::conversation) configuration: ConversationConfiguration,
    session: Session,
}

impl Conversation {
    /// Returns the conversation's ID
    pub fn id(&self) -> &ConversationIdRef {
        self.id.as_ref()
    }

    /// Returns an immutable guard over the underlying MLS group
    pub(crate) async fn group(&self) -> RwLockReadGuard<'_, MlsGroupState> {
        self.group.read().await
    }

    /// Returns the conversation's configuration
    pub fn configuration(&self) -> &ConversationConfiguration {
        &self.configuration
    }

    /// Returns current epoch of the MLS group
    pub async fn epoch(&self) -> u64 {
        self.group().await.epoch().as_u64()
    }

    /// Returns this conversation's cipher suite
    pub fn cipher_suite(&self) -> CipherSuite {
        self.configuration.cipher_suite
    }

    /// Returns a reference to the credential used in this conversation
    pub async fn credential_ref(&self) -> Result<CredentialRef> {
        let credential = self
            .find_current_credential()
            .await
            .map_err(|_| Error::IdentityInitializationError)?;
        Ok(CredentialRef::from_credential(&credential))
    }

    /// Derives a new key from the one in the group, to be used elsewhere.
    ///
    /// # Arguments
    /// * `key_length` - the length of the key to be derived. If the value is higher than the bounds of `u16` or the
    ///   context hash * 255, an error will be returned
    ///
    /// # Errors
    /// OpenMls secret generation error
    pub async fn export_secret_key(&self, key_length: usize) -> Result<SecretKey> {
        const EXPORTER_LABEL: &str = "exporter";
        const EXPORTER_CONTEXT: &[u8] = &[];
        self.group()
            .await
            .export_secret(
                &self.session.crypto_provider,
                EXPORTER_LABEL,
                EXPORTER_CONTEXT,
                key_length,
            )
            .map(Into::into)
            .map_err(OpenMlsError::wrap("exporting secret key"))
            .map_err(Into::into)
    }

    /// Returns the first external sender present in this group.
    ///
    /// This should be used to initialize a subconversation
    pub async fn get_external_sender(&self) -> Result<ExternalSender> {
        let group = self.group().await;
        let ext_senders = group
            .group_context_extensions()
            .external_senders()
            .ok_or(Error::MissingExternalSenderExtension)?;
        let ext_sender = ext_senders.first().ok_or(Error::MissingExternalSenderExtension)?;
        Ok(ext_sender.clone().into())
    }
}

#[cfg(test)]
mod test_utils {
    use openmls::prelude::SignaturePublicKey;

    use super::*;

    impl Conversation {
        pub async fn signature_keys(&self) -> Vec<SignaturePublicKey> {
            let group = self.group().await;
            group
                .members()
                .map(|m| m.signature_key)
                .map(|mpk| SignaturePublicKey::from(mpk.as_slice()))
                .collect()
        }

        pub async fn encryption_keys(&self) -> Vec<Vec<u8>> {
            let group = self.group().await;
            group.members().map(|m| m.encryption_key).collect()
        }

        pub async fn extensions(&self) -> openmls::prelude::Extensions {
            let group = self.group().await;
            group.export_group_context().extensions().to_owned()
        }
    }
}
