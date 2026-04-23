use std::{borrow::Borrow, sync::Arc};

use core_crypto::{
    RecursiveError,
    mls::conversation::{Conversation as _, ConversationIdRef},
};

use crate::{
    Ciphersuite, ClientId, CoreCryptoFfi, CoreCryptoResult, CredentialRef,
    bytes_wrapper::{bytes_wrapper, impl_display_via_hex},
    core_crypto_context::mls::SecretKey,
};

bytes_wrapper!(
    /// A unique identifier for a single conversation.
    ///
    /// The backend provides an opaque string identifying a new conversation.
    /// Construct an instance of this newtype to pass that identifier to Rust.
    #[derive(Debug, PartialOrd, Ord, Clone, PartialEq, Eq, Hash)]
    #[uniffi::export(Debug, Eq, Hash, Display)]
    ConversationId infallibly wraps core_crypto::ConversationId; copy_bytes
);

impl_display_via_hex!(ConversationId);

impl Borrow<ConversationIdRef> for ConversationId {
    fn borrow(&self) -> &ConversationIdRef {
        ConversationIdRef::new(&self.0)
    }
}

impl AsRef<ConversationIdRef> for ConversationId {
    fn as_ref(&self) -> &ConversationIdRef {
        ConversationIdRef::new(&self.0)
    }
}

#[uniffi::export]
impl CoreCryptoFfi {
    /// Returns the current MLS epoch of the given conversation.
    pub async fn conversation_epoch(&self, conversation_id: &ConversationId) -> CoreCryptoResult<u64> {
        let conversation = self
            .inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client(
                "conversation_epoch: getting raw conversation by id",
            ))?;
        Ok(conversation.epoch().await)
    }

    /// Returns the ciphersuite in use for the given conversation.
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let cs = self
            .inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client(
                "conversation_ciphersuite: getting raw conversation by id",
            ))?
            .ciphersuite()
            .await;
        Ok(Ciphersuite::from(core_crypto::MlsCiphersuite::from(cs)))
    }

    /// Get the credential ref for the given conversation.
    pub async fn conversation_credential(&self, conversation_id: &ConversationId) -> CoreCryptoResult<CredentialRef> {
        self.inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client(
                "conversation_credential: getting raw conversation by id",
            ))?
            .credential_ref()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Returns true if a conversation with the given id exists in the local state.
    pub async fn conversation_exists(&self, conversation_id: &ConversationId) -> CoreCryptoResult<bool> {
        self.inner
            .mls_session()
            .await?
            .conversation_exists(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client("getting conversation existence by id"))
            .map_err(Into::into)
    }

    /// Returns the client ids of all members of the given conversation.
    pub async fn get_client_ids(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<Arc<ClientId>>> {
        let conversation = self
            .inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client("get_client_ids: getting raw conversation"))?;
        Ok(conversation
            .get_client_ids()
            .await
            .into_iter()
            .map(Into::into)
            .map(Arc::new)
            .collect())
    }

    /// Returns the serialized public key of the external sender for the given conversation.
    pub async fn get_external_sender(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<u8>> {
        let conversation = self
            .inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client(
                "get_external_sender: getting raw conversation",
            ))?;
        conversation.get_external_sender().await.map_err(Into::into)
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
        self.inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client(
                "export_secret_key: getting raw conversation",
            ))?
            .export_secret_key(key_length as usize)
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Returns true if history sharing is currently enabled for the given conversation.
    pub async fn is_history_sharing_enabled(&self, conversation_id: &ConversationId) -> CoreCryptoResult<bool> {
        let conversation = self
            .inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client(
                "is_history_sharing_enabled: getting raw conversation",
            ))?;
        Ok(conversation.is_history_sharing_enabled().await)
    }
}
