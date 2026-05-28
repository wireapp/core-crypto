mod clients;
mod commit_delay;
mod credential;
mod duplicate;
mod e2ei;
mod history_sharing;
mod persistence;

use async_lock::{RwLock, RwLockReadGuard};
use openmls::group::MlsGroup;

use super::{ConversationIdRef, Error, ExternalSenderKey, Result, SecretKey};
use crate::{CipherSuite, ConversationId, CredentialRef, MlsConversationConfiguration, MlsError, Session};

/// An ImmutableConversation exposes the read-only interface of an MLS conversation.
#[derive(Debug, derive_more::Constructor)]
pub struct ImmutableConversation {
    pub(in crate::mls::conversation) id: ConversationId,
    pub(in crate::mls::conversation) group: RwLock<MlsGroup>,
    pub(in crate::mls::conversation) configuration: MlsConversationConfiguration,
    session: Session,
}

impl ImmutableConversation {
    /// Returns the conversation's ID
    pub fn id(&self) -> &ConversationIdRef {
        ConversationIdRef::new(&self.id)
    }

    /// Returns an immutable guard over the underlying MLS group
    pub async fn group(&self) -> RwLockReadGuard<'_, MlsGroup> {
        self.group.read().await
    }

    /// Returns the conversation's configuration
    pub fn configuration(&self) -> &MlsConversationConfiguration {
        &self.configuration
    }

    /// Returns current epoch of the MLS group
    pub async fn epoch(&self) -> u64 {
        self.group().await.epoch().as_u64()
    }

    /// Returns this conversation's cipher suite
    pub fn ciphersuite(&self) -> CipherSuite {
        self.configuration.ciphersuite
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
            .map_err(MlsError::wrap("exporting secret key"))
            .map_err(Into::into)
    }

    /// Returns the raw public key of the first external sender present in this group.
    ///
    /// This should be used to initialize a subconversation
    pub async fn get_external_sender(&self) -> Result<ExternalSenderKey> {
        let group = self.group().await;
        let ext_senders = group
            .group_context_extensions()
            .external_senders()
            .ok_or(Error::MissingExternalSenderExtension)?;
        let ext_sender = ext_senders.first().ok_or(Error::MissingExternalSenderExtension)?;
        let ext_sender_public_key = ext_sender.signature_key().as_slice().to_vec().into();
        Ok(ext_sender_public_key)
    }
}

#[cfg(test)]
mod test_utils {
    use openmls::prelude::SignaturePublicKey;

    use super::*;

    impl ImmutableConversation {
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
