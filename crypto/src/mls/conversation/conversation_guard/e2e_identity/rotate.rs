//! This module provides the implementation of the `ConversationGuard` for the E2E identity
//! credential rotation.

use super::ConversationGuard;
use super::Result;
use crate::mls::credential::CredentialBundle;
use crate::prelude::MlsCredentialType;
use crate::{LeafError, RecursiveError};

impl ConversationGuard {
    /// Send a commit in a conversation for changing the credential. Requires first
    /// having enrolled a new X509 certificate with either
    /// [crate::context::CentralContext::e2ei_new_activation_enrollment] or
    /// [crate::context::CentralContext::e2ei_new_rotate_enrollment] and having saved it with
    /// [crate::context::CentralContext::save_x509_credential].
    pub async fn e2ei_rotate(&mut self, cb: Option<&CredentialBundle>) -> Result<()> {
        let client = &self.mls_client().await?;
        let backend = &self.mls_provider().await?;
        let mut conversation = self.inner.write().await;

        let cb = match cb {
            Some(cb) => cb,
            None => &client
                .find_most_recent_credential_bundle(
                    conversation.ciphersuite().signature_algorithm(),
                    MlsCredentialType::X509,
                )
                .await
                .map_err(RecursiveError::mls_client("finding most recent x509 credential bundle"))?,
        };

        let mut leaf_node = conversation
            .group
            .own_leaf()
            .ok_or(LeafError::InternalMlsError)?
            .clone();
        leaf_node.set_credential_with_key(cb.to_mls_credential_with_key());

        let commit = conversation
            .update_keying_material(client, backend, Some(cb), Some(leaf_node))
            .await?;
        // we don't need the conversation anymore, but we do need to mutably borrow `self` again
        drop(conversation);

        self.send_and_merge_commit(commit).await
    }
}
