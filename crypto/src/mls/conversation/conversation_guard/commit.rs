//! The methods in this module all produce or handle commits.

use openmls::prelude::KeyPackageIn;

use crate::mls::conversation::{ConversationWithMls as _, Error};
use crate::mls::credential::CredentialBundle;
use crate::prelude::MlsCredentialType;
use crate::{
    LeafError, MlsError, MlsTransportResponse, RecursiveError,
    e2e_identity::init_certificates::NewCrlDistributionPoints,
    mls::{
        conversation::{ConversationGuard, Result, commit::MlsCommitBundle},
        credential::crl::{extract_crl_uris_from_credentials, get_new_crl_distribution_points},
    },
    prelude::ClientId,
};

/// What to do with a commit after it has been sent via [crate::MlsTransport].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportedCommitPolicy {
    /// Accept and merge the commit.
    Merge,
    /// Do nothing, because intended operation was already done in one in intermediate processing.
    None,
}

impl ConversationGuard {
    async fn send_and_merge_commit(&mut self, commit: MlsCommitBundle) -> Result<()> {
        match self.send_commit(commit).await {
            Ok(TransportedCommitPolicy::None) => Ok(()),
            Ok(TransportedCommitPolicy::Merge) => {
                let client = self.mls_client().await?;
                let backend = self.mls_provider().await?;
                let mut conversation = self.inner.write().await;
                conversation.commit_accepted(&client, &backend).await
            }
            Err(e @ Error::MessageRejected { .. }) => {
                self.clear_pending_commit().await?;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Send the commit via [crate::MlsTransport] and handle the response.
    async fn send_commit(&mut self, mut commit: MlsCommitBundle) -> Result<TransportedCommitPolicy> {
        let transport = self
            .context()
            .await?
            .mls_transport()
            .await
            .map_err(RecursiveError::root("getting mls transport"))?;
        let transport = transport.as_ref().ok_or::<Error>(
            RecursiveError::root("getting mls transport")(crate::Error::MlsTransportNotProvided).into(),
        )?;
        let client = self.mls_client().await?;
        let backend = self.mls_provider().await?;

        let inner = self.conversation().await;
        let epoch_before_sending = inner.group().epoch().as_u64();
        // Drop the lock to allow mutably borrowing self again.
        drop(inner);

        loop {
            match transport
                .send_commit_bundle(commit.clone())
                .await
                .map_err(RecursiveError::root("sending commit bundle"))?
            {
                MlsTransportResponse::Success => {
                    return Ok(TransportedCommitPolicy::Merge);
                }
                MlsTransportResponse::Abort { reason } => {
                    return Err(Error::MessageRejected { reason });
                }
                MlsTransportResponse::Retry => {
                    let mut inner = self.conversation_mut().await;
                    let epoch_after_sending = inner.group().epoch().as_u64();
                    if epoch_before_sending == epoch_after_sending {
                        // No intermediate commits have been processed before returning retry.
                        // This will be the case, e.g., on network failure.
                        // We can just send the exact same commit again.
                        continue;
                    }

                    // The epoch has changed. I.e., a client originally tried sending a commit for an old epoch,
                    // which was rejected by the DS.
                    // Before returning `Retry`, the API consumer has fetched and merged all commits,
                    // so the group state is up-to-date.
                    // The original commit has been `renewed` to a pending proposal, unless the
                    // intended operation was already done in one of the merged commits.
                    let Some(commit_to_retry) = inner.commit_pending_proposals(&client, &backend).await? else {
                        // The intended operation was already done in one of the merged commits.
                        return Ok(TransportedCommitPolicy::None);
                    };
                    commit = commit_to_retry;
                }
            }
        }
    }

    /// Adds new members to the group/conversation
    pub async fn add_members(&mut self, key_packages: Vec<KeyPackageIn>) -> Result<NewCrlDistributionPoints> {
        let backend = self.mls_provider().await?;
        let credential = self.credential_bundle().await?;
        let signer = credential.signature_key();
        let mut conversation = self.conversation_mut().await;

        // No need to also check pending proposals since they should already have been scanned while decrypting the proposal message
        let crl_dps = extract_crl_uris_from_credentials(key_packages.iter().filter_map(|kp| {
            let mls_credential = kp.credential().mls_credential();
            matches!(mls_credential, openmls::prelude::MlsCredentialType::X509(_)).then_some(mls_credential)
        }))
        .map_err(RecursiveError::mls_credential("extracting crl uris from credentials"))?;
        let crl_new_distribution_points = get_new_crl_distribution_points(&backend, crl_dps)
            .await
            .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

        let (commit, welcome, group_info) = conversation
            .group
            .add_members(&backend, signer, key_packages)
            .await
            .map_err(MlsError::wrap("group add members"))?;

        // commit requires an optional welcome
        let welcome = Some(welcome);
        let group_info = Self::group_info(group_info)?;

        conversation
            .persist_group_when_changed(&backend.keystore(), false)
            .await?;

        // we don't need the conversation anymore, but we do need to mutably borrow `self` again
        drop(conversation);

        let commit = MlsCommitBundle {
            commit,
            welcome,
            group_info,
        };

        self.send_and_merge_commit(commit).await?;

        Ok(crl_new_distribution_points)
    }

    /// Removes clients from the group/conversation.
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `clients` - list of client ids to be removed from the group
    pub async fn remove_members(&mut self, clients: &[ClientId]) -> Result<()> {
        let backend = self.mls_provider().await?;
        let credential = self.credential_bundle().await?;
        let signer = credential.signature_key();
        let mut conversation = self.inner.write().await;

        let members = conversation
            .group
            .members()
            .filter_map(|kp| {
                clients
                    .iter()
                    .any(move |client_id| client_id.as_slice() == kp.credential.identity())
                    .then_some(kp.index)
            })
            .collect::<Vec<_>>();

        let (commit, welcome, group_info) = conversation
            .group
            .remove_members(&backend, signer, &members)
            .await
            .map_err(MlsError::wrap("group remove members"))?;

        let group_info = Self::group_info(group_info)?;

        conversation
            .persist_group_when_changed(&backend.keystore(), false)
            .await?;

        // we don't need the conversation anymore, but we do need to mutably borrow `self` again
        drop(conversation);

        self.send_and_merge_commit(MlsCommitBundle {
            commit,
            welcome,
            group_info,
        })
        .await
    }

    /// Self updates the KeyPackage and automatically commits. Pending proposals will be commited.
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    ///
    /// see [MlsCentral::update_keying_material]
    pub async fn update_key_material(&mut self) -> Result<()> {
        let client = self.mls_client().await?;
        let backend = self.mls_provider().await?;
        let mut conversation = self.inner.write().await;
        let commit = conversation
            .update_keying_material(&client, &backend, None, None)
            .await?;
        drop(conversation);
        self.send_and_merge_commit(commit).await
    }

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

    /// Commits all pending proposals of the group
    pub async fn commit_pending_proposals(&mut self) -> Result<()> {
        let client = self.mls_client().await?;
        let backend = self.mls_provider().await?;
        let mut conversation = self.inner.write().await;
        let commit = conversation.commit_pending_proposals(&client, &backend).await?;
        drop(conversation);
        let Some(commit) = commit else {
            return Ok(());
        };
        self.send_and_merge_commit(commit).await
    }
}
