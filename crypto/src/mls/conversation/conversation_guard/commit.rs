//! The methods in this module all produce or handle commits.

use openmls::prelude::{KeyPackageIn, LeafNode};

use super::history_sharing::HistoryClientUpdateOutcome;
use crate::{
    ClientId, CredentialType, LeafError, MlsError, MlsGroupInfoBundle, MlsTransportResponse, RecursiveError,
    e2e_identity::NewCrlDistributionPoints,
    mls::{
        conversation::{
            Conversation as _, ConversationGuard, ConversationWithMls as _, Error, Result, commit::MlsCommitBundle,
        },
        credential::{
            Credential,
            crl::{extract_crl_uris_from_credentials, get_new_crl_distribution_points},
        },
    },
};

/// What to do with a commit after it has been sent via [crate::MlsTransport].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportedCommitPolicy {
    /// Accept and merge the commit.
    Merge,
    /// Do nothing, because intended operation was already done in one in intermediate processing.
    None,
}

impl ConversationGuard {
    pub(super) async fn send_and_merge_commit(&mut self, commit: MlsCommitBundle) -> Result<()> {
        let history_client_update_result = self.update_history_client().await?;
        if history_client_update_result == HistoryClientUpdateOutcome::CommitSentAndMerged {
            return Ok(());
        }

        match self.send_commit(commit).await {
            Ok(TransportedCommitPolicy::None) => Ok(()),
            Ok(TransportedCommitPolicy::Merge) => self.merge_commit().await,
            Err(e @ Error::MessageRejected { .. }) => {
                self.clear_pending_commit().await?;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    pub(super) async fn merge_commit(&mut self) -> Result<()> {
        let client = self.session().await?;
        let provider = self.crypto_provider().await?;
        let mut conversation = self.inner.write().await;
        conversation.commit_accepted(&client, &provider).await
    }

    /// Send the commit via [crate::MlsTransport] and handle the response.
    pub(super) async fn send_commit(&mut self, mut commit: MlsCommitBundle) -> Result<TransportedCommitPolicy> {
        let transport = self.transport().await?;

        let epoch_before_sending = self.epoch().await;

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
                    let epoch_after_sending = self.epoch().await;
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
                    let Some(commit_to_retry) = self.commit_pending_proposals_inner().await? else {
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
        let (new_crl_distribution_points, commit) = self.add_members_inner(key_packages).await?;

        self.send_and_merge_commit(commit).await?;

        Ok(new_crl_distribution_points)
    }

    pub(super) async fn add_members_inner(
        &mut self,
        key_packages: Vec<KeyPackageIn>,
    ) -> Result<(NewCrlDistributionPoints, MlsCommitBundle)> {
        self.ensure_no_pending_commit().await?;
        let backend = self.crypto_provider().await?;
        let credential = self.credential().await?;
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

        let commit = MlsCommitBundle {
            commit,
            welcome,
            group_info,
            encrypted_message: None,
        };

        Ok((crl_new_distribution_points, commit))
    }

    /// Removes clients from the group/conversation.
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `clients` - list of client ids to be removed from the group
    pub async fn remove_members(&mut self, clients: &[ClientId]) -> Result<()> {
        self.ensure_no_pending_commit().await?;
        let backend = self.crypto_provider().await?;
        let credential = self.credential().await?;
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
            encrypted_message: None,
        })
        .await
    }

    /// Self updates the KeyPackage and automatically commits. Pending proposals will be commited.
    pub async fn update_key_material(&mut self) -> Result<()> {
        let commit = self.update_key_material_inner(None, None).await?;
        self.send_and_merge_commit(commit).await
    }

    /// Send a commit in a conversation for changing the credential. Requires first
    /// having enrolled a new X509 certificate with either
    /// [crate::transaction_context::TransactionContext::e2ei_new_activation_enrollment] or
    /// [crate::transaction_context::TransactionContext::e2ei_new_rotate_enrollment] and having saved it with
    /// [crate::transaction_context::TransactionContext::save_x509_credential].
    pub async fn e2ei_rotate(&mut self, cb: Option<&Credential>) -> Result<()> {
        let client = &self.session().await?;
        let conversation = self.conversation().await;

        let cb = match cb {
            Some(cb) => cb,
            None => &*client
                .find_most_recent_credential(conversation.ciphersuite().signature_algorithm(), CredentialType::X509)
                .await
                .map_err(RecursiveError::mls_client("finding most recent x509 credential"))?,
        };

        let mut leaf_node = conversation
            .group
            .own_leaf()
            .ok_or(LeafError::InternalMlsError)?
            .clone();
        leaf_node.set_credential_with_key(cb.to_mls_credential_with_key());

        // we don't need the conversation anymore, but we do need to mutably borrow `self` again
        drop(conversation);

        let commit = self.update_key_material_inner(Some(cb), Some(leaf_node)).await?;

        self.send_and_merge_commit(commit).await
    }

    pub(crate) async fn update_key_material_inner(
        &mut self,
        cb: Option<&Credential>,
        leaf_node: Option<LeafNode>,
    ) -> Result<MlsCommitBundle> {
        self.ensure_no_pending_commit().await?;
        let session = &self.session().await?;
        let backend = &self.crypto_provider().await?;
        let mut conversation = self.conversation_mut().await;
        let cb = match cb {
            None => &conversation.find_most_recent_credential(session).await?,
            Some(cb) => cb,
        };
        let (commit, welcome, group_info) = conversation
            .group
            .explicit_self_update(backend, &cb.signature_key_pair, leaf_node)
            .await
            .map_err(MlsError::wrap("group self update"))?;

        // We should always have ratchet tree extension turned on hence GroupInfo should always be present
        let group_info = group_info.ok_or(LeafError::MissingGroupInfo)?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(group_info)?;

        conversation
            .persist_group_when_changed(&backend.keystore(), false)
            .await?;

        Ok(MlsCommitBundle {
            welcome,
            commit,
            group_info,
            encrypted_message: None,
        })
    }

    /// Commits all pending proposals of the group
    pub async fn commit_pending_proposals(&mut self) -> Result<()> {
        self.ensure_no_pending_commit().await?;
        let commit = self.commit_pending_proposals_inner().await?;
        let Some(commit) = commit else {
            return Ok(());
        };
        self.send_and_merge_commit(commit).await
    }

    pub(crate) async fn commit_pending_proposals_inner(&mut self) -> Result<Option<MlsCommitBundle>> {
        let session = &self.session().await?;
        let provider = &self.crypto_provider().await?;
        let mut inner = self.inner.write().await;
        if inner.group.pending_proposals().next().is_none() {
            return Ok(None);
        }

        let signer = &inner.find_most_recent_credential(session).await?.signature_key_pair;

        let (commit, welcome, gi) = inner
            .group
            .commit_to_pending_proposals(provider, signer)
            .await
            .map_err(MlsError::wrap("group commit to pending proposals"))?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(gi.unwrap())?;

        inner.persist_group_when_changed(&provider.keystore(), false).await?;

        Ok(Some(MlsCommitBundle {
            welcome,
            commit,
            group_info,
            encrypted_message: None,
        }))
    }

    pub(crate) async fn commit_inline_proposals(
        &mut self,
        proposals: Vec<openmls::prelude::Proposal>,
    ) -> Result<Option<MlsCommitBundle>> {
        let session = &self.session().await?;
        let provider = &self.crypto_provider().await?;
        let mut inner = self.inner.write().await;
        if proposals.is_empty() {
            return Ok(None);
        }
        let signer = &inner.find_most_recent_credential(session).await?.signature_key_pair;

        let (commit, welcome, gi) = inner
            .group
            .commit_to_inline_proposals(provider, signer, proposals)
            .await
            .map_err(MlsError::wrap("group commit to pending proposals"))?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(gi.unwrap())?;

        inner.persist_group_when_changed(&provider.keystore(), false).await?;

        Ok(Some(MlsCommitBundle {
            welcome,
            commit,
            group_info,
            encrypted_message: None,
        }))
    }
}
