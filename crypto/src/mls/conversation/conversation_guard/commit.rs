//! The methods in this module all produce or handle commits.

use std::{borrow::Borrow, collections::HashMap};

use openmls::prelude::KeyPackageIn;

use super::history_sharing::HistoryClientUpdateOutcome;
use crate::{
    ClientId, ClientIdRef, CredentialRef, LeafError, MlsError, MlsGroupInfoBundle, RecursiveError,
    mls::{
        conversation::{ConversationGuard, ConversationWithMls as _, Error, Result, commit::MlsCommitBundle},
        credential::Credential,
    },
};

impl ConversationGuard {
    pub(super) async fn send_and_merge_commit(&mut self, commit: MlsCommitBundle) -> Result<()> {
        let history_client_update_result = self.update_history_client().await?;
        if history_client_update_result == HistoryClientUpdateOutcome::CommitSentAndMerged {
            return Ok(());
        }

        match self.send_commit(commit).await {
            Ok(()) => self.merge_commit().await,
            e @ Err(_) => {
                self.clear_pending_commit().await?;
                e
            }
        }
    }

    pub(super) async fn merge_commit(&mut self) -> Result<()> {
        let provider = self.crypto_provider().await?;
        let (conversation_id, epoch) = self
            .conversation_mut(async |conversation| {
                conversation.commit_accepted(&provider).await?;
                Ok((conversation.id().to_owned(), conversation.group.epoch().as_u64()))
            })
            .await?;
        self.central_context
            .queue_epoch_changed(conversation_id, epoch)
            .await
            .map_err(RecursiveError::transaction("queueing epoch changed notification"))?;
        Ok(())
    }

    /// Send the commit via [crate::MlsTransport] and handle the response.
    pub(super) async fn send_commit(&mut self, commit: MlsCommitBundle) -> Result<()> {
        let transport = self.transport().await?;

        transport
            .send_commit_bundle(commit)
            .await
            .map_err(RecursiveError::root("sending commit bundle"))
            .map_err(Into::into)
    }

    /// Adds new members to the group/conversation
    pub async fn add_members(&mut self, key_packages: Vec<KeyPackageIn>) -> Result<()> {
        let commit = self.add_members_inner(key_packages).await?;

        self.send_and_merge_commit(commit).await?;

        Ok(())
    }

    pub(super) async fn add_members_inner(&mut self, key_packages: Vec<KeyPackageIn>) -> Result<MlsCommitBundle> {
        self.ensure_no_pending_commit().await?;
        let backend = self.crypto_provider().await?;
        let credential = self.credential().await?;

        self.conversation_mut(async move |conversation| {
            let signer = credential.signature_key();
            let (commit, welcome, group_info) = conversation
                .group
                .add_members(&backend, signer, key_packages.clone())
                .await
                .map_err(|err| {
                    if Self::err_is_duplicate_signature_key(&err) {
                        let affected_clients = Self::clients_with_duplicate_signature_keys(key_packages.as_ref());
                        Error::DuplicateSignature { affected_clients }
                    } else {
                        MlsError::wrap("group add members")(err).into()
                    }
                })?;

            Ok(MlsCommitBundle {
                commit,
                welcome: Some(welcome),
                group_info: Self::group_info(group_info)?,
                encrypted_message: None,
            })
        })
        .await
    }

    fn err_is_duplicate_signature_key(
        err: &openmls::prelude::AddMembersError<core_crypto_keystore::CryptoKeystoreError>,
    ) -> bool {
        matches!(
            err,
            openmls::prelude::AddMembersError::CreateCommitError(
                openmls::prelude::CreateCommitError::ProposalValidationError(
                    openmls::prelude::ProposalValidationError::DuplicateSignatureKey
                )
            )
        )
    }

    fn clients_with_duplicate_signature_keys(key_packages: &[KeyPackageIn]) -> Vec<(ClientId, ClientId)> {
        let mut seen_signature_keys = HashMap::new();
        let mut duplicate_pairs = Vec::new();

        for key_package in key_packages {
            let signature_key = key_package.unverified_credential().signature_key.as_slice().to_vec();

            let client_id: ClientId = key_package.credential().identity().to_vec().into();

            if let Some(previous_client_id) = seen_signature_keys.insert(signature_key, client_id.clone()) {
                duplicate_pairs.push((previous_client_id, client_id));
            }
        }

        duplicate_pairs
    }

    /// Removes clients from the group/conversation.
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `clients` - list of client ids to be removed from the group
    pub async fn remove_members(&mut self, clients: &[impl Borrow<ClientIdRef>]) -> Result<()> {
        self.ensure_no_pending_commit().await?;
        let backend = self.crypto_provider().await?;
        let credential = self.credential().await?;
        let signer = credential.signature_key();

        let (commit, welcome, group_info) = self
            .conversation_mut(async |conversation| {
                let members = conversation
                    .group
                    .members()
                    .filter_map(|kp| {
                        clients
                            .iter()
                            .any(move |client_id| client_id.borrow() == kp.credential.identity())
                            .then_some(kp.index)
                    })
                    .collect::<Vec<_>>();

                conversation
                    .group
                    .remove_members(&backend, signer, &members)
                    .await
                    .map_err(MlsError::wrap("group remove members"))
                    .map_err(Into::into)
            })
            .await?;

        let group_info = Self::group_info(group_info)?;

        self.send_and_merge_commit(MlsCommitBundle {
            commit,
            welcome,
            group_info,
            encrypted_message: None,
        })
        .await
    }

    /// Self updates the own leaf node and automatically commits. Pending proposals will be committed.
    pub async fn update_key_material(&mut self) -> Result<()> {
        let credential = self.credential().await?;
        let commit = self.set_credential_inner(&credential).await?;
        self.send_and_merge_commit(commit).await
    }

    /// Set the referenced credential for this conversation.
    pub async fn set_credential_by_ref(&mut self, credential_ref: &CredentialRef) -> Result<()> {
        let database = self.database().await?;
        let credential = credential_ref
            .load(&database)
            .await
            .map_err(RecursiveError::mls_credential_ref("loading credential from ref"))?;
        let commit = self.set_credential_inner(&credential).await?;

        self.send_and_merge_commit(commit).await
    }

    /// Self updates the own leaf node with the given credential and automatically commits. Pending proposals will be
    /// committed.
    pub(crate) async fn set_credential_inner(&mut self, credential: &Credential) -> Result<MlsCommitBundle> {
        self.ensure_no_pending_commit().await?;
        let backend = self.crypto_provider().await?;
        let credential = credential.clone();

        self.conversation_mut(async move |conversation| {
            // If the credential remains the same and we still want to update, we explicitly need to pass `None` to
            // openmls, if we just passed an unchanged leaf node, no update commit would be created.
            // Also, we can avoid cloning in the case we don't need to create a new leaf node.
            let updated_leaf_node = {
                let leaf_node = conversation.group.own_leaf().ok_or(LeafError::InternalMlsError)?;
                if leaf_node.credential() == &credential.mls_credential {
                    None
                } else {
                    let mut leaf_node = leaf_node.clone();
                    leaf_node.set_credential_with_key(credential.to_mls_credential_with_key());
                    Some(leaf_node)
                }
            };

            let (commit, welcome, group_info) = conversation
                .group
                .explicit_self_update(&backend, &credential.signature_key_pair, updated_leaf_node)
                .await
                .map_err(MlsError::wrap("group self update"))?;

            // We should always have ratchet tree extension turned on hence GroupInfo should always be present
            let group_info = group_info.ok_or(LeafError::MissingGroupInfo)?;
            let group_info = MlsGroupInfoBundle::try_new_full_plaintext(group_info)?;

            Ok(MlsCommitBundle {
                welcome,
                commit,
                group_info,
                encrypted_message: None,
            })
        })
        .await
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
        if self.conversation().await.group().pending_proposals().next().is_none() {
            return Ok(None);
        }

        let (commit, welcome, openmls_group_info) = self
            .conversation_mut(async |inner| {
                let signer = &inner.find_current_credential(session).await?.signature_key_pair;
                inner
                    .group
                    .commit_to_pending_proposals(provider, signer)
                    .await
                    .map_err(MlsError::wrap("group commit to pending proposals"))
                    .map_err(Into::into)
            })
            .await?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(
            openmls_group_info.expect("creating a commit always produces a group info"),
        )?;

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
        if proposals.is_empty() {
            return Ok(None);
        }

        let (commit, welcome, openmls_group_info) = self
            .conversation_mut(async |inner| {
                let signer = &inner.find_current_credential(session).await?.signature_key_pair;
                inner
                    .group
                    .commit_to_inline_proposals(provider, signer, proposals)
                    .await
                    .map_err(MlsError::wrap("group commit to pending proposals"))
                    .map_err(Into::into)
            })
            .await?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(
            openmls_group_info.expect("creating a commit always produces a group info"),
        )?;

        Ok(Some(MlsCommitBundle {
            welcome,
            commit,
            group_info,
            encrypted_message: None,
        }))
    }
}
