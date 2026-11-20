//! The methods in this module all produce or handle commits.

use std::{borrow::Borrow, collections::HashMap};

use openmls::{
    group::CommitMessageBundle,
    prelude::{KeyPackage, KeyPackageIn, LeafNodeParameters, NewSignerBundle},
};
use openmls_traits::OpenMlsProvider as _;

use super::history_sharing::HistoryClientUpdateOutcome;
use crate::{
    ClientId, ClientIdRef, CredentialRef, GroupInfoBundle, OpenMlsError, RecursiveError,
    mls::{
        conversation::{ConversationMut, Error, Result, commit::CommitBundle, member_identity},
        credential::{Credential, validation::validate_key_packages},
    },
};

impl ConversationMut {
    pub(super) async fn send_and_merge_commit(&mut self, commit: CommitBundle) -> Result<()> {
        let history_client_update_result = self.update_history_client().await?;
        if history_client_update_result == HistoryClientUpdateOutcome::CommitSentAndMerged {
            return Ok(());
        }

        match self.send_commit(commit).await {
            Ok(()) => self.merge_commit().await,
            e @ Err(_) => {
                // The transport failure is what the caller needs in order to choose a recovery, so
                // a failure to clean up locally must not impersonate the delivery service's answer.
                if let Err(cleanup_error) = self.clear_pending_commit().await {
                    log::warn!(
                        cleanup_error:% = cleanup_error;
                        "failed to clear the pending commit after the delivery service rejected it"
                    );
                }
                e
            }
        }
    }

    pub(super) async fn merge_commit(&mut self) -> Result<()> {
        self.commit_accepted().await?;
        let conversation_id = self.id().to_owned();
        let epoch = self.epoch().await;

        self.tx_context
            .queue_epoch_changed(conversation_id, epoch)
            .await
            .map_err(RecursiveError::context("queueing epoch changed notification"))?;

        Ok(())
    }

    /// Send the commit via [crate::MlsTransport] and handle the response.
    pub(super) async fn send_commit(&mut self, commit: CommitBundle) -> Result<()> {
        let transport = self.transport().await?;

        transport
            .send_commit_bundle(commit)
            .await
            .map_err(RecursiveError::context("sending commit bundle"))
            .map_err(Into::into)
    }

    /// Adds new members to the group/conversation
    pub async fn add_members(&mut self, key_packages: Vec<KeyPackageIn>) -> Result<()> {
        let commit = self.add_members_inner(key_packages).await?;

        self.send_and_merge_commit(commit).await?;

        Ok(())
    }

    pub(super) async fn add_members_inner(&mut self, key_packages: Vec<KeyPackageIn>) -> Result<CommitBundle> {
        self.ensure_no_pending_commit().await?;
        let backend = self.crypto_provider().await?;
        let credential = self.credential().await?;

        let key_packages =
            validate_key_packages(&backend, key_packages)
                .await
                .map_err(RecursiveError::mls_credential(
                    "validating the key packages of the members to add",
                ))?;

        self.mutate_group(async |provider, group, _| {
            let signer = credential.signature_key();
            let (commit, welcome, group_info) = group.add_members(provider, signer, &key_packages).map_err(|err| {
                if Self::err_is_duplicate_signature_key(&err) {
                    Self::clients_with_duplicate_signature_keys(&key_packages)
                        .map(|affected_clients| Error::DuplicateSignature { affected_clients })
                        .unwrap_or_else(|e| e)
                } else {
                    OpenMlsError::wrap("group add members")(err).into()
                }
            })?;

            Ok(CommitBundle {
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

    fn clients_with_duplicate_signature_keys(key_packages: &[KeyPackage]) -> Result<Vec<(ClientId, ClientId)>> {
        let mut seen_signature_keys = HashMap::new();
        let mut duplicate_pairs = Vec::new();

        for key_package in key_packages {
            let signature_key = key_package.leaf_node().signature_key().as_slice().to_vec();

            let client_id: ClientId = member_identity(key_package.leaf_node().credential())?
                .as_ref()
                .try_into()
                .map_err(RecursiveError::context("client id from bytes"))?;

            if let Some(previous_client_id) = seen_signature_keys.insert(signature_key, client_id.clone()) {
                duplicate_pairs.push((previous_client_id, client_id));
            }
        }

        Ok(duplicate_pairs)
    }

    /// Removes clients from the group/conversation.
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `clients` - list of client ids to be removed from the group
    pub async fn remove_members(&mut self, clients: &[impl Borrow<ClientIdRef>]) -> Result<()> {
        self.remove_members_or_history_clients(clients.iter().map(|e| e.borrow().as_ref()))
            .await
    }

    pub(crate) async fn remove_members_or_history_clients(
        &mut self,
        clients: impl Iterator<Item = &[u8]> + Clone,
    ) -> Result<()> {
        self.ensure_no_pending_commit().await?;
        let credential = self.credential().await?;
        let signer = credential.signature_key();
        let (commit, welcome, group_info) = self
            .mutate_group(async |provider, group, _| {
                let members = group
                    .members()
                    .filter_map(|member| {
                        // A member whose identity can't be read isn't one of the clients to remove.
                        let identity = member_identity(&member.credential).ok()?;
                        clients
                            .clone()
                            .any(|client_id| client_id == identity.as_ref())
                            .then_some(member.index)
                    })
                    .collect::<Vec<_>>();
                group
                    .remove_members(provider, signer, &members)
                    .map_err(OpenMlsError::wrap("group remove members"))
                    .map_err(Into::into)
            })
            .await?;

        let group_info = Self::group_info(group_info)?;

        self.send_and_merge_commit(CommitBundle {
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
        let database = self.database()?;
        let credential = credential_ref
            .load(&*database)
            .await
            .map_err(RecursiveError::context("loading credential from ref"))?;
        let commit = self.set_credential_inner(&credential).await?;

        self.send_and_merge_commit(commit).await
    }

    /// Self updates the own leaf node with the given credential and automatically commits. Pending proposals will be
    /// committed.
    pub(crate) async fn set_credential_inner(&mut self, credential: &Credential) -> Result<CommitBundle> {
        self.ensure_no_pending_commit().await?;
        let current_credential = self.credential().await?;
        let new_credential = credential.clone();

        self.mutate_group(async |provider, group, _| {
            let leaf_node = group
                .own_leaf_node()
                .ok_or(Error::MlsGroupInvalidState("own leaf node not found"))?;
            let new_credential_with_key = new_credential.to_mls_credential_with_key();
            let credential_unchanged = leaf_node.credential() == &new_credential_with_key.credential
                && leaf_node.signature_key() == &new_credential_with_key.signature_key;

            // A self-update with an unchanged credential still renews our encryption key. A new credential comes with
            // its own signature key: the commit is signed with the key we have now, and our new leaf node with the
            // new one.
            let bundle = if credential_unchanged {
                group.self_update(
                    provider,
                    &current_credential.signature_key_pair,
                    LeafNodeParameters::default(),
                )
            } else {
                group.self_update_with_new_signer(
                    provider,
                    &current_credential.signature_key_pair,
                    NewSignerBundle {
                        signer: &new_credential.signature_key_pair,
                        credential_with_key: new_credential_with_key,
                    },
                    LeafNodeParameters::default(),
                )
            }
            .map_err(OpenMlsError::wrap("group self update"))?;

            Self::commit_bundle(bundle)
        })
        .await
    }

    /// Our [CommitBundle] for a commit openmls has staged.
    pub(crate) fn commit_bundle(bundle: CommitMessageBundle) -> Result<CommitBundle> {
        let welcome = bundle.to_welcome_msg();
        let (commit, _, group_info) = bundle.into_contents();
        Ok(CommitBundle {
            welcome,
            commit,
            group_info: Self::group_info(group_info)?,
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

    pub(crate) async fn commit_pending_proposals_inner(&mut self) -> Result<Option<CommitBundle>> {
        if self.group().await.pending_proposals().next().is_none() {
            return Ok(None);
        }

        let credential = self.credential().await?;

        let (commit, welcome, openmls_group_info) = self
            .mutate_group(async |provider, group, _| {
                let signer = &credential.signature_key_pair;
                group
                    .commit_to_pending_proposals(provider, signer)
                    .map_err(OpenMlsError::wrap("group commit to pending proposals"))
                    .map_err(Into::into)
            })
            .await?;
        let group_info = GroupInfoBundle::try_new_full_plaintext(
            openmls_group_info.expect("creating a commit always produces a group info"),
        )?;

        Ok(Some(CommitBundle {
            welcome,
            commit,
            group_info,
            encrypted_message: None,
        }))
    }

    pub(crate) async fn commit_inline_proposals(
        &mut self,
        proposals: Vec<openmls::prelude::Proposal>,
    ) -> Result<Option<CommitBundle>> {
        if proposals.is_empty() {
            return Ok(None);
        }

        let credential = self.credential().await?;

        self.mutate_group(async |provider, group, _| {
            let signer = &credential.signature_key_pair;
            // Commit only these proposals; any pending ones stay pending.
            let bundle = group
                .commit_builder()
                .consume_proposal_store(false)
                .add_proposals(proposals)
                .load_psks(provider.storage())
                .map_err(OpenMlsError::wrap("loading psks for commit to inline proposals"))?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(OpenMlsError::wrap("building commit to inline proposals"))?
                .stage_commit(provider)
                .map_err(OpenMlsError::wrap("staging commit to inline proposals"))?;
            Self::commit_bundle(bundle)
        })
        .await
        .map(Some)
    }
}
