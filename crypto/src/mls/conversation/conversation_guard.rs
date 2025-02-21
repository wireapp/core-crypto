use async_lock::{RwLockReadGuard, RwLockWriteGuard};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{group_info::GroupInfo, KeyPackageIn};

use crate::{
    context::CentralContext,
    e2e_identity::init_certificates::NewCrlDistributionPoint,
    group_store::GroupStoreValue,
    mls::credential::crl::{extract_crl_uris_from_credentials, get_new_crl_distribution_points},
    prelude::{Client, ClientId, MlsGroupInfoBundle},
    LeafError, MlsError, RecursiveError,
};

use super::{commit::MlsCommitBundle, Error, MlsConversation, Result};

/// A Conversation Guard wraps a `GroupStoreValue<MlsConversation>`.
///
/// By doing so, it permits mutable accesses to the conversation. This in turn
/// means that we don't have to duplicate the entire `MlsConversation` API
/// on `CentralContext`.
pub struct ConversationGuard {
    inner: GroupStoreValue<MlsConversation>,
    central_context: CentralContext,
}

impl ConversationGuard {
    pub(crate) fn new(inner: GroupStoreValue<MlsConversation>, central_context: CentralContext) -> Self {
        Self { inner, central_context }
    }

    // This is dead code for now but we expect it to come alive in near-future work.
    #[expect(dead_code)]
    pub(crate) async fn conversation(&self) -> RwLockReadGuard<MlsConversation> {
        self.inner.read().await
    }

    pub(crate) async fn conversation_mut(&mut self) -> RwLockWriteGuard<MlsConversation> {
        self.inner.write().await
    }

    async fn mls_client(&self) -> Result<Client> {
        self.central_context
            .mls_client()
            .await
            .map_err(RecursiveError::root("getting mls client"))
            .map_err(Into::into)
    }

    async fn mls_provider(&self) -> Result<MlsCryptoProvider> {
        self.central_context
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))
            .map_err(Into::into)
    }

    pub(crate) async fn send_and_merge_commit(&mut self, commit: MlsCommitBundle) -> Result<()> {
        // note we hand over this instance of the guard; when we need a `conversation` guard again,
        // we'll need to re-fetch it.
        let conversation = self.inner.write().await;
        match self.central_context.send_commit(commit, Some(conversation)).await {
            Ok(false) => Ok(()),
            Ok(true) => {
                let backend = self.mls_provider().await?;
                let mut conversation = self.inner.write().await;
                conversation.commit_accepted(&backend).await
            }
            Err(e @ Error::MessageRejected { .. }) => {
                let backend = self.mls_provider().await?;
                let mut conversation = self.inner.write().await;
                conversation.clear_pending_commit(&backend).await?;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    fn group_info(group_info: Option<GroupInfo>) -> Result<MlsGroupInfoBundle> {
        let group_info = group_info.ok_or(LeafError::MissingGroupInfo)?;
        MlsGroupInfoBundle::try_new_full_plaintext(group_info)
    }

    /// Adds new members to the group/conversation
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `members` - members to be added to the group
    pub async fn add_members(&mut self, key_packages: Vec<KeyPackageIn>) -> Result<NewCrlDistributionPoint> {
        let client = self.mls_client().await?;
        let backend = self.mls_provider().await?;
        let mut conversation = self.conversation_mut().await;

        let signer = &conversation
            .find_current_credential_bundle(&client)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential bundle"))?
            .signature_key;

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
        let client = self.mls_client().await?;
        let backend = self.mls_provider().await?;
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

        let signer = &conversation
            .find_most_recent_credential_bundle(&client)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential bundle"))?
            .signature_key;

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
}
