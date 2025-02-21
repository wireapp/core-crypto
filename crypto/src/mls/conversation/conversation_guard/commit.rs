use openmls::prelude::KeyPackageIn;

use crate::{
    e2e_identity::init_certificates::NewCrlDistributionPoint,
    mls::{
        conversation::{commit::MlsCommitBundle, ConversationGuard, Result},
        credential::crl::{extract_crl_uris_from_credentials, get_new_crl_distribution_points},
    },
    prelude::ClientId,
    MlsError, RecursiveError,
};

impl ConversationGuard {
    /// Adds new members to the group/conversation
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
