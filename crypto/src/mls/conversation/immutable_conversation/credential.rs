use std::{collections::HashMap, sync::Arc};

use super::{Error, Result};
use crate::{Credential, LeafError, RecursiveError};
use openmls::{
    group::QueuedProposal,
    prelude::{
        Credential as MlsCredential, CredentialWithKey, LeafNode, LeafNodeIndex, Proposal, Sender, SignaturePublicKey,
    },
};

impl super::ImmutableConversation {
    fn extract_own_updated_node_from_proposals<'a>(
        own_index: &LeafNodeIndex,
        pending_proposals: impl Iterator<Item = &'a QueuedProposal>,
    ) -> Option<&'a LeafNode> {
        pending_proposals
            .filter_map(|proposal| {
                if let Sender::Member(index) = proposal.sender()
                    && index == own_index
                    && let Proposal::Update(update_proposal) = proposal.proposal()
                {
                    Some(update_proposal.leaf_node())
                } else {
                    None
                }
            })
            .last()
    }

    /// Find the current leaf node, then load it scredential.
    pub(crate) async fn find_current_credential(&self) -> Result<Arc<Credential>> {
        // if the group has pending proposals one of which is an own update proposal, we should take the credential from
        // there.
        let own_leaf =
            Self::extract_own_updated_node_from_proposals(&self.group.own_leaf_index(), self.group.pending_proposals())
                .or_else(|| self.group.own_leaf())
                .ok_or(LeafError::InternalMlsError)?;
        let credential = self
            .session
            .find_credential_by_public_key(own_leaf.signature_key())
            .await
            .map_err(RecursiveError::mls_client("finding current credential"))?;
        Ok(credential)
    }

    /// Returns all members credentials from the group/conversation
    pub fn members(&self) -> HashMap<Vec<u8>, MlsCredential> {
        self.group.members().fold(HashMap::new(), |mut acc, kp| {
            let credential = kp.credential;
            let id = credential.identity().to_vec();
            acc.entry(id).or_insert(credential);
            acc
        })
    }

    /// Returns all members credentials with their signature public key from the group/conversation
    pub fn members_with_key(&self) -> HashMap<Vec<u8>, CredentialWithKey> {
        self.group.members().fold(HashMap::new(), |mut acc, kp| {
            let credential = kp.credential;
            let id = credential.identity().to_vec();
            let signature_key = SignaturePublicKey::from(kp.signature_key);
            let credential = CredentialWithKey {
                credential,
                signature_key,
            };
            acc.entry(id).or_insert(credential);
            acc
        })
    }

    pub(crate) fn own_mls_credential(&self) -> Result<&MlsCredential> {
        let credential = self
            .group
            .own_leaf_node()
            .ok_or(Error::MlsGroupInvalidState("own_leaf_node not present in group"))?
            .credential();
        Ok(credential)
    }
}
