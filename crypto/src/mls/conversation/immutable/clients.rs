use std::collections::HashSet;

use log::trace;
use openmls::prelude::{LeafNodeIndex, Proposal};

use crate::ClientId;

impl super::Conversation {
    /// Exports the clients from a conversation
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    pub async fn get_client_ids(&self) -> Vec<ClientId> {
        self.group()
            .await
            .members()
            .map(|kp| ClientId::from(kp.credential.identity().to_owned()))
            .collect()
    }

    /// Gather pending remove proposals
    async fn pending_removals(&self) -> Vec<LeafNodeIndex> {
        self.group()
            .await
            .pending_proposals()
            .filter_map(|proposal| match proposal.proposal() {
                Proposal::Remove(remove) => Some(remove.removed()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    /// Get actual group members and subtract pending remove proposals
    pub async fn members_in_next_epoch(&self) -> Vec<ClientId> {
        let pending_removals = self.pending_removals().await;
        let existing_clients = self
            .group()
            .await
            .members()
            .filter_map(|kp| {
                if !pending_removals.contains(&kp.index) {
                    Some(kp.credential.identity().to_owned().into())
                } else {
                    trace!(client_index:% = kp.index; "Client is pending removal");
                    None
                }
            })
            .collect::<HashSet<_>>();
        existing_clients.into_iter().collect()
    }
}
