use std::collections::HashSet;

use log::trace;
use openmls::prelude::{LeafNodeIndex, Proposal};

use crate::ClientId;

impl super::ImmutableConversation {
    /// Exports the clients from a conversation
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    pub fn get_client_ids(&self) -> Vec<ClientId> {
        self.group
            .members()
            .map(|kp| ClientId::from(kp.credential.identity().to_owned()))
            .collect()
    }

    /// Gather pending remove proposals
    fn pending_removals(&self) -> Vec<LeafNodeIndex> {
        self.group
            .pending_proposals()
            .filter_map(|proposal| match proposal.proposal() {
                Proposal::Remove(remove) => Some(remove.removed()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    /// Get actual group members and subtract pending remove proposals
    pub fn members_in_next_epoch(&self) -> Vec<ClientId> {
        let pending_removals = self.pending_removals();
        let existing_clients = self
            .group
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
