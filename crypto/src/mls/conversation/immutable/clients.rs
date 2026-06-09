use std::collections::HashSet;

use log::trace;
use openmls::prelude::{LeafNodeIndex, Proposal};

use crate::ClientId;

impl super::Conversation {
    /// Exports the clients from a conversation
    /// Does NOT include history client ids.
    pub async fn get_client_ids(&self) -> Result<Vec<ClientId>> {
        let prefix = HISTORY_CLIENT_ID_PREFIX.as_bytes();
        self.group()
            .await
            .members()
            .filter(|member| !member.credential.identity().starts_with(prefix))
            .map(|kp| {
                ClientId::new_from_bytes(kp.credential.identity().to_owned())
                    .map_err(RecursiveError::mls_client("new client id from bytes"))
                    .map_err(Into::into)
            })
            .collect()
    }

    /// Exports the history client ids from a conversation
    pub async fn get_history_client_ids(&self) -> Vec<Vec<u8>> {
        let prefix = HISTORY_CLIENT_ID_PREFIX.as_bytes();

        self.group()
            .await
            .members()
            .filter_map(|kp| {
                let identity = kp.credential.identity();

                identity.starts_with(prefix).then(|| identity.to_owned())
            })
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
