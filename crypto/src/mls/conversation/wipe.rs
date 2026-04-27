use openmls_traits::OpenMlsCryptoProvider;

use super::Result;
use crate::{MlsConversation, MlsError, mls_provider::MlsCryptoProvider};

impl MlsConversation {
    pub(crate) async fn wipe_associated_entities(&mut self, backend: &MlsCryptoProvider) -> Result<()> {
        // the own client may or may not have generated an epoch keypair in the previous epoch
        // Since it is a terminal operation, ignoring the error is fine here.
        let _ = self.group.delete_previous_epoch_keypairs(backend).await;

        let pending_proposals = self.group.pending_proposals().cloned().collect::<Vec<_>>();
        for proposal in pending_proposals {
            // Update proposals rekey the own leaf node. Hence the associated encryption keypair has to be cleared
            self.group
                .remove_pending_proposal(backend.key_store(), proposal.proposal_reference())
                .await
                .map_err(MlsError::wrap("removing pending proposal"))?;
        }

        Ok(())
    }
}
