use core_crypto_keystore::CryptoKeystoreMls as _;
use openmls_traits::OpenMlsCryptoProvider as _;

use super::Result;
use crate::{KeystoreError, MlsError, RecursiveError, mls::conversation::ConversationGuard};

impl ConversationGuard {
    /// Destroys a group locally
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn wipe(&mut self) -> Result<()> {
        // to the degree that it's easy, fallibly get things before doing any mutation
        let provider = self.crypto_provider().await?;
        let mut conversation_cache = self
            .tx_context
            .mls_groups()
            .await
            .map_err(RecursiveError::transaction("getting mls conversation cache"))?;

        self.mutate_group(async |database, group, _, _| {
            // the own client may or may not have generated an epoch keypair in the previous epoch
            // Since it is a terminal operation, ignoring the error is fine here.
            let _ = group.delete_previous_epoch_keypairs(&provider).await;

            // collect all the relevant proposal refs without holding onto the group;
            // we'll need to mutate the group in shortly
            let proposals = group
                .pending_proposals()
                .map(|proposal| proposal.proposal_reference().to_owned())
                .collect::<Vec<_>>();
            for proposal in proposals {
                // Update proposals rekey the own leaf node. Hence the associated encryption keypair has to be cleared
                group
                    .remove_pending_proposal(database, &proposal)
                    .await
                    .map_err(MlsError::wrap("removing pending proposal"))?;
            }

            Ok(())
        })
        .await?;

        let id = self.id();

        provider
            .key_store()
            .mls_group_delete(&id)
            .await
            .map_err(KeystoreError::wrap("deleting mls group"))?;
        let _ = conversation_cache.remove(&id);

        Ok(())
    }
}
