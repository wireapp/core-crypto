use openmls::prelude::{GroupEpoch, GroupId, JoinProposal, MlsMessageOut};

use super::Result;
use crate::{ConversationId, CredentialRef, MlsError, RecursiveError, transaction_context::TransactionContext};

impl TransactionContext {
    /// Crafts a new external Add proposal. Enables a client outside a group to request addition to this group.
    /// For Wire only, the client must belong to an user already in the group
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    /// * `epoch` - the current epoch of the group. See [openmls::group::GroupEpoch]
    /// * `credential_ref` - of the new [openmls::prelude::KeyPackage] to create
    ///
    /// # Return type
    /// Returns a message with the proposal to be add a new client
    #[cfg_attr(test, crate::dispotent)]
    pub async fn new_external_add_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: GroupEpoch,
        credential_ref: &CredentialRef,
    ) -> Result<MlsMessageOut> {
        let group_id = GroupId::from_slice(conversation_id.as_ref());

        let kp = self.generate_key_package(credential_ref, None).await?;

        let database = &self.database().await?;
        let credential = credential_ref
            .load(database)
            .await
            .map_err(RecursiveError::mls_credential_ref("loading credential"))?;

        JoinProposal::new(kp, group_id, epoch, &credential.signature_key_pair)
            .map_err(MlsError::wrap("creating join proposal"))
            .map_err(Into::into)
    }
}
