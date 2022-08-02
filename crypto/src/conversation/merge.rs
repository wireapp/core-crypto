//! A MLS group can be merged (aka committed) when it has a pending commit. The latter is a commit
//! we created which is still waiting to be "committed". By doing so, we will apply all the
//! modifications present in the commit to the ratchet tree and also persist the new group in the
//! keystore. Like this, even if the application crashes we will be able to restore.
//!
//! This table summarizes when a MLS group can be merged:
//!
//! | can be merged ?   | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ❌              | ✅              |
//! | 1+ pend. Proposal | ❌              | ✅              |
//!

use mls_crypto_provider::MlsCryptoProvider;

use crate::{ConversationId, CryptoResult, MlsCentral, MlsConversation, MlsError};

/// Abstraction over a MLS group capable of merging a commit
impl MlsConversation {
    /// see [MlsCentral::commit_accepted]
    pub async fn commit_accepted(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<()> {
        self.group.merge_pending_commit().map_err(MlsError::from)?;
        self.persist_group_when_changed(backend, false).await
    }
}

/// A MLS group is a distributed object scattered across many parties. We use a Delivery Service
/// to orchestrate those parties. So when we create a commit, a mutable operation, it has to be
/// validated by the Delivery Service. But it might occur that another group member did the
/// exact same thing at the same time. So if we arrive second in this race, we must "rollback" the commit
/// we created and accept ("merge") the other one.
/// A client would
/// * Create a commit
/// * Send the commit to the Delivery Service
/// * When Delivery Service responds
///     * 200 OK --> use [MlsCentral::commit_accepted] to merge the commit
///     * 409 CONFLICT --> do nothing. [MlsCentral::decrypt_message] will restore the proposals not committed
///     * 5xx --> retry
impl MlsCentral {
    /// The commit we created has been accepted by the Delivery Service. Hence it is guaranteed
    /// to be used for the new epoch.
    /// We can now safely "merge" it (effectively apply the commit to the group) and update it
    /// in the keystore. The previous can be discarded to respect Forward Secrecy.
    pub async fn commit_accepted(&mut self, conversation_id: &ConversationId) -> CryptoResult<()> {
        Self::get_conversation_mut(&mut self.mls_groups, conversation_id)?
            .commit_accepted(&self.mls_backend)
            .await
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{credential::CredentialSupplier, prelude::MlsProposal, test_utils::*, MlsConversationConfiguration};

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod commit_accepted {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_clear_pending_commit_and_proposals(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice", "bob"], move |[mut alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    alice_central.new_proposal(&id, MlsProposal::Update).await.unwrap();
                    alice_central
                        .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                        .await
                        .unwrap();
                    assert!(!alice_central.pending_proposals(&id).is_empty());
                    assert!(alice_central.pending_commit(&id).is_some());
                    alice_central.commit_accepted(&id).await.unwrap();
                    assert!(alice_central.pending_commit(&id).is_none());
                    assert!(alice_central.pending_proposals(&id).is_empty());
                })
            })
            .await
        }
    }
}
