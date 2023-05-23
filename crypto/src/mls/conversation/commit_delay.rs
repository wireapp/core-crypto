use openmls_traits::OpenMlsCryptoProvider;

use super::MlsConversation;
use crate::{mls::MlsCryptoProvider, MlsError};

/// These constants intend to ramp up the delay and flatten the curve for later positions
pub(self) const DELAY_RAMP_UP_MULTIPLIER: f32 = 120.0;
pub(self) const DELAY_RAMP_UP_SUB: u64 = 106;
pub(self) const DELAY_POS_LINEAR_INCR: u64 = 15;
pub(self) const DELAY_POS_LINEAR_RANGE: std::ops::RangeInclusive<u64> = 1..=3;

impl MlsConversation {
    /// Helps consumer by providing a deterministic delay in seconds for him to commit its pending proposal.
    /// It depends on the index of the client in the ratchet tree
    /// * `self_index` - ratchet tree index of self client
    /// * `epoch` - current group epoch
    /// * `nb_members` - number of clients in the group
    pub fn compute_next_commit_delay(&self, backend: &MlsCryptoProvider) -> Option<u64> {
        use openmls::{messages::proposals::Proposal, prelude::KeyPackageRef};

        if self.group.pending_proposals().count() > 0 {
            let removed_kprefs: Vec<&KeyPackageRef> = self
                .group
                .pending_proposals()
                .filter_map(|proposal| {
                    if let Proposal::Remove(remove_proposal) = proposal.proposal() {
                        Some(remove_proposal.removed())
                    } else {
                        None
                    }
                })
                .collect();

            let is_self_removed = if let Some(self_kpref) = self.group.key_package_ref() {
                // Find a remove proposal that concerns us
                removed_kprefs.iter().any(|kpref| *kpref == self_kpref)
            } else {
                // If we don't have a leaf node for the current client, MOST likely we've been removed from the group from a previous commit.
                // So we shouldn't be committing anything
                true
            };

            // If our own client has been removed, don't commit
            if is_self_removed {
                return None;
            }

            let epoch = self.group.epoch().as_u64();
            let mut own_index = self.group.own_leaf_index() as u64;
            let members = self.group.members();

            // Look for members that were removed at the left of our tree in order to shift our own leaf index (post-commit tree visualization)
            let left_tree_diff = members
                .iter()
                .take(own_index as usize)
                .try_fold(0u32, |mut acc, keypackage| {
                    let hash_ref = keypackage.hash_ref(backend.crypto())?;
                    if removed_kprefs.contains(&&hash_ref) {
                        acc += 1;
                    }

                    Result::<_, MlsError>::Ok(acc)
                })
                .map_err(MlsError::from)
                .unwrap_or_default();

            // Post-commit visualization of the number of members after remove proposals
            let nb_members = (self.group.members().len() as u64).saturating_sub(removed_kprefs.len() as u64);
            // This shifts our own leaf index to the left (tree-wise) from as many as there was removed members that have a smaller leaf index than us (older members)
            own_index = own_index.saturating_sub(left_tree_diff as u64);

            Some(Self::calculate_delay(own_index, epoch, nb_members))
        } else {
            None
        }
    }

    fn calculate_delay(self_index: u64, epoch: u64, nb_members: u64) -> u64 {
        let position = if nb_members > 0 {
            ((epoch % nb_members) + (self_index % nb_members)) % nb_members + 1
        } else {
            1
        };

        if DELAY_POS_LINEAR_RANGE.contains(&position) {
            position.saturating_sub(1) * DELAY_POS_LINEAR_INCR
        } else {
            (((position as f32).ln() * DELAY_RAMP_UP_MULTIPLIER) as u64).saturating_sub(DELAY_RAMP_UP_SUB)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        mls::{conversation::handshake::MlsConversationCreationMessage, proposal::MlsProposal},
        test_utils::*,
    };
    use tls_codec::Serialize as _;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    pub fn calculate_delay_single() {
        let (self_index, epoch, nb_members) = (0, 0, 1);
        let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    #[wasm_bindgen_test]
    pub fn calculate_delay_max() {
        let (self_index, epoch, nb_members) = (u64::MAX, u64::MAX, u64::MAX);
        let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    #[wasm_bindgen_test]
    pub fn calculate_delay_min() {
        let (self_index, epoch, nb_members) = (u64::MIN, u64::MIN, u64::MAX);
        let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    #[wasm_bindgen_test]
    pub fn calculate_delay_zero_members() {
        let (self_index, epoch, nb_members) = (0, 0, u64::MIN);
        let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    #[wasm_bindgen_test]
    pub fn calculate_delay_min_max() {
        let (self_index, epoch, nb_members) = (u64::MIN, u64::MAX, u64::MAX);
        let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    #[wasm_bindgen_test]
    pub fn calculate_delay_n() {
        let epoch = 1;
        let nb_members = 10;

        let indexes_delays = [
            (0, 15),
            (1, 30),
            (2, 60),
            (3, 87),
            (4, 109),
            (5, 127),
            (6, 143),
            (7, 157),
            (8, 170),
            (9, 0),
            // wrong but it shouldn't cause problems
            (10, 15),
        ];

        for (self_index, expected_delay) in indexes_delays {
            let delay = MlsConversation::calculate_delay(self_index, epoch, nb_members);
            assert_eq!(delay, expected_delay);
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn calculate_delay_creator_removed(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "charlie"],
            move |[mut alice_central, mut bob_central, mut charlie_central]| {
                Box::pin(async move {
                    let id = conversation_id();

                    alice_central
                        .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let MlsConversationCreationMessage {
                        welcome: bob_welcome, ..
                    } = alice_central
                        .add_members_to_conversation(&id, &mut [bob_central.rand_member().await])
                        .await
                        .unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                    alice_central.commit_accepted(&id).await.unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                    bob_central
                        .process_welcome_message(bob_welcome.clone(), case.custom_cfg())
                        .await
                        .unwrap();

                    let MlsConversationCreationMessage {
                        welcome: charlie_welcome,
                        commit,
                        ..
                    } = alice_central
                        .add_members_to_conversation(&id, &mut [charlie_central.rand_member().await])
                        .await
                        .unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    alice_central.commit_accepted(&id).await.unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 3);

                    let _ = bob_central
                        .decrypt_message(&id, &commit.tls_serialize_detached().unwrap())
                        .await
                        .unwrap();

                    charlie_central
                        .process_welcome_message(charlie_welcome, case.custom_cfg())
                        .await
                        .unwrap();

                    assert_eq!(
                        bob_central.get_conversation_unchecked(&id).await.id(),
                        alice_central.get_conversation_unchecked(&id).await.id()
                    );
                    assert_eq!(
                        charlie_central.get_conversation_unchecked(&id).await.id(),
                        alice_central.get_conversation_unchecked(&id).await.id()
                    );

                    let proposal_bundle = alice_central
                        .new_proposal(&id, MlsProposal::Remove(alice_central.read_client_id()))
                        .await
                        .unwrap();

                    let bob_hypothetical_position = 0;
                    let charlie_hypothetical_position = 1;

                    let bob_decrypted_message = bob_central
                        .decrypt_message(&id, &proposal_bundle.proposal.tls_serialize_detached().unwrap())
                        .await
                        .unwrap();

                    assert_eq!(
                        bob_decrypted_message.delay,
                        Some(DELAY_POS_LINEAR_INCR * bob_hypothetical_position)
                    );

                    let charlie_decrypted_message = charlie_central
                        .decrypt_message(&id, &proposal_bundle.proposal.tls_serialize_detached().unwrap())
                        .await
                        .unwrap();

                    assert_eq!(
                        charlie_decrypted_message.delay,
                        Some(DELAY_POS_LINEAR_INCR * charlie_hypothetical_position)
                    );
                })
            },
        )
        .await;
    }
}
