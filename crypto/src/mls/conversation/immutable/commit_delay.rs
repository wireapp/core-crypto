use std::collections::HashSet;

use itertools::Itertools;
use log::{debug, trace};
use openmls::{messages::proposals::Proposal, prelude::LeafNodeIndex};

use super::Conversation;

/// These constants intend to ramp up the delay and flatten the curve for later positions
const DELAY_RAMP_UP_MULTIPLIER: f32 = 120.0;
const DELAY_RAMP_UP_SUB: u64 = 106;
const DELAY_POS_LINEAR_INCR: u64 = 15;
const DELAY_POS_LINEAR_RANGE: std::ops::RangeInclusive<u64> = 1..=3;

impl Conversation {
    /// Helps consumer by providing a deterministic delay in seconds for him to commit its pending proposal.
    /// It depends on the index of the client in the ratchet tree
    /// * `self_index` - ratchet tree index of self client
    /// * `epoch` - current group epoch
    /// * `nb_members` - number of clients in the group
    pub async fn compute_next_commit_delay(&self) -> Option<u64> {
        let group = self.group().await;

        if group.pending_proposals().next().is_none() {
            trace!("No pending proposals, no delay needed");
            return None;
        }

        let removed_indices = group
            .pending_proposals()
            .filter_map(|proposal| {
                if let Proposal::Remove(remove_proposal) = proposal.proposal() {
                    Some(remove_proposal.removed())
                } else {
                    None
                }
            })
            .collect::<HashSet<LeafNodeIndex>>();

        let self_index = group.own_leaf_index();
        debug!(removed_index:? = removed_indices, self_index:? = self_index; "Indexes");
        // Find a remove proposal that concerns us
        let is_self_removed = removed_indices.contains(&self_index);

        // If our own client has been removed, don't commit
        if is_self_removed {
            debug!("Self removed from group, no delay needed");
            return None;
        }

        let epoch = group.epoch().as_u64();

        // Position in array among non-blank leaf node indices
        let self_position = group
            .members()
            .find_position(|member| member.index == self_index)
            .map(|pos| pos.0 as u64)
            .unwrap();
        let removed_indices_to_the_left = removed_indices
            .iter()
            .filter(|index| index.u32() < self_index.u32())
            .count() as u64;

        // This shifts our own self-position to the left (tree-wise) from as many as there was removed members that have
        // a smaller leaf index than us (older members)
        let own_index = self_position - removed_indices_to_the_left;

        // Post-commit visualization of the number of members after remove proposals
        let nb_members = (group.members().count() as u64).saturating_sub(removed_indices.len() as u64);

        Some(Self::calculate_delay(own_index, epoch, nb_members))
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
mod tests {
    use super::*;
    use crate::test_utils::*;

    fn assert_delays_are_unique(delays: &[(&str, Option<u64>)]) {
        for (i, (name_a, delay_a)) in delays.iter().enumerate() {
            assert!(delay_a.is_some(), "{name_a} should have a delay");
            for (name_b, delay_b) in &delays[i + 1..] {
                assert_ne!(
                    delay_a, delay_b,
                    "{name_a} and {name_b} have the same commit delay; all delays: {delays:?}"
                );
            }
        }
    }

    #[test]
    fn calculate_delay_single() {
        let (self_index, epoch, nb_members) = (0, 0, 1);
        let delay = Conversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    fn calculate_delay_max() {
        let (self_index, epoch, nb_members) = (u64::MAX, u64::MAX, u64::MAX);
        let delay = Conversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    fn calculate_delay_min() {
        let (self_index, epoch, nb_members) = (u64::MIN, u64::MIN, u64::MAX);
        let delay = Conversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    fn calculate_delay_zero_members() {
        let (self_index, epoch, nb_members) = (0, 0, u64::MIN);
        let delay = Conversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    fn calculate_delay_min_max() {
        let (self_index, epoch, nb_members) = (u64::MIN, u64::MAX, u64::MAX);
        let delay = Conversation::calculate_delay(self_index, epoch, nb_members);
        assert_eq!(delay, 0);
    }

    #[test]
    fn calculate_delay_n() {
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
            let delay = Conversation::calculate_delay(self_index, epoch, nb_members);
            assert_eq!(delay, expected_delay);
        }
    }

    #[apply(all_cred_cipher)]
    async fn calculate_delay_creator_removed(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        Box::pin(async move {
            let conversation = case
                .create_conversation([&alice, &bob])
                .await
                .invite_notify([&charlie])
                .await;
            assert_eq!(conversation.member_count().await, 3);

            let proposal_guard = conversation.remove_proposal(&alice).await;
            let (proposal_guard, result) = proposal_guard.notify_member_fallible(&bob).await;
            let bob_decrypted_message = result.unwrap();
            let (_, result) = proposal_guard.notify_member_fallible(&charlie).await;
            let charlie_decrypted_message = result.unwrap();

            let bob_hypothetical_position = 0;
            let charlie_hypothetical_position = 1;

            assert_eq!(
                bob_decrypted_message.as_proposal().unwrap().delay,
                Some(DELAY_POS_LINEAR_INCR * bob_hypothetical_position)
            );

            assert_eq!(
                charlie_decrypted_message.as_proposal().unwrap().delay,
                Some(DELAY_POS_LINEAR_INCR * charlie_hypothetical_position)
            );
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    async fn calculate_delay_is_unique_with_blank_leaves(case: TestContext) {
        let [alice, bob, charlie, dave, eve, frank] = case.sessions().await;
        Box::pin(async move {
            // leaf indices: alice 0, bob 1, charlie 2, dave 3, eve 4
            let conversation = case
                .create_conversation([&alice, &bob, &charlie, &dave, &eve])
                .await
                // removing bob leaves a blank leaf at index 1
                .remove_notify(&bob)
                .await;
            assert_eq!(conversation.member_count().await, 4);

            // any pending proposal which isn't a remove will do
            let mut proposal_guard = conversation.invite_proposal(&frank).await;
            let mut delays = vec![(
                "alice",
                proposal_guard
                    .conversation()
                    .guard_of(&alice)
                    .await
                    .compute_next_commit_delay()
                    .await,
            )];
            for (name, member) in [("charlie", &charlie), ("dave", &dave), ("eve", &eve)] {
                let (guard, result) = proposal_guard.notify_member_fallible(member).await;
                proposal_guard = guard;
                delays.push((name, result.unwrap().as_proposal().unwrap().delay));
            }

            assert_delays_are_unique(&delays);
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    async fn calculate_delay_with_blank_leaves_ignores_removed_members_to_the_right(case: TestContext) {
        let [alice, bob, charlie, dave, eve] = case.sessions().await;
        Box::pin(async move {
            // leaf indices: alice 0, bob 1, charlie 2, dave 3, eve 4
            let conversation = case
                .create_conversation([&alice, &bob, &charlie, &dave, &eve])
                .await
                // removing bob and charlie leaves blank leaves at indices 1 and 2
                .remove_notify(&bob)
                .await
                .remove_notify(&charlie)
                .await;
            assert_eq!(conversation.member_count().await, 3);

            // eve is to the right of dave, so her removal must not shift dave's position
            let proposal_guard = conversation.remove_proposal(&eve).await;
            let alice_delay = proposal_guard
                .conversation()
                .guard_of(&alice)
                .await
                .compute_next_commit_delay()
                .await;
            let (_, result) = proposal_guard.notify_member_fallible(&dave).await;
            let dave_delay = result.unwrap().as_proposal().unwrap().delay;
            let delays = vec![("alice", alice_delay), ("dave", dave_delay)];

            // post-commit, the members are alice and dave, at positions 0 and 1
            assert_delays_are_unique(&delays);
        })
        .await;
    }
}
