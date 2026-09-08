//! Deriving `PersistedMlsGroup`'s small denormalized columns from a live `openmls::group::MlsGroup`.
//!
//! Shared between [`super::immutable::MlsGroupState::persist`] (an established or newly-merged
//! group) and [`super::pending::PendingConversation`] (a group awaiting external-commit
//! confirmation): both need the same derivation, and it has to agree with what
//! `keystore`'s `v39` meta migration backfilled for existing rows.

use core_crypto_keystore::{
    Sha256Hash,
    entities::{StoredCredential, StoredCredentialPk},
    traits::FetchFromDatabase,
};
use openmls::{
    group::{MlsGroup, QueuedProposal},
    prelude::{LeafNode, LeafNodeIndex, Proposal, Sender},
};

use super::{Error, Result};
use crate::KeystoreError;

/// The leaf node whose credential should be treated as "current": the target of a pending own
/// update proposal if one exists, otherwise the actually-committed own leaf, otherwise the leaf we
/// are about to occupy according to our own pending commit.
///
/// That last fallback covers joining by external commit: `MlsGroup::join_by_external_commit` builds
/// the ratchet tree from the group info, which does not contain our leaf yet, so
/// [`MlsGroup::own_leaf_index`] points at the blank slot we are about to fill and
/// [`MlsGroup::own_leaf`] is `None`. Our leaf lives in the staged commit until it is merged. Note
/// that the group is *active* in that state, so an `is_active` check does not distinguish it.
pub(super) fn current_own_leaf(group: &MlsGroup) -> Option<&LeafNode> {
    extract_own_updated_node_from_proposals(&group.own_leaf_index(), group.pending_proposals())
        .or_else(|| group.own_leaf())
        .or_else(|| own_leaf_from_pending_commit(group))
}

/// Our own leaf as staged by our own pending commit, if we have one which contains an update path.
///
/// [`MlsGroup::pending_commit`] only ever returns a commit *we* created; commits received from
/// others are merged directly instead of being staged here. The update path leaf of a commit we
/// authored is therefore always our own leaf.
///
/// This is deliberately consulted only after [`MlsGroup::own_leaf`]: while a commit is pending, the
/// credential actually in force is still the committed one, so the staged leaf is only "current"
/// when we have no leaf in the tree at all.
fn own_leaf_from_pending_commit(group: &MlsGroup) -> Option<&LeafNode> {
    group.pending_commit()?.get_update_path_leaf_node()
}

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

/// Get the primary key of the credential this group currently presents on our behalf.
///
/// Credentials have composite primary keys, which can be constructed from the current group.
///
/// # Only valid while the group is active
///
/// This derives the credential from our leaf in the ratchet tree, which only identifies us while we
/// are a member. Once we have been evicted our leaf is gone, and if our former slot was recycled by
/// a member added in the same commit, it identifies *them* — so this would report their credential,
/// not ours. Callers must establish [`MlsGroup::is_active`] first; an evicted conversation has to
/// reuse the credential already recorded for it instead of deriving a new one.
pub(super) async fn current_credential_pk(
    group: &MlsGroup,
    database: &impl FetchFromDatabase,
) -> Result<StoredCredentialPk> {
    // it's a coding problem if this happens, so we panic here instead of using a runtime check
    debug_assert!(
        group.is_active(),
        "this function cannot produce valid results if called on an inactive group"
    );

    let leaf = current_own_leaf(group).ok_or(Error::MlsGroupInvalidState(
        "this group has no leaf node and therefore no credential",
    ))?;
    let id = Sha256Hash::hash_from(leaf.signature_key().as_slice());
    let credential_type: u16 = leaf.credential().credential_type().into();
    let pk = StoredCredentialPk {
        public_key_hash: id,
        credential_type,
    };

    // The credential we present must be one we hold, so its absence is a real inconsistency rather
    // than something a caller could sensibly carry on without.
    database
        .get::<StoredCredential>(&pk)
        .await
        .map_err(KeystoreError::wrap(
            "checking for existence of credential in the database",
        ))?
        .ok_or(Error::MlsGroupInvalidState("group credential is not in the keystore"))
        .map(|_| pk)
}

#[cfg(test)]
mod tests {
    //! These exercise the denormalized credential columns end to end: the value which actually
    //! lands in `mls_groups` for a conversation, in each of the situations where our own leaf is
    //! hard to pin down.

    use std::sync::Arc;

    use core_crypto_keystore::{Sha256Hash, entities::PersistedMlsGroup, traits::FetchFromDatabase as _};

    use crate::{
        CertificateBundle, ConversationId, Credential, CredentialRef,
        test_utils::{TestConversation, *},
    };

    /// The row recorded for `conversation` in `session`'s keystore.
    async fn persisted_group(session: &SessionContext, conversation: &ConversationId) -> Arc<PersistedMlsGroup> {
        session
            .transaction
            .database()
            .await
            .unwrap()
            .get_borrowed::<PersistedMlsGroup>(conversation.as_ref().keystore())
            .await
            .unwrap()
            .expect("conversation is persisted")
    }

    /// The `(credential_id, credential_type)` pair recorded for `conversation` in `session`'s
    /// keystore.
    async fn persisted_credential(session: &SessionContext, conversation: &ConversationId) -> (Sha256Hash, u16) {
        let row = persisted_group(session, conversation).await;
        (row.credential_id, row.credential_type)
    }

    /// The same pair, as it should appear for a conversation using `credential`.
    fn expected_credential(credential: &CredentialRef) -> (Sha256Hash, u16) {
        (credential.public_key_hash(), credential.r#type().into())
    }

    /// The leaf index `target` occupies in `conversation`, according to `observer`.
    async fn leaf_index_of(
        conversation: &TestConversation<'_>,
        observer: &SessionContext,
        target: &SessionContext,
    ) -> u32 {
        let target_key_hash = target.initial_credential.public_key_hash();
        conversation
            .guard_of(observer)
            .await
            .group()
            .await
            .members()
            .find(|member| Sha256Hash::hash_from(member.signature_key.as_slice()) == target_key_hash)
            .expect("target is a member of the conversation")
            .index
            .u32()
    }

    /// Joining by external commit has to record the credential the caller asked to join with, even
    /// before the commit is merged, when our leaf exists only in the staged commit.
    #[apply(all_cred_cipher)]
    async fn external_join_records_the_credential_it_joined_with(case: TestContext) {
        let [alice, bob] = case.sessions().await;

        let conversation = case.create_conversation([&alice]).await;
        let id = conversation.id().clone();

        // Bob's leaf is not in the ratchet tree yet: it is in the commit he has just staged.
        let (commit_guard, mut pending_conversation) = conversation.external_join_unmerged(&bob).await;
        assert_eq!(
            persisted_credential(&bob, &id).await,
            expected_credential(&bob.initial_credential),
            "a pending external join must record the credential it was created with"
        );

        let conversation = commit_guard.notify_members().await;
        pending_conversation.merge().await.unwrap();

        // and it still agrees once the leaf really is in the tree
        assert_eq!(
            persisted_credential(&bob, &id).await,
            expected_credential(&bob.initial_credential),
            "merging an external join must not change which credential is recorded"
        );
        assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
    }

    /// Being evicted has to keep working when our leaf slot is recycled by a member added in the
    /// same commit.
    ///
    /// Six members, of which the last two are removed while one new member is added, all in a
    /// single commit: the joiner is placed in a slot freed by the removals. The `own_leaf_index` of
    /// the member which vacated that slot then resolves to the joiner's leaf, so deriving a
    /// credential from the tree while persisting the very commit which evicted us reads *their*
    /// credential instead of ours — which fails outright when the joiner's credential is not one we
    /// hold, and silently records the wrong one when it is.
    ///
    /// This deliberately does not assert which credential the row ends up with, because no row is
    /// left to inspect: a commit which leaves us inactive is followed immediately by a wipe of the
    /// conversation, so it is gone by the time `decrypt_message` returns. What is observable, and
    /// what this shape used to break, is that the eviction goes through at all.
    #[apply(all_cred_cipher)]
    async fn eviction_succeeds_when_our_leaf_slot_is_recycled(case: TestContext) {
        const ALL_MEMBERS_COUNT: usize = 7;
        const INITIAL_MEMBERS_COUNT: usize = 6;
        const REMAINING_MEMBERS_COUNT: usize = 4;

        let all_members = case.sessions::<ALL_MEMBERS_COUNT>().await;
        let initial_members = &all_members[..INITIAL_MEMBERS_COUNT];
        let removed_members = &all_members[REMAINING_MEMBERS_COUNT..INITIAL_MEMBERS_COUNT];
        let joiner = &all_members[INITIAL_MEMBERS_COUNT];

        let mut conversation = case.create_conversation(initial_members).await;
        let id = conversation.id().clone();

        for member in removed_members {
            conversation = conversation
                .acting_as(&all_members[1])
                .await
                .remove_proposal_notify(member)
                .await;
        }
        conversation = conversation.invite_proposal_notify(joiner).await;
        let mut commit_guard = conversation.commit_pending_proposals().await;

        let mut vacated_leaf_indices = Vec::with_capacity(removed_members.len());
        for member in removed_members {
            // while this member is still in the group, note the slot it is about to vacate
            vacated_leaf_indices.push(persisted_group(member, &id).await.own_leaf_index);

            let (guard, result) = commit_guard.notify_member_fallible(member).await;
            commit_guard = guard;

            // deriving a credential from the recycled slot used to make this fail
            let decrypted = result.expect("a member must be able to process its own eviction");
            assert!(
                decrypted.as_commit().is_some_and(|commit| !commit.is_active),
                "the commit must report the conversation as no longer active"
            );
            assert!(
                member.transaction.conversation(&id).await.is_err(),
                "handling our own eviction must leave the conversation wiped"
            );
        }

        // Confirm we really did reproduce the recycled slot, so this test cannot quietly stop
        // exercising the interesting case: the joiner sits where a removed member used to.
        let conversation = commit_guard.notify_members().await;
        let recycled_leaf_index = leaf_index_of(&conversation, &all_members[0], joiner).await;
        assert!(
            vacated_leaf_indices.contains(&recycled_leaf_index),
            "expected the joiner to take a slot vacated by one of the removed members, \
                 but it took {recycled_leaf_index} and they vacated {vacated_leaf_indices:?}"
        );
    }

    /// Rotating our credential has to be reflected in the column, which is the reason this
    /// derivation exists at all: nothing carries the new credential to `persist` explicitly.
    #[apply(all_cred_cipher)]
    async fn rotating_the_credential_updates_the_recorded_one(case: TestContext) {
        // A basic credential is just our client id, so a "new" one for the same client compares
        // equal to the old one and openmls declines to rotate anything. Only x509 can rotate here.
        if !case.is_x509() {
            return;
        }

        let [alice] = case.sessions().await;

        let conversation = case.create_conversation([&alice]).await;
        let id = conversation.id().clone();
        assert_eq!(
            persisted_credential(&alice, &id).await,
            expected_credential(&alice.initial_credential)
        );

        let intermediate_ca = alice.x509_chain_unchecked().find_local_intermediate_ca();
        let certificate = CertificateBundle::new_with_default_values(intermediate_ca, None);
        let new_credential = Credential::x509(case.cipher_suite(), certificate).unwrap();
        alice
            .transaction
            .add_credential_without_clientid_check(new_credential.clone())
            .await
            .unwrap();
        let new_credential = CredentialRef::from_credential(&new_credential);

        conversation.set_credential_by_ref_notify(&new_credential).await;

        assert_eq!(
            persisted_credential(&alice, &id).await,
            expected_credential(&new_credential),
            "the recorded credential must follow a rotation"
        );
    }
}
