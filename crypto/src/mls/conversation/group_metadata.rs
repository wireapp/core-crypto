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
