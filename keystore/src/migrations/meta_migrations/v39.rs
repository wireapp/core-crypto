//! Backfill `epoch`, `ciphersuite`, `own_leaf_index`, `credential_id`, and `credential_type` on
//! the unified `mls_groups` table by parsing each row's `state` blob.
//!
//! These columns can't be populated in SQL: the values only exist inside the postcard-serialized
//! `openmls::group::MlsGroup` stored in `state`.

use log::warn;
use openmls::{
    group::{MlsGroup, QueuedProposal},
    prelude::{LeafNode, LeafNodeIndex, Proposal, Sender},
};
use rusqlite::{named_params, params};

use crate::{CryptoKeystoreResult, Sha256Hash, deser};

pub(crate) const VERSION: i32 = 39;

pub(crate) fn meta_migration(tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT id, state FROM mls_groups")?;
        stmt.query_map([], |row| Ok((row.get("id")?, row.get("state")?)))?
            .collect::<Result<_, _>>()?
    };

    // drop these statements once they're no longer needed
    {
        let mut update_stmt = tx.prepare(
            "UPDATE mls_groups SET
                epoch = :epoch,
                ciphersuite = :ciphersuite,
                own_leaf_index = :own_leaf_index,
                credential_id = :credential_id,
                credential_type = :credential_type
            WHERE id = :id",
        )?;

        let mut delete_stmt = tx.prepare("DELETE FROM mls_groups WHERE id = ?")?;

        let mut query_credential_existence = tx.prepare(
            "SELECT EXISTS (
                SELECT 1 FROM mls_credentials
                WHERE public_key_sha256 = :credential_id AND credential_type = :credential_type
            )",
        )?;

        for (id, state) in rows {
            let group = match deser::<MlsGroup>(&state) {
                Ok(group) => group,
                Err(err) => {
                    warn!(
                        "failed to deserialize mls group state for id {} due to {err}; removing",
                        hex::encode(&id)
                    );
                    delete_stmt.execute(params![&id])?;
                    continue;
                }
            };

            // An inactive group is one we have been evicted from. Our leaf is gone from the
            // ratchet tree, and if our former slot was recycled by a member added in the same
            // commit then `own_leaf` resolves to *their* leaf — so backfilling would point this
            // row at a credential which was never ours, and would do so undetectably whenever we
            // happen to hold that credential too. Nothing in the state blob can recover our own.
            // Dropping the row loses nothing: `core-crypto` wipes a conversation as soon as it
            // processes our eviction, so a row in this state would not have survived there either.
            if !group.is_active() {
                warn!(
                    "mls group {} is inactive, i.e. we have been evicted from it; removing",
                    hex::encode(&id)
                );
                delete_stmt.execute(params![&id])?;
                continue;
            }

            let Some((credential_id, credential_type)) = current_credential(&group) else {
                warn!(
                    "could not determine current credential for mls group {}: own leaf node not found",
                    hex::encode(&id)
                );
                delete_stmt.execute(params![&id])?;
                continue;
            };

            let credential_exists = query_credential_existence.query_one(
                named_params! {":credential_id": credential_id, ":credential_type": credential_type},
                |row| row.get::<_, bool>(0),
            )?;
            if !credential_exists {
                warn!(
                    "group id {} references a credential which does not exist (hash {credential_id:?}, type {credential_type})",
                    hex::encode(&id)
                );
                delete_stmt.execute(params![&id])?;
                continue;
            }

            update_stmt.execute(named_params! {
                ":epoch": group.epoch().as_u64() as i64,
                ":ciphersuite": group.ciphersuite() as u16,
                ":own_leaf_index": group.own_leaf_index().u32(),
                ":credential_id": credential_id,
                ":credential_type": credential_type,
                ":id": id,
            })?;
        }
    }

    Ok(())
}

/// Find the current leaf node's credential hash and type, matching the logic in `core-crypto`'s
/// `group_metadata::current_own_leaf`: a pending own update proposal takes priority over the
/// currently committed leaf, which in turn takes priority over the leaf staged by our own pending
/// commit.
///
/// That last fallback is what preserves a saved pending external join: such a group has staged the
/// commit which will insert our leaf, but the ratchet tree it was built from does not contain that
/// leaf yet, so it has no committed own leaf to read. Those rows are persisted deliberately, so
/// that `join_by_external_commit` can recover from a failed send or merge, and deleting them here
/// would destroy exactly that recovery state.
///
/// Only meaningful for an active group; see the `is_active` check in [`meta_migration`].
fn current_credential(group: &MlsGroup) -> Option<(Sha256Hash, u16)> {
    let own_index = group.own_leaf_index();
    let leaf = extract_own_updated_node_from_proposals(&own_index, group.pending_proposals())
        .or_else(|| group.own_leaf())
        .or_else(|| group.pending_commit()?.get_update_path_leaf_node())?;
    let id = Sha256Hash::hash_from(leaf.signature_key().as_slice());
    let credential_type: u16 = leaf.credential().credential_type().into();
    Some((id, credential_type))
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
