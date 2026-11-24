//! SQL for the part of a group's state that openmls writes.
//!
//! Most of it lives in columns of the group's `mls_groups` row, which core-crypto inserts before openmls writes
//! anything. So writes to the row fail if it doesn't exist, while clearing a column of a missing row does nothing.
//! The two pieces that are lists live in `mls_group_own_leaf_nodes` and `mls_group_queued_proposals`.
//!
//! Everything here deals in bytes. Converting openmls's types to and from them is up to the caller.

use rusqlite::{Connection, OptionalExtension as _, params};
use zeroize::Zeroizing;

use crate::{CryptoKeystoreError, CryptoKeystoreResult};

/// A column of `mls_groups` holding one serialized piece of openmls's group state.
#[derive(Debug, Clone, Copy)]
pub(super) enum BlobColumn {
    JoinConfig,
    Tree,
    Context,
    InterimTranscriptHash,
    ConfirmationTag,
    MessageSecrets,
    ResumptionPskStore,
    EpochSecrets,
}

impl BlobColumn {
    fn name(self) -> &'static str {
        match self {
            BlobColumn::JoinConfig => "join_config",
            BlobColumn::Tree => "tree",
            BlobColumn::Context => "context",
            BlobColumn::InterimTranscriptHash => "interim_transcript_hash",
            BlobColumn::ConfirmationTag => "confirmation_tag",
            BlobColumn::MessageSecrets => "message_secrets",
            BlobColumn::ResumptionPskStore => "resumption_psk_store",
            BlobColumn::EpochSecrets => "epoch_secrets",
        }
    }
}

/// openmls's `MlsGroupState`, in the form `mls_groups.group_status` and `mls_groups.pending_commit` store it.
pub(super) enum GroupStatus {
    Operational,
    /// The serialized `PendingCommitState`.
    PendingCommit(Zeroizing<Vec<u8>>),
    Inactive,
}

impl GroupStatus {
    // These values are fixed by the V53 migration.
    const OPERATIONAL: u8 = 0;
    const PENDING_COMMIT: u8 = 1;
    const INACTIVE: u8 = 2;
}

/// Fail if an update to a group's row changed nothing, because the row doesn't exist.
fn expect_group_row(changed: usize, group_id: &[u8]) -> CryptoKeystoreResult<()> {
    if changed == 0 {
        return Err(CryptoKeystoreError::NotFound("mls group", hex::encode(group_id)));
    }
    Ok(())
}

pub(super) fn read_blob(
    conn: &Connection,
    group_id: &[u8],
    column: BlobColumn,
) -> CryptoKeystoreResult<Option<Zeroizing<Vec<u8>>>> {
    let value = conn
        .prepare_cached(&format!("SELECT {} FROM mls_groups WHERE id = ?", column.name()))?
        .query_row([group_id], |row| row.get::<_, Option<Vec<u8>>>(0))
        .optional()?
        .flatten();
    Ok(value.map(Zeroizing::new))
}

pub(super) fn write_blob(
    conn: &Connection,
    group_id: &[u8],
    column: BlobColumn,
    value: &[u8],
) -> CryptoKeystoreResult<()> {
    let changed = conn
        .prepare_cached(&format!("UPDATE mls_groups SET {} = ? WHERE id = ?", column.name()))?
        .execute(params![value, group_id])?;
    expect_group_row(changed, group_id)
}

pub(super) fn clear_blob(conn: &Connection, group_id: &[u8], column: BlobColumn) -> CryptoKeystoreResult<()> {
    conn.prepare_cached(&format!("UPDATE mls_groups SET {} = NULL WHERE id = ?", column.name()))?
        .execute([group_id])?;
    Ok(())
}

/// Write the group context, along with the epoch and ciphersuite it contains.
///
/// Writing them in one statement keeps the `epoch` and `ciphersuite` columns in step with the context.
pub(super) fn write_context(
    conn: &Connection,
    group_id: &[u8],
    context: &[u8],
    epoch: u64,
    ciphersuite: u16,
) -> CryptoKeystoreResult<()> {
    let changed = conn
        .prepare_cached("UPDATE mls_groups SET context = ?, epoch = ?, ciphersuite = ? WHERE id = ?")?
        .execute(params![context, epoch, ciphersuite, group_id])?;
    expect_group_row(changed, group_id)
}

pub(super) fn read_own_leaf_index(conn: &Connection, group_id: &[u8]) -> CryptoKeystoreResult<Option<u32>> {
    conn.prepare_cached("SELECT own_leaf_index FROM mls_groups WHERE id = ?")?
        .query_row([group_id], |row| row.get(0))
        .optional()
        .map_err(Into::into)
}

pub(super) fn write_own_leaf_index(
    conn: &Connection,
    group_id: &[u8],
    own_leaf_index: u32,
) -> CryptoKeystoreResult<()> {
    let changed = conn
        .prepare_cached("UPDATE mls_groups SET own_leaf_index = ? WHERE id = ?")?
        .execute(params![own_leaf_index, group_id])?;
    expect_group_row(changed, group_id)
}

pub(super) fn read_group_status(conn: &Connection, group_id: &[u8]) -> CryptoKeystoreResult<Option<GroupStatus>> {
    let row = conn
        .prepare_cached("SELECT group_status, pending_commit FROM mls_groups WHERE id = ?")?
        .query_row([group_id], |row| {
            Ok((row.get::<_, Option<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
        })
        .optional()?;
    let Some((Some(status), pending_commit)) = row else {
        return Ok(None);
    };
    let status = match (status, pending_commit) {
        (GroupStatus::OPERATIONAL, None) => GroupStatus::Operational,
        (GroupStatus::PENDING_COMMIT, Some(pending_commit)) => {
            GroupStatus::PendingCommit(Zeroizing::new(pending_commit))
        }
        (GroupStatus::INACTIVE, None) => GroupStatus::Inactive,
        // The table's CHECK constraints rule this out.
        (status, pending_commit) => {
            return Err(CryptoKeystoreError::MlsKeyStoreError(format!(
                "group status {status} with{} a pending commit",
                if pending_commit.is_some() { "" } else { "out" }
            )));
        }
    };
    Ok(Some(status))
}

pub(super) fn write_group_status(conn: &Connection, group_id: &[u8], status: &GroupStatus) -> CryptoKeystoreResult<()> {
    let (status, pending_commit) = match status {
        GroupStatus::Operational => (GroupStatus::OPERATIONAL, None),
        GroupStatus::PendingCommit(pending_commit) => (GroupStatus::PENDING_COMMIT, Some(pending_commit.as_slice())),
        GroupStatus::Inactive => (GroupStatus::INACTIVE, None),
    };
    let changed = conn
        .prepare_cached("UPDATE mls_groups SET group_status = ?, pending_commit = ? WHERE id = ?")?
        .execute(params![status, pending_commit, group_id])?;
    expect_group_row(changed, group_id)
}

pub(super) fn clear_group_status(conn: &Connection, group_id: &[u8]) -> CryptoKeystoreResult<()> {
    conn.prepare_cached("UPDATE mls_groups SET group_status = NULL, pending_commit = NULL WHERE id = ?")?
        .execute([group_id])?;
    Ok(())
}

pub(super) fn append_own_leaf_node(conn: &Connection, group_id: &[u8], leaf_node: &[u8]) -> CryptoKeystoreResult<()> {
    conn.prepare_cached("INSERT INTO mls_group_own_leaf_nodes (group_id, leaf_node) VALUES (?, ?)")?
        .execute(params![group_id, leaf_node])?;
    Ok(())
}

/// Our own leaf nodes in this group, in the order they were appended.
pub(super) fn own_leaf_nodes(conn: &Connection, group_id: &[u8]) -> CryptoKeystoreResult<Vec<Vec<u8>>> {
    conn.prepare_cached("SELECT leaf_node FROM mls_group_own_leaf_nodes WHERE group_id = ? ORDER BY id")?
        .query_map([group_id], |row| row.get(0))?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

pub(super) fn delete_own_leaf_nodes(conn: &Connection, group_id: &[u8]) -> CryptoKeystoreResult<()> {
    conn.prepare_cached("DELETE FROM mls_group_own_leaf_nodes WHERE group_id = ?")?
        .execute([group_id])?;
    Ok(())
}

/// Queue a proposal, unless one with this reference is already queued.
///
/// A proposal reference is a hash of the proposal, so a proposal already queued under it is the same proposal.
pub(super) fn queue_proposal(
    conn: &Connection,
    group_id: &[u8],
    proposal_ref: &[u8],
    proposal: &[u8],
) -> CryptoKeystoreResult<()> {
    conn.prepare_cached(
        "INSERT INTO mls_group_queued_proposals (group_id, proposal_ref, proposal) VALUES (?, ?, ?)
        ON CONFLICT (group_id, proposal_ref) DO NOTHING",
    )?
    .execute(params![group_id, proposal_ref, proposal])?;
    Ok(())
}

/// The references of the proposals queued in this group, in the order they were queued.
pub(super) fn queued_proposal_refs(conn: &Connection, group_id: &[u8]) -> CryptoKeystoreResult<Vec<Vec<u8>>> {
    conn.prepare_cached("SELECT proposal_ref FROM mls_group_queued_proposals WHERE group_id = ? ORDER BY rowid")?
        .query_map([group_id], |row| row.get(0))?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

/// The proposals queued in this group with their references, in the order they were queued.
pub(super) fn queued_proposals(conn: &Connection, group_id: &[u8]) -> CryptoKeystoreResult<Vec<(Vec<u8>, Vec<u8>)>> {
    conn.prepare_cached(
        "SELECT proposal_ref, proposal FROM mls_group_queued_proposals WHERE group_id = ? ORDER BY rowid",
    )?
    .query_map([group_id], |row| Ok((row.get(0)?, row.get(1)?)))?
    .collect::<Result<_, _>>()
    .map_err(Into::into)
}

pub(super) fn remove_proposal(conn: &Connection, group_id: &[u8], proposal_ref: &[u8]) -> CryptoKeystoreResult<()> {
    conn.prepare_cached("DELETE FROM mls_group_queued_proposals WHERE group_id = ? AND proposal_ref = ?")?
        .execute(params![group_id, proposal_ref])?;
    Ok(())
}

pub(super) fn clear_proposal_queue(conn: &Connection, group_id: &[u8]) -> CryptoKeystoreResult<()> {
    conn.prepare_cached("DELETE FROM mls_group_queued_proposals WHERE group_id = ?")?
        .execute([group_id])?;
    Ok(())
}
