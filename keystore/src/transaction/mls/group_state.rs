//! Converting a group's state between openmls's types and the bytes [`group_state_sql`] stores.

use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use super::{
    Storage,
    group_state_sql::{self, BlobColumn, GroupStatus},
    storage::Access,
};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::{convert, raw_bytes},
    deser, ser,
};

/// The first byte of a serialized `MlsGroupState`, which tells its variant.
///
/// postcard encodes an enum as the index of its variant, followed by the variant's fields. `MlsGroupState`'s
/// variants all have indices below 128, so the index takes one byte. Splitting it off saves serializing a pending
/// commit, which can be large, a second time.
pub(super) mod group_state_tag {
    pub(in crate::transaction::mls) const PENDING_COMMIT: u8 = 0;
    pub(in crate::transaction::mls) const OPERATIONAL: u8 = 1;
    pub(in crate::transaction::mls) const INACTIVE: u8 = 2;
}

/// The status to store for a serialized `MlsGroupState`.
pub(super) fn status_from_serialized(serialized: &[u8]) -> CryptoKeystoreResult<GroupStatus> {
    match serialized.split_first() {
        Some((&group_state_tag::OPERATIONAL, [])) => Ok(GroupStatus::Operational),
        Some((&group_state_tag::PENDING_COMMIT, pending_commit)) => {
            Ok(GroupStatus::PendingCommit(Zeroizing::new(pending_commit.to_vec())))
        }
        Some((&group_state_tag::INACTIVE, [])) => Ok(GroupStatus::Inactive),
        _ => Err(CryptoKeystoreError::MlsKeyStoreError(
            "unexpected serialization of a group state".into(),
        )),
    }
}

/// The serialized `MlsGroupState` for a stored status.
pub(super) fn serialized_from_status(status: GroupStatus) -> Zeroizing<Vec<u8>> {
    match status {
        GroupStatus::Operational => Zeroizing::new(vec![group_state_tag::OPERATIONAL]),
        GroupStatus::PendingCommit(pending_commit) => {
            let mut serialized = Zeroizing::new(Vec::with_capacity(1 + pending_commit.len()));
            serialized.push(group_state_tag::PENDING_COMMIT);
            serialized.extend_from_slice(&pending_commit);
            serialized
        }
        GroupStatus::Inactive => Zeroizing::new(vec![group_state_tag::INACTIVE]),
    }
}

#[expect(private_bounds, reason = "the methods here are private too")]
impl<'a, A: Access<'a>> Storage<A> {
    pub(super) fn write_group_blob(
        &self,
        group_id: &impl Serialize,
        column: BlobColumn,
        value: &impl Serialize,
    ) -> CryptoKeystoreResult<()> {
        let value = Zeroizing::new(ser(value)?);
        group_state_sql::write_blob(&*self.write_conn()?, &raw_bytes(group_id)?, column, &value)
    }

    pub(super) fn read_group_blob<T: DeserializeOwned>(
        &self,
        group_id: &impl Serialize,
        column: BlobColumn,
    ) -> CryptoKeystoreResult<Option<T>> {
        group_state_sql::read_blob(&*self.read_conn()?, &raw_bytes(group_id)?, column)?
            .map(|value| deser(&value))
            .transpose()
    }

    /// Write a value that is a byte string underneath as its raw bytes.
    pub(super) fn write_group_bytes(
        &self,
        group_id: &impl Serialize,
        column: BlobColumn,
        value: &impl Serialize,
    ) -> CryptoKeystoreResult<()> {
        group_state_sql::write_blob(&*self.write_conn()?, &raw_bytes(group_id)?, column, &raw_bytes(value)?)
    }

    pub(super) fn read_group_bytes<T: DeserializeOwned>(
        &self,
        group_id: &impl Serialize,
        column: BlobColumn,
    ) -> CryptoKeystoreResult<Option<T>> {
        group_state_sql::read_blob(&*self.read_conn()?, &raw_bytes(group_id)?, column)?
            .map(|value| convert::<[u8], _>(&value))
            .transpose()
    }

    pub(super) fn clear_group_blob(&self, group_id: &impl Serialize, column: BlobColumn) -> CryptoKeystoreResult<()> {
        group_state_sql::clear_blob(&*self.write_conn()?, &raw_bytes(group_id)?, column)
    }
}
