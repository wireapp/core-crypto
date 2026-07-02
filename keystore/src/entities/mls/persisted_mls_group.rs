use rusqlite::Connection;
use zeroize::Zeroize;

use crate::{
    CryptoKeystoreResult,
    traits::{KeyType, UnifiedEntityGetBorrowed as _, UnifiedSearchableEntity},
};

/// This type exists so that we can efficiently search for the children of a given group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::From, derive_more::Into, derive_more::AsRef)]
pub struct ParentGroupId<'a>(&'a [u8]);

impl<'a> KeyType for ParentGroupId<'a> {
    fn bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        self.0.into()
    }
}

/// Entity representing a persisted `MlsGroup`
#[derive(
    core_crypto_macros::Debug,
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
#[entity(collection_name = "mls_groups")]
#[sensitive]
pub struct PersistedMlsGroup {
    pub id: Vec<u8>,
    pub state: Vec<u8>,
    pub parent_id: Option<Vec<u8>>,
}

impl PersistedMlsGroup {
    /// Get the parent group of this group.
    pub async fn parent_group(&self, conn: &Connection) -> CryptoKeystoreResult<Option<Self>> {
        let Some(parent_id) = self.parent_id.as_deref() else {
            return Ok(None);
        };

        Self::get_borrowed(conn, parent_id)
    }

    /// Get all children of this group.
    pub async fn child_groups(&self, conn: &Connection) -> CryptoKeystoreResult<Vec<Self>> {
        let parent_id = self.id.as_slice();
        Self::find_all_matching(conn, &parent_id.into())
    }
}

impl<'a> UnifiedSearchableEntity<ParentGroupId<'a>> for PersistedMlsGroup {
    fn find_all_matching(conn: &Connection, parent_id: &ParentGroupId<'a>) -> CryptoKeystoreResult<Vec<Self>> {
        let parent_id = *parent_id.as_ref();

        let mut stmt = conn.prepare_cached("SELECT id, parent_id, state FROM mls_groups WHERE parent_id = ?")?;
        stmt.query_and_then([parent_id], |row| {
            let id = row.get("id")?;
            let parent_id = row.get("parent_id")?;
            let state = row.get("state")?;

            Ok(PersistedMlsGroup { id, state, parent_id })
        })?
        .collect()
    }

    fn matches(&self, search_key: &ParentGroupId<'a>) -> bool {
        self.parent_id.as_deref() == Some(*search_key.as_ref())
    }
}
