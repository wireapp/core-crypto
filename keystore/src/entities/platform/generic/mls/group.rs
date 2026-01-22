use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    entities::{ParentGroupId, PersistedMlsGroup, PersistedMlsGroupExt},
    traits::{BorrowPrimaryKey, SearchableEntity},
};

#[async_trait]
impl<'a> SearchableEntity<ParentGroupId<'a>> for PersistedMlsGroup {
    async fn find_all_matching(
        conn: &mut Self::ConnectionType,
        parent_id: &ParentGroupId<'a>,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let parent_id = *parent_id.as_ref();
        let mut conn = conn.conn().await;
        let mut stmt = conn.prepare_cached("SELECT id_hex, parent_id, state FROM mls_groups WHERE parent_id = ?")?;
        stmt.query_and_then([parent_id], |row| {
            let id = row.get::<_, String>("id_hex")?;
            let id = hex::decode(id)?;
            let parent_id = row.get("parent_id")?;
            let state = row.get("state")?;

            Ok(PersistedMlsGroup { id, state, parent_id })
        })?
        .collect()
    }
}

#[async_trait]
impl PersistedMlsGroupExt for PersistedMlsGroup {
    fn parent_id(&self) -> Option<&[u8]> {
        self.parent_id.as_deref()
    }

    async fn child_groups(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        let parent_id = self.borrow_primary_key().into();
        Self::find_all_matching(conn, &parent_id).await
    }
}
