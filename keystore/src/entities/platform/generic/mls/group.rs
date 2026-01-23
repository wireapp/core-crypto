use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    entities::{ParentGroupId, PersistedMlsGroup},
    traits::SearchableEntity,
};

#[async_trait]
impl<'a> SearchableEntity<ParentGroupId<'a>> for PersistedMlsGroup {
    async fn find_all_matching(
        conn: &mut Self::ConnectionType,
        parent_id: &ParentGroupId<'a>,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let parent_id = *parent_id.as_ref();
        let mut conn = conn.conn().await;
        let mut query = conn.prepare_cached("SELECT id, parent_id, state FROM mls_groups WHERE parent_id = ?")?;
        query
            .query_and_then([parent_id], |row| {
                let id = row.get::<_, String>("id")?;
                let id = hex::decode(id)?;
                let parent_id = row.get("parent_id")?;
                let state = row.get("state")?;

                Ok(PersistedMlsGroup { id, state, parent_id })
            })?
            .collect::<Result<_, _>>()
    }
}
