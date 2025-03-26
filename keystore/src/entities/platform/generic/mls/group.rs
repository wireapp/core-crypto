use crate::{
    CryptoKeystoreResult,
    entities::{Entity, EntityBase, PersistedMlsGroup, PersistedMlsGroupExt},
};

#[async_trait::async_trait]
impl PersistedMlsGroupExt for PersistedMlsGroup {
    fn parent_id(&self) -> Option<&[u8]> {
        self.parent_id.as_deref()
    }

    async fn child_groups(&self, conn: &mut <Self as EntityBase>::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        let id = self.id_raw();
        let mut conn = conn.conn().await;
        let transaction = conn.transaction()?;
        let mut query = transaction.prepare_cached("SELECT rowid FROM mls_groups WHERE parent_id = ?")?;
        let mut rows = query.query_map([id], |r| r.get(0))?;

        let entities = rows.try_fold(Vec::new(), |mut acc, rowid_result| {
            use std::io::Read as _;
            let rowid = rowid_result?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "id", rowid, true)?;
            let mut id = vec![];
            blob.read_to_end(&mut id)?;
            blob.close()?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "state", rowid, true)?;
            let mut state = vec![];
            blob.read_to_end(&mut state)?;
            blob.close()?;

            let mut parent_id = None;
            // Ignore errors because null blobs cause errors on open
            if let Ok(mut blob) =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "parent_id", rowid, true)
            {
                if !blob.is_empty() {
                    let mut tmp = Vec::with_capacity(blob.len());
                    blob.read_to_end(&mut tmp)?;
                    parent_id.replace(tmp);
                }
                blob.close()?;
            }

            acc.push(Self { id, parent_id, state });
            crate::CryptoKeystoreResult::Ok(acc)
        })?;

        Ok(entities)
    }
}
