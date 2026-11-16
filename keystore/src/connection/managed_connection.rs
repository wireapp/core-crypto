//! The connection to a database, in a small wrapping struct.

#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
pub(crate) struct ManagedConnection {
    #[deref]
    #[deref_mut]
    inner: rusqlite::Connection,
    last_data_version: Option<i64>,
}

impl From<rusqlite::Connection> for ManagedConnection {
    fn from(inner: rusqlite::Connection) -> Self {
        Self {
            inner,
            last_data_version: None,
        }
    }
}

impl ManagedConnection {
    pub(crate) fn into_inner(self) -> rusqlite::Connection {
        self.inner
    }

    /// Get the value of SQLite's `PRAGMA data_version` and compute `externally_modified` from it.
    ///
    /// Returns `true` when the database knows that an external connection changed database state
    /// since the last time this was called.
    ///
    /// See: <https://www.sqlite.org/pragma.html#pragma_data_version>
    pub(crate) fn update_data_version(&mut self) -> rusqlite::Result<bool> {
        let data_version = self.inner.pragma_query_one(None, "data_version")?;
        let externally_modified = self
            .last_data_version
            .is_some_and(|stored_data_version| stored_data_version != data_version);
        self.last_data_version = Some(data_version);
        Ok(externally_modified)
    }
}

#[cfg(all(test, target_os = "unknown"))]
mod tests {
    use std::sync::Arc;

    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{Database, DatabaseKey};

    #[wasm_bindgen_test]
    async fn dropping_transaction_and_database_rolls_back_and_closes_before_reopen() {
        let name = format!("managed-{}.db", uuid::Uuid::new_v4());
        let key = DatabaseKey::generate();
        let db = Database::open(&name, &key).await.unwrap();
        db.conn()
            .await
            .execute_batch("CREATE TABLE cleanup_probe(value INTEGER); INSERT INTO cleanup_probe VALUES (1);")
            .unwrap();
        let tx = db.new_transaction().await.unwrap();
        tx.conn()
            .unwrap()
            .execute("UPDATE cleanup_probe SET value=2", [])
            .unwrap();

        drop(tx);
        drop(db);

        let db = Database::open(&name, &key).await.unwrap();
        assert_eq!(
            db.conn()
                .await
                .query_row("SELECT value FROM cleanup_probe", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.conn()
                .await
                .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        Arc::into_inner(db).unwrap().wipe().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn rekey_keeps_wal_and_reopens_with_the_new_key() {
        let name = format!("rekey-{}.db", uuid::Uuid::new_v4());
        let old_key = DatabaseKey::generate();
        let new_key = DatabaseKey::generate();
        let db = Database::open(&name, &old_key).await.unwrap();
        db.conn()
            .await
            .execute_batch("CREATE TABLE rekey_probe(value INTEGER); INSERT INTO rekey_probe VALUES (7)")
            .unwrap();
        db.update_key(&new_key).await.unwrap();
        assert_eq!(
            db.conn()
                .await
                .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        Arc::into_inner(db).unwrap().close().await.unwrap();
        assert!(Database::open(&name, &old_key).await.is_err());
        let db = Database::open(&name, &new_key).await.unwrap();
        assert_eq!(
            db.conn()
                .await
                .query_row("SELECT value FROM rekey_probe", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            7
        );
        Arc::into_inner(db).unwrap().wipe().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn dropped_transaction_releases_connection_for_the_next_transaction() {
        let name = format!("rollback-{}.db", uuid::Uuid::new_v4());
        let db = Database::open(&name, &DatabaseKey::generate()).await.unwrap();
        db.conn()
            .await
            .execute_batch("CREATE TABLE rollback_probe(value INTEGER)")
            .unwrap();
        let tx = db.new_transaction().await.unwrap();
        tx.conn()
            .unwrap()
            .execute("INSERT INTO rollback_probe VALUES (1)", [])
            .unwrap();
        drop(tx);
        let tx = db.new_transaction().await.unwrap();
        assert_eq!(
            tx.conn()
                .unwrap()
                .query_row("SELECT count(*) FROM rollback_probe", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        tx.commit().await.unwrap();
        Arc::into_inner(db).unwrap().wipe().await.unwrap();
    }
}
