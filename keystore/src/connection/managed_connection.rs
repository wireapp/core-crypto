//! SQLite ownership and entry on Wasm, where synchronous I/O can suspend through JSPI.
//!
//! The entry guard covers whole SQLite operations and must precede synchronous
//! connection locks. It is not held for the lifetime of a keystore transaction.
//! Native builds retain rusqlite's connection and their existing locking behavior.

#[cfg(not(target_os = "unknown"))]
pub(crate) type ManagedConnection = rusqlite::Connection;

#[cfg(not(target_os = "unknown"))]
pub(crate) struct SqliteGuard;

#[cfg(not(target_os = "unknown"))]
impl SqliteGuard {
    pub(crate) fn lock() -> Self {
        Self
    }
}

#[cfg(target_os = "unknown")]
pub(crate) use sqlite_wasm_vfs::opfs_jspi::{SqliteGuard, defer};
#[cfg(target_os = "unknown")]
pub(crate) use wasm::ManagedConnection;

/// Drop the connection lock before releasing the SQLite entry guard.
pub(crate) struct Guarded<T> {
    pub(crate) inner: T,
    pub(crate) _sqlite: SqliteGuard,
}

impl<T: std::ops::Deref> std::ops::Deref for Guarded<T> {
    type Target = T::Target;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(target_os = "unknown")]
mod wasm {
    use std::ops::{Deref, DerefMut};

    use super::{SqliteGuard, defer};

    #[derive(Debug)]
    // The inner is always `Some` while the value is usable; taken only by `close` or `Drop`.
    pub(crate) struct ManagedConnection(Option<rusqlite::Connection>);

    impl From<rusqlite::Connection> for ManagedConnection {
        fn from(conn: rusqlite::Connection) -> Self {
            Self(Some(conn))
        }
    }

    impl Deref for ManagedConnection {
        type Target = rusqlite::Connection;

        fn deref(&self) -> &Self::Target {
            self.0.as_ref().expect("connection is open")
        }
    }

    impl DerefMut for ManagedConnection {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.0.as_mut().expect("connection is open")
        }
    }

    impl ManagedConnection {
        pub(crate) fn close(mut self) -> Result<(), (Self, rusqlite::Error)> {
            let _sqlite = SqliteGuard::lock();
            self.0
                .take()
                .expect("connection is open")
                .close()
                .map_err(|(conn, error)| (conn.into(), error))
        }
    }

    impl Drop for ManagedConnection {
        fn drop(&mut self) {
            if let Some(conn) = self.0.take() {
                defer(move || {
                    if let Err((conn, error)) = conn.close() {
                        log::warn!(err:err = error; "failed to close SQLite connection");
                        drop(conn);
                    }
                });
            }
        }
    }
}

/// wasm-bindgen-test does not enter test futures through promising exports.
#[cfg(all(test, target_os = "unknown"))]
pub(crate) async fn run_test(test: impl std::future::Future<Output = ()> + 'static) {
    use wasm_bindgen::JsValue;

    let mut test = Some(test);
    let completion = js_sys::Promise::new(&mut |resolve, _reject| {
        let test = test.take().expect("promise executor runs once");
        defer(move || {
            let result = wasm_bindgen_futures::future_to_promise(async move {
                test.await;
                Ok(JsValue::UNDEFINED)
            });
            resolve.call1(&JsValue::UNDEFINED, &result).unwrap();
        });
    });
    wasm_bindgen_futures::JsFuture::from(completion).await.unwrap();
}

#[cfg(all(test, target_os = "unknown"))]
mod tests {
    use std::{cell::RefCell, rc::Rc, sync::Arc};

    use wasm_bindgen_test::wasm_bindgen_test;

    use super::run_test;
    use crate::{Database, DatabaseKey};

    #[wasm_bindgen_test]
    async fn drop_outside_jspi_rolls_back_and_closes_before_reopen() {
        let name = format!("managed-{}.db", uuid::Uuid::new_v4());
        let key = DatabaseKey::generate();
        let owners = Rc::new(RefCell::new(None));
        run_test({
            let (name, key, owners) = (name.clone(), key.clone(), owners.clone());
            async move {
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
                *owners.borrow_mut() = Some((db, tx));
            }
        })
        .await;

        // Deliberately outside a promising export, as with a JavaScript finalizer.
        let (db, tx) = owners.borrow_mut().take().unwrap();
        drop(tx);
        drop(db);

        run_test(async move {
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
        })
        .await;
    }

    #[wasm_bindgen_test]
    async fn rekey_restores_wal_and_reopens_with_the_new_key() {
        run_test(async {
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
        })
        .await;
    }

    #[wasm_bindgen_test]
    async fn dropped_transaction_releases_connection_for_the_next_transaction() {
        run_test(async {
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
        })
        .await;
    }
}
