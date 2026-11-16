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
