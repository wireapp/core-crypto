//! The connection to a database, in a small wrapping struct.

#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
pub(crate) struct ManagedConnection {
    #[deref]
    #[deref_mut]
    inner: rusqlite::Connection,
}

impl From<rusqlite::Connection> for ManagedConnection {
    fn from(inner: rusqlite::Connection) -> Self {
        Self { inner }
    }
}

impl ManagedConnection {
    pub(crate) fn into_inner(self) -> rusqlite::Connection {
        self.inner
    }
}
