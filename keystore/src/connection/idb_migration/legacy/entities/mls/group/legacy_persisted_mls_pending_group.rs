use zeroize::ZeroizeOnDrop;

use crate::{
    CryptoKeystoreResult,
    traits::{BorrowPrimaryKey, PrimaryKey},
};

/// The MLS pending-group shape shared by the final legacy IDB schema and SQL schema v22.
///
/// `mls_pending_groups` is a distinct table at this schema version (it isn't unified into
/// `mls_groups` until V39, long after v22), so this can't reuse [`crate::entities::PersistedMlsGroup`]:
/// that type's shape belongs to the unified table this migration hasn't reached yet.
///
/// Only used by the WASM legacy IndexedDB migration: unlike [`LegacyPersistedMlsGroup`], nothing on
/// native ever needed to read a pre-unification pending group by hand.
#[derive(ZeroizeOnDrop)]
pub(crate) struct LegacyPersistedMlsPendingGroup {
    pub(crate) id: Vec<u8>,
    pub(crate) state: Vec<u8>,
}

impl LegacyPersistedMlsPendingGroup {
    pub(crate) fn save(&self, tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
        let mut stmt = tx.prepare_cached("INSERT OR REPLACE INTO mls_pending_groups (id, state) VALUES (?, ?)")?;
        stmt.execute((&self.id, &self.state))?;
        Ok(())
    }
}

impl PrimaryKey for LegacyPersistedMlsPendingGroup {
    type PrimaryKey = Vec<u8>;

    fn primary_key(&self) -> Self::PrimaryKey {
        self.id.clone()
    }
}

impl BorrowPrimaryKey for LegacyPersistedMlsPendingGroup {
    type BorrowedPrimaryKey<'a> = &'a [u8];

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        &self.id
    }
}
