use crate::{
    CryptoKeystoreResult,
    migrations::LegacyPersistedMlsGroup,
    traits::{BorrowPrimaryKey, PrimaryKey},
};

impl LegacyPersistedMlsGroup {
    pub(crate) fn save(&self, tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
        let mut stmt =
            tx.prepare_cached("INSERT OR REPLACE INTO mls_groups (id, state, parent_id) VALUES (?, ?, ?)")?;
        stmt.execute((&self.id, &self.state, &self.parent_id))?;
        Ok(())
    }
}

impl PrimaryKey for LegacyPersistedMlsGroup {
    type PrimaryKey = Vec<u8>;

    fn primary_key(&self) -> Self::PrimaryKey {
        self.id.clone()
    }
}

impl BorrowPrimaryKey for LegacyPersistedMlsGroup {
    type BorrowedPrimaryKey = [u8];

    fn borrow_primary_key(&self) -> &Self::BorrowedPrimaryKey {
        &self.id
    }
}
