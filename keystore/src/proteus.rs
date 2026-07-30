use crate::{CryptoKeystoreResult, Database, entities::ProteusPrekey};

impl Database {
    pub async fn proteus_store_prekey(&self, id: u16, prekey: &[u8]) -> CryptoKeystoreResult<()> {
        self.with_transaction(async |tx| tx.save(ProteusPrekey::from_raw(id, prekey.to_vec())).await)
            .await
    }
}
