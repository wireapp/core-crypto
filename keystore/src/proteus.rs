use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database, entities::ProteusPrekey, traits::FetchFromDatabase as _,
};

impl Database {
    pub async fn proteus_store_prekey(&self, id: u16, prekey: &[u8]) -> CryptoKeystoreResult<()> {
        self.with_transaction(async |tx| tx.save(ProteusPrekey::from_raw(id, prekey.to_vec())).await)
            .await
    }
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl proteus_traits::PreKeyStore for Database {
    type Error = CryptoKeystoreError;

    async fn prekey(&self, id: proteus_traits::RawPreKeyId) -> Result<Option<proteus_traits::RawPreKey>, Self::Error> {
        self.get::<ProteusPrekey>(&id)
            .await
            .map(|maybe_prekey| maybe_prekey.map(|mut db_prekey| std::mem::take(&mut db_prekey.prekey)))
    }

    async fn remove(&self, id: proteus_traits::RawPreKeyId) -> Result<(), Self::Error> {
        self.with_transaction(async |tx| tx.remove::<ProteusPrekey>(&id).await)
            .await
            .map(|_| ())
    }
}
