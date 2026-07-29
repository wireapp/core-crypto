use crate::{CryptoKeystoreError, Transaction, entities::ProteusPrekey, traits::FetchFromDatabase};

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl proteus_traits::PreKeyStore for Transaction {
    type Error = CryptoKeystoreError;

    async fn prekey(&self, id: proteus_traits::RawPreKeyId) -> Result<Option<proteus_traits::RawPreKey>, Self::Error> {
        FetchFromDatabase::get::<ProteusPrekey>(self, &id)
            .await
            .map(|maybe_prekey| maybe_prekey.map(|mut db_prekey| std::mem::take(&mut db_prekey.prekey)))
    }

    async fn remove(&self, id: proteus_traits::RawPreKeyId) -> Result<(), Self::Error> {
        <Self>::remove::<ProteusPrekey>(self, &id).await
    }
}
