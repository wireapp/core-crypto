use crate::{CryptoKeystoreError, FetchFromDatabase as _, connection::Database, entities::ProteusPrekey};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl proteus_traits::PreKeyStore for Database {
    type Error = CryptoKeystoreError;

    async fn prekey(
        &mut self,
        id: proteus_traits::RawPreKeyId,
    ) -> Result<Option<proteus_traits::RawPreKey>, Self::Error> {
        Ok(self
            .get::<ProteusPrekey>(&id)
            .await?
            .map(|db_prekey| db_prekey.prekey.clone()))
    }

    async fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), Self::Error> {
        Database::remove::<ProteusPrekey, _>(self, id.to_le_bytes()).await?;

        Ok(())
    }
}
