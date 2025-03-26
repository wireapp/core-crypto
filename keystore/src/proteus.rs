use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::{Connection, FetchFromDatabase},
    entities::ProteusPrekey,
};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait CryptoKeystoreProteus {
    async fn proteus_store_prekey(&self, id: u16, prekey: &[u8]) -> CryptoKeystoreResult<()>;
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl CryptoKeystoreProteus for Connection {
    async fn proteus_store_prekey(&self, id: u16, prekey: &[u8]) -> CryptoKeystoreResult<()> {
        let entity = ProteusPrekey::from_raw(id, prekey.to_vec());
        self.save(entity).await?;
        Ok(())
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl proteus_traits::PreKeyStore for Connection {
    type Error = CryptoKeystoreError;

    async fn prekey(
        &mut self,
        id: proteus_traits::RawPreKeyId,
    ) -> Result<Option<proteus_traits::RawPreKey>, Self::Error> {
        Ok(self
            .find::<ProteusPrekey>(&id.to_le_bytes())
            .await?
            .map(|db_prekey| db_prekey.prekey.clone()))
    }

    async fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), Self::Error> {
        Connection::remove::<ProteusPrekey, _>(self, id.to_le_bytes()).await?;

        Ok(())
    }
}
