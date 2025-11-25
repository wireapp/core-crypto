use crate::{CoreCryptoError, CoreCryptoFfi, CoreCryptoResult};

#[uniffi::export]
impl CoreCryptoFfi {
    /// See [core_crypto::Session::random_bytes]
    pub async fn random_bytes(&self, len: u32) -> CoreCryptoResult<Vec<u8>> {
        let len = len.try_into().map_err(CoreCryptoError::generic())?;
        self.inner.random_bytes(len).map_err(Into::into)
    }

    /// see [core_crypto::Session::reseed]
    pub async fn reseed(&self, seed: Vec<u8>) -> CoreCryptoResult<()> {
        let seed = core_crypto::EntropySeed::try_from_slice(&seed).map_err(CoreCryptoError::generic())?;
        self.inner.reseed(Some(seed)).await?;

        Ok(())
    }
}
