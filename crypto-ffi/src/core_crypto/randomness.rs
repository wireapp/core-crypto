use crate::{CoreCryptoError, CoreCryptoFfi, CoreCryptoResult};

#[uniffi::export]
impl CoreCryptoFfi {
    /// Generate `len` random bytes from the MLS session's cryptographically secure RNG.
    pub async fn random_bytes(&self, len: u32) -> CoreCryptoResult<Vec<u8>> {
        let len = len.try_into().map_err(CoreCryptoError::generic())?;
        self.inner.mls_session().await?.random_bytes(len).map_err(Into::into)
    }

    /// Re-seed the MLS session's CSPRNG with the provided entropy seed.
    pub async fn reseed(&self, seed: Vec<u8>) -> CoreCryptoResult<()> {
        let seed = core_crypto::EntropySeed::try_from_slice(&seed).map_err(CoreCryptoError::generic())?;
        self.inner.mls_session().await?.reseed(Some(seed)).await?;

        Ok(())
    }
}
