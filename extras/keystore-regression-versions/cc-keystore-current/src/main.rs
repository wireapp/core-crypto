use cc_keystore_support::*;
use core_crypto_keystore::Connection;
pub struct CoreCryptoKeystoreCurrent(Connection);

#[async_trait::async_trait(?Send)]
impl CoreCryptoKeystore for CoreCryptoKeystoreCurrent {
    async fn open(path: &str, key: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self(Connection::open_with_key(path, key).await?))
    }
    async fn close(self) -> Result<()> {
        self.0.close().await?;
        Ok(())
    }
    async fn wipe(self) -> Result<()> {
        self.0.wipe().await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    use clap::Parser as _;
    let args = CliArgs::<CoreCryptoKeystoreCurrent>::parse();
    args.run().await?;
    Ok(())
}
