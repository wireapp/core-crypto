pub use async_trait;
pub use clap;
pub use color_eyre::Result;
pub use tokio;

pub const TEST_ENCRYPTION_KEY: &str = "test1234";

#[async_trait::async_trait(?Send)]
pub trait CoreCryptoKeystore {
    async fn open(path: &str, key: &str) -> Result<Self>
    where
        Self: Sized;
    async fn close(self) -> Result<()>;
    async fn wipe(self) -> Result<()>;
}

#[derive(Debug, clap::Parser)]
#[clap(author, version, about, long_about = None)]
pub struct CliArgs<T: CoreCryptoKeystore> {
    pub store_path: String,
    #[clap(skip)]
    _marker: std::marker::PhantomData<T>,
}

impl<T: CoreCryptoKeystore> CliArgs<T> {
    pub async fn run(&self) -> Result<()> {
        let instance = T::open(&self.store_path, TEST_ENCRYPTION_KEY).await?;
        instance.close().await?;
        Ok(())
    }

    pub async fn rm(self) -> Result<()> {
        tokio::fs::remove_file(&self.store_path).await?;
        Ok(())
    }
}
