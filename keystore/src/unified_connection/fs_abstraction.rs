/// Abstraction over a possibly-virtual filesystem
use async_trait::async_trait;

use crate::CryptoKeystoreResult;

#[cfg_attr(not(target_os = "unknown"), async_trait)]
#[cfg_attr(target_os = "unknown", async_trait(?Send))]
pub(crate) trait FilesystemAbstraction: std::fmt::Debug {
    /// Remove the file at the specified location.
    async fn delete(&self, path: &str) -> CryptoKeystoreResult<()>;
}

/// Async operations on the native filesystem
#[cfg(not(target_os = "unknown"))]
#[derive(Debug)]
pub(super) struct NativeFs;

#[cfg(not(target_os = "unknown"))]
#[async_trait]
impl FilesystemAbstraction for NativeFs {
    async fn delete(&self, path: &str) -> CryptoKeystoreResult<()> {
        async_fs::remove_file(path).await.map_err(Into::into)
    }
}

/// An implementation of a "filesystem" which operates on an in-memory database:
/// in other words, one which does nothing.
#[derive(Debug)]
pub(super) struct Nop;

#[cfg_attr(not(target_os = "unknown"), async_trait)]
#[cfg_attr(target_os = "unknown", async_trait(?Send))]
impl FilesystemAbstraction for Nop {
    async fn delete(&self, _path: &str) -> CryptoKeystoreResult<()> {
        Ok(())
    }
}
