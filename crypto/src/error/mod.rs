// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

mod cryptobox_migration;
mod keystore;
mod leaf;
mod legacy;
mod mls;
mod proteus;
mod recursive;
mod wrapper;

pub use cryptobox_migration::{CryptoboxMigrationError, CryptoboxMigrationErrorKind};
pub use keystore::KeystoreError;
pub use leaf::LeafError;
pub use mls::{MlsError, MlsErrorKind};
pub use proteus::{ProteusError, ProteusErrorKind};
pub use recursive::RecursiveError;
pub(crate) use wrapper::WrappedContextualError;

/// A module-specific [Result][core::result::Result] type with a default error variant.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Errors produced by the root module group
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid Context. This context has been finished and can no longer be used.
    #[error("This context has already been finished and can no longer be used.")]
    InvalidContext,
    /// The proteus client has been called but has not been initialized yet
    #[error("Proteus client hasn't been initialized")]
    ProteusNotInitialized,
    /// A key store operation failed
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    /// An external MLS operation failed
    #[error(transparent)]
    Mls(#[from] MlsError),
    /// A Proteus operation failed
    #[error(transparent)]
    Proteus(#[from] ProteusError),
    /// A cryptobox migration operation failed
    #[error(transparent)]
    CryptoboxMigration(#[from] CryptoboxMigrationError),
    /// A crate-internal operation failed
    #[error(transparent)]
    Recursive(#[from] RecursiveError),
}
