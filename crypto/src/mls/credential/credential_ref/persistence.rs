//! Persistence for [`CredentialRef`], i.e. loading actual credentials from the keystore given a ref.
//!
//! It is not logically required that these methods are crate-private, but they aren't likely to be
//! useful to end users. Clients building on the CC API can't do anything useful with a full [`Credential`],
//! and it's wasteful to transfer one across the FFI boundary.

use core_crypto_keystore::{entities::StoredCredential, traits::FetchFromDatabase};

use super::{Error, Result};
use crate::{Credential, CredentialRef, KeystoreError, RecursiveError};

impl CredentialRef {
    /// Load the credential which matches this ref from the database.
    ///
    /// Note that this does not attach the credential to any Session; it just does the data manipulation.
    pub async fn load(&self, database: &impl FetchFromDatabase) -> Result<Credential> {
        database
            .get::<StoredCredential>(&self.public_key_hash())
            .await
            .map_err(KeystoreError::wrap("finding credential"))?
            .ok_or(Error::CredentialNotFound)
            .and_then(|stored_credential| {
                Credential::try_from(&stored_credential)
                    .map_err(RecursiveError::mls_credential(
                        "creating credential from stored credential",
                    ))
                    .map_err(Into::into)
            })
    }

    /// Load the public key for the credential matching this ref from the database.
    ///
    /// It might seem surprising that the public key isn't stored in the [`Credential`] type;
    /// you can't get it simpliy by calling [`Self::load`]. The reason for this is that keys
    /// can be quite large, especially in a post-quantum world, and most of the time, we do not
    /// actually need the public key. We therefore offer this method to load it dynamically.
    pub async fn public_key(&self, database: &impl FetchFromDatabase) -> Result<Vec<u8>> {
        database
            .get::<StoredCredential>(&self.public_key_hash())
            .await
            .map_err(KeystoreError::wrap("finding credential"))?
            .ok_or(Error::CredentialNotFound)
            .map_err(RecursiveError::mls_credential_ref("retrieving public key"))
            .map(|mut stored_credential| std::mem::take(&mut stored_credential.public_key))
            .map_err(Into::into)
    }
}
