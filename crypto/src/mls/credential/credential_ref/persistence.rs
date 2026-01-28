//! Persistence for [`CredentialRef`], i.e. loading actual credentials from the keystore given a ref.
//!
//! It is not logically required that these methods are crate-private, but they aren't likely to be
//! useful to end users. Clients building on the CC API can't do anything useful with a full [`Credential`],
//! and it's wasteful to transfer one across the FFI boundary.

use core_crypto_keystore::{Sha256Hash, entities::StoredCredential, traits::FetchFromDatabase};

use super::{Error, Result};
use crate::{Credential, CredentialRef, KeystoreError, RecursiveError};

impl CredentialRef {
    /// Load the credential which matches this ref from the database.
    ///
    /// Note that this does not attach the credential to any Session; it just does the data manipulation.
    pub(crate) async fn load(&self, database: &impl FetchFromDatabase) -> Result<Credential> {
        database
            .get::<StoredCredential>(&Sha256Hash::hash_from(self.public_key()))
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
}
