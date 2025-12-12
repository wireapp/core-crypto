//! Persistence for [`CredentialRef`], i.e. loading actual credentials from the keystore given a ref.
//!
//! It is not logically required that these methods are crate-private, but they aren't likely to be
//! useful to end users. Clients building on the CC API can't do anything useful with a full [`Credential`],
//! and it's wasteful to transfer one across the FFI boundary.

use core_crypto_keystore::{
    connection::FetchFromDatabase as _,
    entities::{EntityFindParams, StoredCredential},
};
use mls_crypto_provider::Database;

use super::{Error, Result};
use crate::{Credential, CredentialRef, KeystoreError, RecursiveError};

impl CredentialRef {
    /// Helper to prefetch relevant keypairs when loading multiple credentials at a time.
    ///
    /// Only useful when preparing to call [`Self::load_from_cache`] multiple times.
    /// For loading a single credential, prefer [`Self::load`].
    pub(crate) async fn load_stored_credentials(database: &Database) -> Result<Vec<StoredCredential>> {
        let credentials = database
            .find_all::<StoredCredential>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls credentials"))?;
        Ok(credentials)
    }

    /// Load the credential which matches this ref from the database.
    ///
    /// Note that this does not attach the credential to any Session; it just does the data manipulation.
    pub(crate) async fn load(&self, database: &Database) -> Result<Credential> {
        database
            .find::<StoredCredential>(self.public_key())
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

    /// Filter and map the provided stored credentials (_cache_). This results in [Credential]s which match
    /// this [CredentialRef]'s conditions.
    ///
    /// If you are only loading a single credential ref, it may be simpler to call [`Self::load`].
    pub(crate) fn load_from_cache(&self, cache: &[StoredCredential]) -> Result<Option<Credential>> {
        cache
            .iter()
            .filter(|stored_credential| stored_credential.public_key == self.public_key)
            .map(|stored_credential| {
                Credential::try_from(stored_credential)
                    .map_err(RecursiveError::mls_credential(
                        "creating credential from stored credential",
                    ))
                    .map_err(Into::into)
            })
            .map(|credential_result| {
                credential_result.and_then(|credential| {
                    Credential::validate_mls_credential(
                        &credential.mls_credential,
                        self.client_id(),
                        &credential.signature_key_pair,
                    )?;
                    Ok(credential)
                })
            })
            .next()
            .transpose()
    }
}
