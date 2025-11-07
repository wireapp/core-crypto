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
use openmls::prelude::Credential as MlsCredential;
use tls_codec::Deserialize as _;

use super::{Error, Result};
use crate::{Ciphersuite, Credential, CredentialRef, KeystoreError, RecursiveError};

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

    /// Load all credentials which match this ref from the database.
    ///
    /// Note that this does not attach the credential to any Session; it just does the data manipulation.
    ///
    /// The database schema currently permits multiple credentials to exist simultaneously which match a given credential ref.
    /// Therefore, this function returns all of them, ordered by `earliest_validity`.
    ///
    /// Due to database limitations we currently cannot efficiently retrieve only those keypairs of interest;
    /// if you are going to be loading several references in a row, it is more efficient to first fetch all
    /// stored keypairs with [`Self::load_cache`] and then call [`Self::load_with_cache`].
    ///
    ///  We'd very much like it if in the future we could do filtering at the database level,
    /// obviating the requirement for this cache structure. See WPB-20839, WPB-20844 and WPB-21819.
    pub(crate) async fn load(&self, database: &Database) -> Result<Vec<Credential>> {
        let credentials = database
            .find_all::<StoredCredential>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all mls credentials"))?;
        let credentials = self.load_from_cache(&credentials)?.collect::<Result<Vec<_>>>()?;
        Ok(credentials)
    }

    /// Filter and map the provided stored credentials (_cache_). This results in [Credential]s which match
    /// this [CredentialRef]'s conditions.
    ///
    /// If you are only loading a single credential ref, it may be simpler to call [`Self::load`].
    pub(crate) fn load_from_cache(
        &self,
        cache: &[StoredCredential],
    ) -> Result<impl Iterator<Item = Result<Credential>>> {
        let iter = cache
            .iter()
            // these are the only checks we can currently do at the DB level: match the client id, creation timestamp,
            // public key and signature scheme
            .filter(|stored_credential|
                        stored_credential.id == self.client_id().as_slice()
                        && stored_credential.created_at == self.earliest_validity
                        && stored_credential.public_key == self.public_key
                        && stored_credential.ciphersuite == u16::from(self.ciphersuite)
            )
            // from here we can at least deserialize the credential
            .map(move |stored_credential| {
                let mls_credential = MlsCredential::tls_deserialize(&mut stored_credential.credential.as_slice())
                    .map_err(Error::tls_deserialize("mls credential"))?;
                let ciphersuite = Ciphersuite::try_from(stored_credential.ciphersuite).map_err(RecursiveError::mls("loading ciphersuite from db"))?;
                let signature_key_pair = openmls_basic_credential::SignatureKeyPair::from_raw(ciphersuite.signature_algorithm(), stored_credential.secret_key.to_owned(), stored_credential.public_key.to_owned());
                let credential_type = mls_credential.credential_type().try_into().map_err(RecursiveError::mls_credential("loading credential from db"))?;
                let earliest_validity = stored_credential.created_at;
                Ok(Credential {
                    ciphersuite,
                    signature_key_pair,
                    credential_type,
                    mls_credential,
                    earliest_validity,
                })
            })
            // after deserialization, we can filter out any results which do not match the conditions in the credential ref
            // but pass through any errors
            .filter(|credential_result| {
                credential_result.as_ref().ok().is_none_or(|credential| {
                            self.r#type == credential.mls_credential.credential_type()
                })
            })
            // we also need to ensure that the credential validates
            .map(|credential_result| {
                credential_result.and_then(|credential| {
                    Credential::validate_mls_credential(
                        &credential.mls_credential,
                        self.client_id(),
                        &credential.signature_key_pair,
                    )?;
                    Ok(credential)
                })
            });

        Ok(iter)
    }
}
