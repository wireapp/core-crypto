use core_crypto_keystore::{Sha256Hash, entities::StoredCredential, traits::FetchFromDatabase as _};
use openmls::prelude::SignaturePublicKey;
use tls_codec::Serialize as _;

use super::{Error, Result};
use crate::{Credential, CredentialRef, KeystoreError, mls_provider::Database};

impl Credential {
    /// Loads a credential with the given public key from the database.
    ///
    /// Should not be passed over the ffi boundary.
    pub(crate) async fn find_by_public_key(database: &Database, public_key: &SignaturePublicKey) -> Result<Self> {
        let stored_credential = &database
            .get::<StoredCredential>(&Sha256Hash::hash_from(public_key.as_slice()))
            .await
            .map_err(KeystoreError::wrap("getting credential by public key"))?
            .ok_or_else(|| Error::CredentialNotFound(public_key.clone()))?;
        stored_credential.try_into()
    }

    /// Persist this credential into the database.
    ///
    /// Returns a reference which is stable over time and across the FFI boundary.
    ///
    /// Normally this is called internally by [`Session::add_credential`][crate::Session::add_credential];
    /// use caution if calling it from elsewhere.
    pub(crate) async fn save(&mut self, database: &Database) -> Result<CredentialRef> {
        let credential_data = self
            .mls_credential
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("credential"))?;

        self.earliest_validity = database
            .save(StoredCredential {
                session_id: self.client_id().to_owned().into_inner(),
                credential: credential_data,
                created_at: Default::default(), // updated by the `.save` impl
                ciphersuite: u16::from(self.ciphersuite),
                private_key: self.signature_key_pair.private().to_owned(),
                public_key: self.signature_key().public().to_owned(),
            })
            .await
            .map_err(KeystoreError::wrap("saving credential"))?;

        Ok(CredentialRef::from_credential(self))
    }

    /// Delete this credential from the database
    pub(crate) async fn delete(self, database: &Database) -> Result<()> {
        database
            .remove::<StoredCredential>(&Sha256Hash::hash_from(self.signature_key_pair.public()))
            .await
            .map_err(KeystoreError::wrap("deleting credential"))?;

        Ok(())
    }
}
