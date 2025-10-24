use core_crypto_keystore::entities::StoredCredential;
use mls_crypto_provider::Database;
use tls_codec::Serialize as _;

use super::{Error, Result};
use crate::{Credential, CredentialRef, KeystoreError, mls::credential::keypairs};

impl Credential {
    /// Update all the fields that were updated by the DB during the save.
    ///
    /// [`<StoredCredential as EntityTransactionExt>::pre_save`][core_crypto_keystore::entities::EntityTransactionExt::pre_save].
    fn update_from(&mut self, stored: StoredCredential) {
        self.earliest_validity = stored.created_at;
    }

    /// Persist this credential into the database.
    ///
    /// Returns a reference which is stable over time and across the FFI boundary.
    pub async fn save(&mut self, database: &Database) -> Result<CredentialRef> {
        keypairs::store(database, self.client_id(), &self.signature_key_pair).await?;

        let credential_data = self
            .mls_credential
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("credential"))?;

        let stored_credential = database
            .save(StoredCredential {
                id: self.client_id().to_owned().into_inner(),
                credential: credential_data,
                created_at: Default::default(), // updated by the `.save` impl
            })
            .await
            .map_err(KeystoreError::wrap("saving credential"))?;

        self.update_from(stored_credential);

        Ok(CredentialRef::new(
            self.client_id().to_owned(),
            self.signature_key_pair.public().to_owned(),
            self.mls_credential.credential_type(),
            self.signature_key_pair.signature_scheme(),
            self.earliest_validity,
        ))
    }
}
