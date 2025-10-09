use super::{Error, Result};
use crate::{CredentialFindFilters, CredentialRef, RecursiveError, Session};

impl Session {
    /// Find all credentials which match the specified conditions.
    ///
    /// If no filters are set, this is equivalent to [`get_credentials`][Self::get_credentials].
    ///
    /// This is a convenience method entirely equivalent to [CredentialRef::find];
    /// the only difference is that it automatically includes the appropriate
    /// [`Database`][core_crypto_keystore::Database] reference.
    pub async fn find_credentials(&self, find_filters: CredentialFindFilters<'_>) -> Result<Vec<CredentialRef>> {
        let database = self.crypto_provider.keystore();
        CredentialRef::find(&database, find_filters)
            .await
            .map_err(RecursiveError::mls_credential_ref("finding credentials"))
            .map_err(Into::into)
    }

    /// Get all credentials
    ///
    /// This is a convenience method entirely equivalent to [CredentialRef::get_all];
    /// the only difference is that it automatically includes the appropriate
    /// [`Database`][core_crypto_keystore::Database] reference.
    pub async fn get_credentials(&self) -> Result<Vec<CredentialRef>> {
        let database = self.crypto_provider.keystore();
        CredentialRef::get_all(&database)
            .await
            .map_err(RecursiveError::mls_credential_ref("getting all credentials"))
            .map_err(Into::into)
    }

    /// Add a credential to the identities of this session.
    ///
    /// Note that this accepts a [`CredentialRef`], _not_ a raw [`Credential`][crate::Credential].
    /// This is because a `CredentialRef` serves as proof of persistence. Only credentials
    /// which have been persisted are eligible to be included in a session.
    pub async fn add_credential(&self, credential_ref: CredentialRef) -> Result<()> {
        if *credential_ref.client_id() != self.id().await? {
            return Err(Error::WrongCredential);
        }

        // The primary key situation of `Credential` is a bad joke.
        // We have no idea how many credentials might be attached to a particular ref, or even
        // how they may be related.
        //
        // Happily, our identities structure has set semantics, so let's lean (heavily) on that.

        // `.load` allocates, but also sorts by `earliest_validity`, which we want
        let credentials =
            credential_ref
                .load(&self.crypto_provider.keystore())
                .await
                .map_err(RecursiveError::mls_credential_ref(
                    "loading all matching credentials in `add_credential`",
                ))?;

        let mut inner = self.inner.write().await;
        let inner = inner.as_mut().ok_or(Error::MlsNotInitialized)?;

        for credential in credentials {
            inner
                .identities
                .push_credential(credential.signature_key_pair.signature_scheme(), credential)
                .await?;
        }

        Ok(())
    }
}
