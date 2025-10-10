use openmls_traits::OpenMlsCryptoProvider as _;

use super::{Error, Result};
use crate::{CredentialFindFilters, CredentialRef, MlsConversation, RecursiveError, Session};

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
    pub async fn add_credential(&self, credential_ref: &CredentialRef) -> Result<()> {
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

    /// Remove a credential from the identities of this session.
    ///
    /// First checks that the credential is not used in any conversation.
    /// Removes both the credential itself and also any key packages which were generated from it.
    pub async fn remove_credential(&self, credential_ref: &CredentialRef) -> Result<()> {
        // setup
        if *credential_ref.client_id() != self.id().await? {
            return Err(Error::WrongCredential);
        }

        let database = self.crypto_provider.keystore();

        let credentials = credential_ref
            .load(&database)
            .await
            .map_err(RecursiveError::mls_credential_ref(
                "loading all credentials from ref to remove from session identities",
            ))?;

        // in a perfect world, we'd pre-cache the mls credentials in a set structure of some sort for faster querying.
        // unfortunately, `MlsCredential` is `!Hash` and `!Ord`, so both the standard sets are out.
        // so whatever, linear scan over the credentials every time will have to do.

        // ensure this credential is not in use by any conversation
        for (conversation_id, conversation) in
            MlsConversation::load_all(&database)
                .await
                .map_err(RecursiveError::mls_conversation(
                    "loading all conversations to check if the credential to be removed is present",
                ))?
        {
            let converation_credential = conversation
                .own_mls_credential()
                .map_err(RecursiveError::mls_conversation("geting conversation credential"))?;
            if credentials
                .iter()
                .any(|credential| credential.mls_credential() == converation_credential)
            {
                return Err(Error::CredentialStillInUse(conversation_id));
            }
        }

        // remove any key packages generated by this credential
        let keypackages = self.find_all_keypackages(&self.crypto_provider.keystore()).await?;
        let keypackages_from_this_credential = keypackages.iter().filter_map(|(_stored_key_package, key_package)| {
            credentials
                    .iter()
                    .any(|credential| key_package.leaf_node().credential() == credential.mls_credential())
                    // if computing the hash reference fails, we will just not delete the key package
                    .then(|| key_package.hash_ref(self.crypto_provider.crypto()).ok()).flatten()
        });
        self.prune_keypackages(&self.crypto_provider, keypackages_from_this_credential)
            .await?;

        // remove all credentials associated with this ref
        // do this last so we only remove the actual credential after the keypackages are all gone,
        // and keep the lock open as briefly as possible
        let mut inner = self.inner.write().await;
        let inner = inner.as_mut().ok_or(Error::MlsNotInitialized)?;
        for credential in credentials {
            inner
                .identities
                .remove(credential.mls_credential())
                .await
                .map_err(RecursiveError::mls_client("removing credential"))?;
        }

        Ok(())
    }
}
