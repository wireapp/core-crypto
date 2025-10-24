use std::sync::Arc;

use openmls::prelude::{CredentialType, SignaturePublicKey, SignatureScheme};
use openmls_traits::OpenMlsCryptoProvider as _;

use super::{Error, Result};
use crate::{
    Credential, CredentialFindFilters, CredentialRef, LeafError, MlsConversation, RecursiveError, Session,
    mls::session::SessionInner,
};

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
    /// Note that this accepts a [`CredentialRef`], _not_ a raw [`Credential`].
    /// This is because a `CredentialRef` serves as proof of persistence. Only credentials
    /// which have been persisted are eligible to be included in a session.
    ///
    /// Returns the actual credential instance which was loaded from the DB.
    /// This is a convenience for internal use and should _not_ be propagated across
    /// the FFI boundary.
    pub async fn add_credential(&self, credential_ref: &CredentialRef) -> Result<Arc<Credential>> {
        if *credential_ref.client_id() != self.id().await? {
            return Err(Error::WrongCredential);
        }

        self.add_credential_without_clientid_check(credential_ref).await
    }

    /// Add a credential to the identities of this session without validating that its client ID matches the session client id.
    ///
    /// This is rarely useful and should only be used when absolutely necessary. You'll know it if you need it.
    ///
    /// Prefer [`Self::add_credential`].
    pub(crate) async fn add_credential_without_clientid_check(
        &self,
        credential_ref: &CredentialRef,
    ) -> Result<Arc<Credential>> {
        let guard = self.inner.upgradable_read().await;
        let inner = guard.as_ref().ok_or(Error::MlsNotInitialized)?;

        // failfast before loading the cache if we know already that this credential ref can't be added to the identity set
        inner.identities.ensure_distinct(
            credential_ref.signature_scheme(),
            credential_ref.r#type(),
            credential_ref.earliest_validity(),
        )?;

        let cache = CredentialRef::load_cache(&self.crypto_provider.keystore())
            .await
            .map_err(RecursiveError::mls_credential_ref("loading credential cache"))?;

        // only upgrade to a write guard here in order to minimize the amount of time the unique lock is held
        let mut guard = async_lock::RwLockUpgradableReadGuard::upgrade(guard).await;
        let inner = guard.as_mut().ok_or(Error::MlsNotInitialized)?;

        // The primary key situation of `Credential` is a bad joke.
        // We have no idea how many credentials might be attached to a particular ref, or even
        // how they may be related.
        //
        // Happily, our identities structure has set semantics, so let's lean (heavily) on that.

        // the credential being added here might not be the most recent, so we need to manually
        // keep track of the first one that we insert in response to this add operation
        let mut first_inserted_credential = None;

        for credential_result in
            credential_ref
                .load_with_cache(&cache)
                .await
                .map_err(RecursiveError::mls_credential_ref(
                    "loading all matching credentials in `add_credential`",
                ))?
        {
            let credential = credential_result.map_err(RecursiveError::mls_credential_ref(
                "failed to load credential in `add_credential`",
            ))?;
            let credential = inner.identities.push_credential(credential).await?;
            if first_inserted_credential.is_none() {
                first_inserted_credential = Some(credential);
            }
        }

        // maybe the credentialref was invalid or something
        first_inserted_credential.ok_or(Error::CredentialNotFound(credential_ref.r#type()))
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
            inner.identities.remove(credential.mls_credential());
        }

        Ok(())
    }

    /// convenience function deferring to the implementation on the inner type
    pub(crate) async fn find_most_recent_credential(
        &self,
        signature_scheme: SignatureScheme,
        credential_type: CredentialType,
    ) -> Result<Arc<Credential>> {
        match &*self.inner.read().await {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner { identities, .. }) => identities
                .find_most_recent_credential(signature_scheme, credential_type)
                .await
                .ok_or(Error::CredentialNotFound(credential_type)),
        }
    }

    /// convenience function deferring to the implementation on the inner type
    pub(crate) async fn find_credential_by_public_key(
        &self,
        sc: SignatureScheme,
        ct: CredentialType,
        pk: &SignaturePublicKey,
    ) -> Result<Arc<Credential>> {
        match &*self.inner.read().await {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner { identities, .. }) => identities
                .find_credential_by_public_key(sc, ct, pk)
                .await
                .ok_or(Error::CredentialNotFound(ct)),
        }
    }

    /// Convenience function to save a credential and add it to the session's identities
    ///
    /// If you want to keep access to your original credential, do this manually. This function
    /// intentionally takes ownership as a reminder that we're moving the credential into the identities.
    ///
    /// Returns a smart pointer to where the credential is stored within its ultimate data structure.
    pub(crate) async fn save_and_add_credential(&self, mut credential: Credential) -> Result<Arc<Credential>> {
        let credential_ref = credential
            .save(&self.crypto_provider.keystore())
            .await
            .map_err(RecursiveError::mls_credential("saving new x509 credential"))?;
        self.add_credential(&credential_ref).await
    }

    /// Convenience function to get the most recent credential, creating it if the credential type is basic.
    ///
    /// If the credential type is X509, a missing credential returns `LeafError::E2eiEnrollmentNotDone`
    pub(crate) async fn find_most_recent_or_create_basic_credential(
        &self,
        signature_scheme: SignatureScheme,
        credential_type: CredentialType,
    ) -> Result<Arc<Credential>> {
        let credential = match self
            .find_most_recent_credential(signature_scheme, credential_type)
            .await
        {
            Ok(credential) => credential,
            Err(Error::CredentialNotFound(_)) if credential_type == CredentialType::Basic => {
                let client_id = self.id().await?;
                let credential = Credential::basic(signature_scheme, client_id, &self.crypto_provider).map_err(
                    RecursiveError::mls_credential(
                        "creating basic credential in find_most_recent_or_create_basic_credential",
                    ),
                )?;
                self.save_and_add_credential(credential).await?
            }
            Err(Error::CredentialNotFound(_)) if credential_type == CredentialType::X509 => {
                return Err(LeafError::E2eiEnrollmentNotDone.into());
            }
            Err(err) => return Err(err),
        };
        Ok(credential)
    }
}
