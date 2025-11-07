use std::sync::Arc;

use openmls::prelude::{SignaturePublicKey, SignatureScheme};
use openmls_traits::OpenMlsCryptoProvider as _;

use super::{Error, Result};
use crate::{
    Ciphersuite, Credential, CredentialFindFilters, CredentialRef, CredentialType, LeafError, MlsConversation,
    RecursiveError, Session, mls::session::SessionInner,
};

impl Session {
    /// Find all credentials known by this session which match the specified conditions.
    ///
    /// If no filters are set, this is equivalent to [`Self::get_credentials`].
    pub async fn find_credentials(&self, find_filters: CredentialFindFilters<'_>) -> Result<Vec<CredentialRef>> {
        let guard = self.inner.read().await;
        let inner = guard.as_ref().ok_or(Error::MlsNotInitialized)?;
        Ok(inner
            .identities
            .find_credential(find_filters)
            .map(|credential| CredentialRef::from_credential(&credential))
            .collect())
    }

    /// Get all credentials known by this session.
    pub async fn get_credentials(&self) -> Result<Vec<CredentialRef>> {
        self.find_credentials(Default::default()).await
    }

    /// Add a credential to the identities of this session.
    ///
    /// As a side effect, stores the credential in the keystore.
    pub(crate) async fn add_credential(&self, credential: Credential) -> Result<CredentialRef> {
        let credential = self.add_credential_producing_arc(credential).await?;
        Ok(CredentialRef::from_credential(&credential))
    }

    /// Add a credential to the identities of this session.
    ///
    /// As a side effect, stores the credential in the keystore.
    ///
    /// Returns the actual credential instance which was loaded from the DB.
    /// This is a convenience for internal use and should _not_ be propagated across
    /// the FFI boundary. Instead, use [`Self::add_credential`] to produce a [`CredentialRef`].
    pub(crate) async fn add_credential_producing_arc(&self, credential: Credential) -> Result<Arc<Credential>> {
        if *credential.client_id() != self.id().await? {
            return Err(Error::WrongCredential);
        }

        self.add_credential_without_clientid_check(credential).await
    }

    /// Add a credential to the identities of this session without validating that its client ID matches the session client id.
    ///
    /// This is rarely useful and should only be used when absolutely necessary. You'll know it if you need it.
    ///
    /// Prefer [`Self::add_credential`].
    pub(crate) async fn add_credential_without_clientid_check(
        &self,
        mut credential: Credential,
    ) -> Result<Arc<Credential>> {
        let credential_ref = credential
            .save(&self.crypto_provider.keystore())
            .await
            .map_err(RecursiveError::mls_credential("saving credential"))?;

        let guard = self.inner.upgradable_read().await;
        let inner = guard.as_ref().ok_or(Error::MlsNotInitialized)?;

        // failfast before loading the cache if we know already that this credential ref can't be added to the identity set
        let distinct_result = inner.identities.ensure_distinct(
            credential_ref.signature_scheme(),
            credential_ref.r#type(),
            credential_ref.earliest_validity(),
        );
        if let Err(err) = distinct_result {
            // first clean up by removing the credential we just saved
            // otherwise, we'll have nondeterministic results when we load
            //
            // TODO this depends for correctness that no two added credentials have the same keypair;
            // if this happens for a keypair which was removed, we'll remove the (old, used) keypair
            // and forever after be unable to mls_init on that DB due to a missing keypair for the given credential
            // this is pointlessly difficult to check right now, but we should do a uniqueness check
            // after WPB-20844
            credential
                .delete(&self.crypto_provider.keystore())
                .await
                .map_err(RecursiveError::mls_credential(
                    "deleting nondistinct credential from keystore",
                ))?;
            return Err(err);
        }

        // only upgrade to a write guard here in order to minimize the amount of time the unique lock is held
        let mut guard = async_lock::RwLockUpgradableReadGuard::upgrade(guard).await;
        let inner = guard.as_mut().ok_or(Error::MlsNotInitialized)?;
        let credential = inner.identities.push_credential(credential).await?;

        Ok(credential)
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
        // only remove the actual credential after the keypackages are all gone,
        // and keep the lock open as briefly as possible
        {
            let mut inner = self.inner.write().await;
            let inner = inner.as_mut().ok_or(Error::MlsNotInitialized)?;
            for credential in &credentials {
                inner.identities.remove_by_mls_credential(credential.mls_credential());
            }
        }

        // finally remove the credentials from the keystore so they won't be loaded on next mls_init
        for credential in credentials {
            credential
                .delete(&database)
                .await
                .map_err(RecursiveError::mls_credential("deleting credential from keystore"))?;
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
                .ok_or(Error::CredentialNotFound(credential_type, signature_scheme)),
        }
    }

    /// convenience function deferring to the implementation on the inner type
    pub(crate) async fn find_credential_by_public_key(
        &self,
        signature_scheme: SignatureScheme,
        credential_type: CredentialType,
        public_key: &SignaturePublicKey,
    ) -> Result<Arc<Credential>> {
        match &*self.inner.read().await {
            None => Err(Error::MlsNotInitialized),
            Some(SessionInner { identities, .. }) => identities
                .find_credential_by_public_key(signature_scheme, credential_type, public_key)
                .await
                .ok_or(Error::CredentialNotFound(credential_type, signature_scheme)),
        }
    }

    /// Convenience function to get the most recent credential, creating it if the credential type is basic.
    ///
    /// If the credential type is X509, a missing credential returns `LeafError::E2eiEnrollmentNotDone`
    pub(crate) async fn find_most_recent_or_create_basic_credential(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> Result<Arc<Credential>> {
        let credential = match self
            .find_most_recent_credential(ciphersuite.signature_algorithm(), credential_type)
            .await
        {
            Ok(credential) => credential,
            Err(Error::CredentialNotFound(..)) if credential_type == CredentialType::Basic => {
                let client_id = self.id().await?;
                let credential = Credential::basic(ciphersuite, client_id, &self.crypto_provider).map_err(
                    RecursiveError::mls_credential(
                        "creating basic credential in find_most_recent_or_create_basic_credential",
                    ),
                )?;
                self.add_credential_producing_arc(credential).await?
            }
            Err(Error::CredentialNotFound(..)) if credential_type == CredentialType::X509 => {
                return Err(LeafError::E2eiEnrollmentNotDone.into());
            }
            Err(err) => return Err(err),
        };
        Ok(credential)
    }
}
