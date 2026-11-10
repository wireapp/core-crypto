mod check;

use std::sync::Arc;

use super::{Error, Result};
use crate::{Credential, CredentialRef, RecursiveError, transaction_context::TransactionContext};

impl TransactionContext {
    /// Add a credential to the database of this session without validating that its client ID matches the session
    /// client id.
    ///
    /// This is rarely useful and should only be used when absolutely necessary. You'll know it if you need it.
    ///
    /// Prefer [`Self::add_credential`].
    pub(crate) fn add_credential_without_clientid_check(&self, mut credential: Credential) -> Result<Arc<Credential>> {
        let inner = self.inner()?;
        let _credential_ref = credential
            .save(&inner.transaction)
            .map_err(RecursiveError::context("saving credential"))?;

        Ok(Arc::new(credential))
    }
    /// Add a credential to the database of this session.
    pub async fn add_credential(&self, credential: Credential) -> Result<CredentialRef> {
        let credential = self.add_credential_producing_arc(credential).await?;
        Ok(CredentialRef::from_credential(&credential))
    }

    /// Add a credential to the database of this session.
    ///
    /// Returns the actual credential instance which was loaded from the DB.
    /// This is a convenience for internal use and should _not_ be propagated across
    /// the FFI boundary. Instead, use [`Self::add_credential`] to produce a [`CredentialRef`].
    pub(crate) async fn add_credential_producing_arc(&self, credential: Credential) -> Result<Arc<Credential>> {
        if *credential.client_id() != self.session().await?.id() {
            return Err(Error::WrongCredential);
        }

        self.add_credential_without_clientid_check(credential)
    }

    /// Remove a credential from the database of this session.
    ///
    /// First checks that the credential is not used in any conversation.
    /// Removes both the credential itself and also any key packages which were generated from it.
    pub async fn remove_credential(&self, credential_ref: &CredentialRef) -> Result<bool> {
        // setup
        if *credential_ref.client_id() != self.session().await?.id() {
            return Err(Error::WrongCredential);
        }

        let inner = self.inner()?;

        let removed = credential_ref.delete(&inner.transaction).map_err(|err| -> Error {
            let crate::KeystoreError { source, .. } = &err;
            let Some(core_crypto_keystore::CryptoKeystoreError::DbError(rusqlite_err)) = source.downcast_ref() else {
                return err.into();
            };
            if rusqlite_err
                .sqlite_error_code()
                .is_some_and(|code| code == core_crypto_keystore::RusqliteErrorCode::ConstraintViolation)
            {
                Error::CredentialStillInUse
            } else {
                err.into()
            }
        })?;

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{
        entities::{StoredCredential, StoredKeyPackage},
        traits::FetchFromDatabase as _,
    };

    use super::*;
    use crate::{CertificateBundle, test_utils::*};

    async fn credential_is_stored(session: &SessionContext, credential: &CredentialRef) -> bool {
        session
            .transaction
            .database()
            .unwrap()
            .get::<StoredCredential>(&credential.keystore_pk())
            .await
            .unwrap()
            .is_some()
    }

    /// How many stored key packages were generated from `credential`.
    async fn count_key_packages_for(session: &SessionContext, credential: &CredentialRef) -> usize {
        session
            .transaction
            .database()
            .unwrap()
            .search::<StoredKeyPackage, _>(&credential.keystore_pk())
            .await
            .unwrap()
            .len()
    }

    /// A credential a conversation still uses cannot be removed, and the refused removal writes nothing: neither the
    /// credential nor the key packages generated from it go missing. Once the conversation moves on to another
    /// credential, the old one can be removed.
    #[apply(all_cred_cipher)]
    async fn credential_in_use_by_a_conversation_cannot_be_removed(case: TestContext) {
        const KEY_PACKAGES: usize = 2;

        let [alice] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let credential = alice.initial_credential.clone();

        for _ in 0..KEY_PACKAGES {
            alice.new_keypackage_from_ref(credential.clone(), None).await;
        }
        assert_eq!(count_key_packages_for(&alice, &credential).await, KEY_PACKAGES);

        let result = alice.transaction.remove_credential(&credential).await;
        assert!(
            matches!(result, Err(Error::CredentialStillInUse)),
            "removing a credential in use must fail with `CredentialStillInUse`, but got {result:?}"
        );

        // The caller may catch the error and carry on with this transaction, so the failed removal must not have
        // written anything.
        assert!(
            credential_is_stored(&alice, &credential).await,
            "a refused removal must keep the credential"
        );
        assert_eq!(
            count_key_packages_for(&alice, &credential).await,
            KEY_PACKAGES,
            "a refused removal must keep the key packages generated from the credential"
        );

        // A basic credential is just our client id, so a "new" one for the same client compares equal to the old one
        // and openmls declines to rotate anything. Only x509 can rotate here.
        if !case.is_x509() {
            return;
        }

        let intermediate_ca = alice.x509_chain_unchecked().find_local_intermediate_ca();
        let certificate = CertificateBundle::new_with_default_values(intermediate_ca, None);
        let new_credential = Credential::x509(case.cipher_suite(), certificate).unwrap();
        alice
            .transaction
            .add_credential_without_clientid_check(new_credential.clone())
            .unwrap();
        let new_credential = CredentialRef::from_credential(&new_credential);
        conversation.set_credential_by_ref_notify(&new_credential).await;

        let removed = alice
            .transaction
            .remove_credential(&credential)
            .await
            .expect("a credential no conversation uses any more can be removed");
        assert!(removed, "removal must report that the credential was deleted");
        assert!(!credential_is_stored(&alice, &credential).await);
        assert_eq!(count_key_packages_for(&alice, &credential).await, 0);
    }

    /// An X509 credential renewed over the same key pair can be stored next to the original. Each keeps its own key
    /// packages, conversations keep using the original until they are moved to the renewal, and once they have been,
    /// the original can be removed.
    #[apply(all_cred_cipher)]
    async fn renewed_x509_credential_coexists_with_the_original(case: TestContext) {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        use crate::test_utils::x509::PkiKeypair;

        /// How much later the renewal expires than the original.
        const RENEWAL: u64 = 86_400;
        /// Slack for the seconds which pass between computing the renewal's lifetime and issuing it.
        const CLOCK_TOLERANCE: u64 = 5;
        /// Test certificates start their validity a second in the past, so they also expire a second early.
        const BACKDATING: u64 = 1;

        // A basic credential has no expiration date, so there's nothing to renew.
        if !case.is_x509() {
            return;
        }

        let [alice] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let database = alice.transaction.database().unwrap();
        let original_ref = alice.initial_credential.clone();
        let original = original_ref.load(&*database).await.unwrap();

        // Issue a certificate for the same client and key pair, which expires a day after the original.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let key_pair =
            PkiKeypair::new(case.signature_scheme(), original.signature_key_pair.private().to_vec()).unwrap();
        let certificate = CertificateBundle::new_with_expiration(
            "alice_wire",
            "Alice Smith",
            Some(&original.client_id().to_owned()),
            Some(key_pair),
            alice.x509_chain_unchecked().find_local_intermediate_ca(),
            Some(Duration::from_secs(original.expiration_date() + RENEWAL - now)),
        );
        let renewed = Credential::x509(case.cipher_suite(), certificate).unwrap();
        assert_eq!(
            renewed.signature_key_pair.public(),
            original.signature_key_pair.public(),
            "a renewal keeps the key pair"
        );
        let expected_expiration = original.expiration_date() + RENEWAL;
        assert!(
            (expected_expiration - BACKDATING..=expected_expiration + CLOCK_TOLERANCE)
                .contains(&renewed.expiration_date()),
            "the renewal expires when its certificate does: expected about {expected_expiration}, got {}",
            renewed.expiration_date()
        );

        let renewed_ref = alice
            .transaction
            .add_credential(renewed.clone())
            .await
            .expect("a renewed credential can be stored next to the original");
        assert_eq!(renewed_ref.public_key_hash(), original_ref.public_key_hash());
        assert_eq!(renewed_ref.r#type(), original_ref.r#type());

        // Each ref resolves to its own credential.
        assert_eq!(original_ref.load(&*database).await.unwrap(), original);
        assert_eq!(renewed_ref.load(&*database).await.unwrap(), renewed);

        // Key packages belong to the credential they were generated from, not to every credential with that key.
        let original_key_packages = count_key_packages_for(&alice, &original_ref).await;
        alice.new_keypackage_from_ref(renewed_ref.clone(), None).await;
        assert_eq!(count_key_packages_for(&alice, &renewed_ref).await, 1);
        assert_eq!(
            count_key_packages_for(&alice, &original_ref).await,
            original_key_packages
        );

        assert_eq!(
            *conversation.guard().await.credential().await.unwrap(),
            original,
            "adding a renewal doesn't move existing conversations to it"
        );

        let conversation = conversation.set_credential_by_ref_notify(&renewed_ref).await;
        assert_eq!(*conversation.guard().await.credential().await.unwrap(), renewed);

        // Removing a credential which a conversation still uses fails, so this also shows that the stored
        // conversation now references the renewal rather than the original.
        let removed = alice
            .transaction
            .remove_credential(&original_ref)
            .await
            .expect("the original can be removed once no conversation uses it");
        assert!(removed, "removal must report that the credential was deleted");
        assert!(!credential_is_stored(&alice, &original_ref).await);
        assert!(credential_is_stored(&alice, &renewed_ref).await);
        assert_eq!(*conversation.guard().await.credential().await.unwrap(), renewed);
    }
}
