use core_crypto_keystore::{CryptoKeystoreMls, connection::FetchFromDatabase, entities::StoredKeypackage};
use openmls::prelude::KeyPackage;
use openmls_traits::OpenMlsCryptoProvider;

use super::error::{Error, Result};
use crate::{
    CertificateBundle, Ciphersuite, Credential, CredentialType, E2eiEnrollment, KeystoreError, MlsError,
    RecursiveError, e2e_identity::NewCrlDistributionPoints, mls::credential::x509::CertificatePrivateKey,
    transaction_context::TransactionContext,
};

impl TransactionContext {
    /// Generates an E2EI enrollment instance for a "regular" client (with a Basic credential)
    /// willing to migrate to E2EI. As a consequence, this method does not support changing the
    /// ClientId which should remain the same as the Basic one.
    /// Once the enrollment is finished, use the instance in [TransactionContext::save_x509_credential]
    /// to save the new credential.
    pub async fn e2ei_new_activation_enrollment(
        &self,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Result<E2eiEnrollment> {
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        // look for existing credential of type basic. If there isn't, then this method has been misused
        let cb = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?
            .find_most_recent_credential(ciphersuite.signature_algorithm(), CredentialType::Basic)
            .await
            .map_err(|_| Error::MissingExistingClient(CredentialType::Basic))?;
        let client_id = cb.mls_credential().identity().to_owned().into();

        let sign_keypair = Some(
            cb.signature_key()
                .try_into()
                .map_err(RecursiveError::e2e_identity("creating E2eiSignatureKeypair"))?,
        );

        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            &mls_provider,
            ciphersuite,
            sign_keypair,
            false, // no x509 credential yet at this point so no OIDC authn yet so no refresh token to restore
        )
        .map_err(RecursiveError::e2e_identity("creating new enrollment"))
        .map_err(Into::into)
    }

    /// Saves a new X509 credential. Requires first
    /// having enrolled a new X509 certificate with [TransactionContext::e2ei_new_activation_enrollment].
    ///
    /// # Expected actions to perform after this function (in this order)
    /// 1. Rotate credentials for each conversation in [crate::mls::conversation::ConversationGuard::e2ei_rotate]
    /// 2. Generate new key packages with [crate::mls::session::Session::request_key_packages]
    /// 3. Use these to replace the stale ones the in the backend
    /// 4. Delete the stale ones locally using [Self::delete_stale_key_packages]
    ///     * This is the last step because you might still need the old key packages to avoid
    ///       an orphan welcome message
    pub async fn save_x509_credential(
        &self,
        enrollment: &mut E2eiEnrollment,
        certificate_chain: String,
    ) -> Result<NewCrlDistributionPoints> {
        let sk = enrollment
            .get_sign_key_for_mls()
            .map_err(RecursiveError::e2e_identity("getting sign key for mls"))?;
        let signature_scheme = enrollment.ciphersuite().signature_algorithm();

        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                mls_provider
                    .authentication_service()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(Error::PkiEnvironmentUnset)?,
            )
            .await
            .map_err(RecursiveError::e2e_identity("getting certificate response"))?;

        let private_key = CertificatePrivateKey {
            value: sk,
            signature_scheme,
        };

        let crl_new_distribution_points = self.extract_dp_on_init(&certificate_chain[..]).await?;

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
        };
        let client = &self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting session"))?;

        let credential = Credential::x509(cert_bundle).map_err(RecursiveError::mls_credential(
            "creating new x509 credential from certificate bundle in save_x509_credential",
        ))?;
        client
            .add_credential(credential)
            .await
            .map_err(RecursiveError::mls_client(
                "saving and adding credential in save_x509_credential",
            ))?;

        Ok(crl_new_distribution_points)
    }

    /// Deletes all key packages whose leaf node's credential does not match the most recently
    /// saved x509 credential with the provided signature scheme.
    pub async fn delete_stale_key_packages(&self, cipher_suite: Ciphersuite) -> Result<()> {
        let signature_scheme = cipher_suite.signature_algorithm();
        let keystore = self
            .keystore()
            .await
            .map_err(RecursiveError::transaction("getting keystore"))?;
        let nb_kp = keystore
            .count::<StoredKeypackage>()
            .await
            .map_err(KeystoreError::wrap("counting key packages"))?;
        let kps: Vec<KeyPackage> = keystore
            .mls_fetch_keypackages(nb_kp as u32)
            .await
            .map_err(KeystoreError::wrap("fetching key packages"))?;
        let client = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?;

        let cb = client
            .find_most_recent_credential(signature_scheme, CredentialType::X509)
            .await
            .map_err(RecursiveError::mls_client("finding most recent credential"))?;

        let mut kp_refs = vec![];

        let provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        for kp in kps {
            let kp_cred = kp.leaf_node().credential().mls_credential();
            let local_cred = cb.mls_credential().mls_credential();
            if kp_cred != local_cred {
                let kpr = kp
                    .hash_ref(provider.crypto())
                    .map_err(MlsError::wrap("computing keypackage hashref"))?;
                kp_refs.push(kpr);
            };
        }
        self.delete_keypackages(kp_refs)
            .await
            .map_err(RecursiveError::transaction("deleting keypackages"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    mod one {
        use super::*;
        use crate::mls::conversation::Conversation as _;

        #[apply(all_cred_cipher)]
        pub async fn should_rotate_one_conversations_credential(case: TestContext) {
            if case.is_x509() {
                let [alice, bob] = case.sessions().await;
                Box::pin(async move {
                    let conversation = case.create_conversation([&alice, &bob]).await;
                    let id = conversation.id().clone();

                    let init_count = alice.transaction.count_entities().await;
                    let x509_test_chain = alice.x509_chain_unchecked();

                    let intermediate_ca = x509_test_chain.find_local_intermediate_ca();

                    // all credentials need to be distinguishable by type, scheme, and timestamp
                    // we need to wait a second so the new credential has a distinct timestamp
                    // (our DB has a timestamp resolution of 1s)
                    smol::Timer::after(std::time::Duration::from_secs(1)).await;

                    // Alice creates a new Credential, updating her handle/display_name
                    let alice_cid = alice.get_client_id().await;
                    let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                    let cb = alice
                        .save_new_credential(&case, new_handle, new_display_name, intermediate_ca)
                        .await;

                    // Verify old identity is still there in the MLS group
                    let alice_old_identities = alice
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .get_device_identities(&[alice_cid])
                        .await
                        .unwrap();
                    let alice_old_identity = alice_old_identities.first().unwrap();
                    assert_ne!(
                        alice_old_identity.x509_identity.as_ref().unwrap().display_name,
                        new_display_name
                    );
                    assert_ne!(
                        alice_old_identity.x509_identity.as_ref().unwrap().handle,
                        format!("{new_handle}@world.com")
                    );

                    // Alice issues an Update commit to replace her current identity
                    let conversation = conversation.e2ei_rotate_notify_and_verify_sender(Some(&cb)).await;

                    // Finally, Alice merges her commit and verifies her new identity gets applied
                    conversation
                        .verify_credential_handle_and_name(new_handle, new_display_name)
                        .await;

                    let final_count = alice.transaction.count_entities().await;
                    assert_eq!(init_count.encryption_keypair, final_count.encryption_keypair);
                    assert_eq!(
                        init_count.epoch_encryption_keypair,
                        final_count.epoch_encryption_keypair
                    );
                    assert_eq!(init_count.key_package, final_count.key_package);
                })
                .await
            }
        }

        #[apply(all_cred_cipher)]
        pub async fn rotate_should_be_renewable_when_commit_denied(case: TestContext) {
            if !case.is_x509() {
                return;
            }

            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let init_count = alice.transaction.count_entities().await;

                let x509_test_chain = alice.x509_chain_unchecked();

                let intermediate_ca = x509_test_chain.find_local_intermediate_ca();

                // In this case Alice will try to rotate her credential but her commit will be denied
                // by the backend (because another commit from Bob had precedence)

                // all credentials need to be distinguishable by type, scheme, and timestamp
                // we need to wait a second so the new credential has a distinct timestamp
                // (our DB has a timestamp resolution of 1s)
                smol::Timer::after(std::time::Duration::from_secs(1)).await;

                // Alice creates a new Credential, updating her handle/display_name
                let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                let cb = alice
                    .save_new_credential(&case, new_handle, new_display_name, intermediate_ca)
                    .await;

                // Alice issues an Update commit to replace her current identity
                let conversation = conversation.e2ei_rotate_unmerged(&cb).await.finish();

                // Meanwhile, Bob creates a simple commit
                // accepted by the backend
                // Alice decrypts the commit...
                let (commit, decrypted) = conversation
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;

                let decrypted = decrypted.unwrap();

                // Alice's previous rotate commit should have been renewed so that she can re-commit it
                assert_eq!(decrypted.proposals.len(), 1);

                // Bob verifies that now Alice is represented with her new identity
                let conversation = commit
                    .finish()
                    .commit_pending_proposals()
                    .await
                    .notify_members_and_verify_sender()
                    .await;

                // Finally, Alice merges her commit and verifies her new identity gets applied
                conversation
                    .verify_credential_handle_and_name(new_handle, new_display_name)
                    .await;

                let final_count = alice.transaction.count_entities().await;
                assert_eq!(init_count.encryption_keypair, final_count.encryption_keypair);
                // TODO: there is no efficient way to clean a credential when alice merges her pending commit. Tracking issue: WPB-9594
                // One option would be to fetch all conversations and see if Alice is never represented with the said Credential
                // but let's be honest this is not very efficient.
                // The other option would be to get rid of having an implicit KeyPackage for the creator of a conversation
                // assert_eq!(init_count.credential, final_count.credential);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn rotate_should_replace_existing_basic_credentials(case: TestContext) {
            if !case.is_x509() {
                return;
            }

            let [alice, bob] = case.sessions_basic_with_pki_env().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation_with_credential_type(CredentialType::Basic, [&alice, &bob])
                    .await;
                let id = conversation.id().clone();

                let x509_test_chain = alice.x509_chain_unchecked();
                let intermediate_ca = x509_test_chain.find_local_intermediate_ca();

                // Alice creates a new Credential, updating her handle/display_name
                let alice_cid = alice.get_client_id().await;
                let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                alice
                    .save_new_credential(&case, new_handle, new_display_name, intermediate_ca)
                    .await;

                // Verify old identity is a basic identity in the MLS group
                let alice_old_identities = alice
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .get_device_identities(&[alice_cid])
                    .await
                    .unwrap();
                let alice_old_identity = alice_old_identities.first().unwrap();
                assert_eq!(alice_old_identity.credential_type, CredentialType::Basic);
                assert_eq!(alice_old_identity.x509_identity, None);

                // Alice issues an Update commit to replace her current identity
                // Bob decrypts the commit...
                // ...and verifies that now Alice is represented with her new identity
                let conversation = conversation.e2ei_rotate_notify_and_verify_sender(None).await;

                // Finally, Alice merges her commit and verifies her new identity gets applied
                conversation
                    .verify_credential_handle_and_name(new_handle, new_display_name)
                    .await;
            })
            .await
        }
    }
}
