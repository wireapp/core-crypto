use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsCryptoProvider as _, random::OpenMlsRand as _};

use super::error::{Error, Result};
use crate::{
    CertificateBundle, Ciphersuite, Credential, CredentialFindFilters, CredentialRef, CredentialType, E2eiEnrollment,
    MlsError, RecursiveError,
    e2e_identity::{E2eiSignatureKeypair, NewCrlDistributionPoints},
    mls::credential::{ext::CredentialExt, x509::CertificatePrivateKey},
    transaction_context::TransactionContext,
};

impl TransactionContext {
    async fn new_sign_keypair(&self, ciphersuite: Ciphersuite) -> Result<E2eiSignatureKeypair> {
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;

        let sign_keypair = &SignatureKeyPair::new(
            ciphersuite.signature_algorithm(),
            &mut *mls_provider
                .rand()
                .borrow_rand()
                .map_err(MlsError::wrap("borrowing rng"))?,
        )
        .map_err(MlsError::wrap("generating new sign keypair"))?;

        sign_keypair
            .try_into()
            .map_err(RecursiveError::e2e_identity("creating E2eiSignatureKeypair"))
            .map_err(Into::into)
    }

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
        let client_id = self
            .client_id()
            .await
            .map_err(RecursiveError::transaction("getting client id"))?;

        let sign_keypair = self.new_sign_keypair(ciphersuite).await?;

        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            ciphersuite,
            Some(sign_keypair),
            false, // no x509 credential yet at this point so no OIDC authn yet so no refresh token to restore
        )
        .map_err(RecursiveError::e2e_identity("creating new enrollment"))
        .map_err(Into::into)
    }

    /// Generates an E2EI enrollment instance for a E2EI client (with a X509 certificate credential)
    /// having to change/rotate their credential, either because the former one is expired or it
    /// has been revoked. As a consequence, this method does not support changing neither ClientId which
    /// should remain the same as the previous one. It lets you change the DisplayName or the handle
    /// if you need to. Once the enrollment is finished, use the instance in [TransactionContext::save_x509_credential]
    /// to do the rotation.
    pub async fn e2ei_new_rotate_enrollment(
        &self,
        display_name: Option<String>,
        handle: Option<String>,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Result<E2eiEnrollment> {
        // look for existing credential of type x509. If there isn't, then this method has been misused
        let find_filters = CredentialFindFilters::builder()
            .credential_type(CredentialType::X509)
            .ciphersuite(ciphersuite)
            .build();
        let credentials = self
            .find_credentials(find_filters)
            .await
            .map_err(RecursiveError::transaction("finding x509 credentials"))?;
        let credential_ref = credentials
            .first()
            .ok_or(Error::MissingExistingClient(CredentialType::X509))?;

        let database = self
            .database()
            .await
            .map_err(RecursiveError::transaction("getting database"))?;
        let credential = credential_ref
            .load(&database)
            .await
            .map_err(RecursiveError::mls_credential_ref("loading credential"))?;

        let client_id = self
            .client_id()
            .await
            .map_err(RecursiveError::transaction("getting client id"))?;
        let sign_keypair = self.new_sign_keypair(ciphersuite).await?;
        let existing_identity = credential
            .to_mls_credential_with_key()
            .extract_identity(ciphersuite, None)
            .map_err(RecursiveError::mls_credential("extracting identity"))?
            .x509_identity
            .ok_or(Error::ImplementationError)?;

        let display_name = display_name.unwrap_or(existing_identity.display_name);
        let handle = handle.unwrap_or(existing_identity.handle);

        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            ciphersuite,
            Some(sign_keypair),
            true, /* Since we are renewing an e2ei certificate we MUST have already generated one hence we MUST
                   * already have done an OIDC authn and gotten a refresh token from it */
        )
        .map_err(RecursiveError::e2e_identity("creating new enrollment"))
        .map_err(Into::into)
    }

    /// Saves a new X509 credential. Requires first
    /// having enrolled a new X509 certificate with either [TransactionContext::e2ei_new_activation_enrollment]
    /// or [TransactionContext::e2ei_new_rotate_enrollment].
    ///
    /// # Expected actions to perform after this function (in this order)
    /// 1. Set the credential to the return value of this function for each conversation via
    ///    [crate::mls::conversation::ConversationGuard::set_credential_by_ref]
    /// 2. Generate new key packages with [Self::generate_keypackage]
    /// 3. Use these to replace the stale ones the in the backend
    /// 4. Delete the old credentials and keypackages locally using [Self::remove_credential]
    pub async fn save_x509_credential(
        &self,
        enrollment: &mut E2eiEnrollment,
        certificate_chain: String,
    ) -> Result<(CredentialRef, NewCrlDistributionPoints)> {
        let sk = enrollment
            .get_sign_key_for_mls()
            .map_err(RecursiveError::e2e_identity("getting sign key for mls"))?;
        let ciphersuite = *enrollment.ciphersuite();
        let signature_scheme = ciphersuite.signature_algorithm();

        let pki_environment = self
            .pki_environment()
            .await
            .map_err(RecursiveError::transaction("getting pki environment"))?;
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                pki_environment
                    .mls_pki_env_provider()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(Error::PkiEnvironmentUnset)?,
            )
            .await
            .map_err(RecursiveError::e2e_identity("getting certificate response"))?;

        let private_key = CertificatePrivateKey::new(sk);

        let crl_new_distribution_points = self.extract_dp_on_init(&certificate_chain[..]).await?;

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
            signature_scheme,
        };

        let credential = Credential::x509(ciphersuite, cert_bundle).map_err(RecursiveError::mls_credential(
            "creating new x509 credential from certificate bundle in save_x509_credential",
        ))?;

        let credential_ref = self
            .add_credential(credential)
            .await
            .map_err(RecursiveError::transaction(
                "saving and adding credential in save_x509_credential",
            ))?;

        Ok((credential_ref, crl_new_distribution_points))
    }
}

#[cfg(test)]
mod tests {

    use openmls::prelude::SignaturePublicKey;

    use super::*;
    use crate::{
        e2e_identity::enrollment::test_utils as e2ei_utils, mls::credential::ext::CredentialExt, test_utils::*,
        transaction_context::key_package::INITIAL_KEYING_MATERIAL_COUNT,
    };

    pub(crate) mod all {
        use e2ei_utils::E2EI_EXPIRY;

        use super::*;
        use crate::{CredentialRef, test_utils::context::TEAM};

        #[apply(all_cred_cipher)]
        async fn enrollment_should_rotate_all(case: TestContext) {
            let [alice, bob, charlie] = case.sessions_with_pki_env().await;
            Box::pin(async move {
                const N: usize = 50;

                let mut conversations = vec![];

                let x509_test_chain = bob.x509_chain_unchecked();

                for _ in 0..N {
                    let conversation = case.create_conversation([&alice, &bob]).await;
                    conversations.push(conversation)
                }

                let alice_credential_ref = &alice.initial_credential;

                for _ in 0..INITIAL_KEYING_MATERIAL_COUNT {
                    alice
                        .transaction
                        .generate_keypackage(alice_credential_ref, None)
                        .await
                        .unwrap();
                }

                // Count the key material before the rotation to compare it later
                let before_rotate = alice.transaction.count_entities().await;
                assert_eq!(before_rotate.key_package, INITIAL_KEYING_MATERIAL_COUNT);

                assert_eq!(before_rotate.hpke_private_key, INITIAL_KEYING_MATERIAL_COUNT);

                // 1 is created per new KeyPackage
                assert_eq!(before_rotate.encryption_keypair, INITIAL_KEYING_MATERIAL_COUNT);

                assert_eq!(before_rotate.credential, 1);
                let old_credential = alice_credential_ref.clone();

                let is_renewal = case.credential_type == CredentialType::X509;

                let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                    &alice.transaction,
                    &case,
                    x509_test_chain,
                    &alice.get_e2ei_client_id().await.to_uri(),
                    is_renewal,
                    e2ei_utils::init_activation_or_rotation,
                    e2ei_utils::noop_restore,
                )
                .await
                .unwrap();

                let (credential_ref, _) = alice
                    .transaction
                    .save_x509_credential(&mut enrollment, cert)
                    .await
                    .unwrap();

                let result = alice
                    .update_credential_in_all_conversations(conversations, &credential_ref, *enrollment.ciphersuite())
                    .await
                    .unwrap();

                let after_rotate = alice.transaction.count_entities().await;

                // rotation neither creates nor deletes keypackages
                assert_eq!(after_rotate.key_package, before_rotate.key_package);

                // and a new Credential has been persisted in the keystore
                assert_eq!(after_rotate.credential - before_rotate.credential, 1);

                for commit in result.commits {
                    let conversation = commit
                        .notify_members_and_verify_sender_with_credential(&credential_ref)
                        .await;

                    conversation
                        .verify_credential_handle_and_name(
                            e2ei_utils::NEW_HANDLE,
                            e2ei_utils::NEW_DISPLAY_NAME,
                            &credential_ref,
                        )
                        .await;
                }

                // Alice has to delete her old KeyPackages
                // But first let's verify the previous credential material is present
                assert!(
                    alice
                        .find_credential(&old_credential.public_key().into())
                        .await
                        .is_some()
                );

                // rotation neither creates nor deletes private keys or key packages
                let before_delete = alice.transaction.count_entities().await;
                assert_eq!(before_delete.hpke_private_key, before_rotate.hpke_private_key);
                assert_eq!(before_delete.key_package, before_rotate.key_package);

                // Checks are done, now let's delete the old credential.
                // This should have the consequence to purge the all the stale keypackages as well.
                alice.transaction.remove_credential(alice_credential_ref).await.unwrap();

                // No keypackages were automatically created.
                let nb_x509_kp = alice
                    .count_key_package(case.ciphersuite(), Some(CredentialType::X509))
                    .await;
                assert_eq!(nb_x509_kp, 0);
                // Because we removed her old credential, Alice should not anymore have any Basic KeyPackages
                let nb_basic_kp = alice
                    .count_key_package(case.ciphersuite(), Some(CredentialType::Basic))
                    .await;
                assert_eq!(nb_basic_kp, 0);

                // Also the old Credential has been removed from the keystore
                let after_delete = alice.transaction.count_entities().await;
                assert_eq!(after_delete.credential, 1);
                let database = alice.transaction.database().await.unwrap();
                let err = old_credential.load(&database).await.unwrap_err();
                assert!(matches!(
                    err,
                    crate::mls::credential::credential_ref::Error::CredentialNotFound
                ));

                // and all her Private HPKE keys...
                assert_eq!(after_delete.hpke_private_key, 0);

                // ...and encryption keypairs
                assert_eq!(after_delete.encryption_keypair, 0);

                // Now charlie tries to add Alice to a conversation
                // (the create_conversation helper implicitly generates keypackages as needed)
                let credential = alice
                    .find_any_credential(case.ciphersuite(), CredentialType::X509)
                    .await;
                let credential_ref = CredentialRef::from_credential(&credential);
                let conversation = case
                    .create_conversation([&charlie])
                    .await
                    .invite_with_credential_notify([(&alice, &credential_ref)])
                    .await;
                assert!(conversation.is_functional_and_contains([&alice, &charlie]).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_restore_credentials_in_order(case: TestContext) {
            let [alice] = case.sessions_with_pki_env().await;
            Box::pin(async move {
                let x509_test_chain = alice.x509_chain_unchecked();

                case.create_conversation([&alice]).await;

                let initial_cred_ref = alice.initial_credential.clone();
                let old_cb = initial_cred_ref
                    .load(&alice.transaction.database().await.unwrap())
                    .await
                    .unwrap();

                // simulate a real rotation where both credential are not created within the same second
                // we only have a precision of 1 second for the `created_at` field of the Credential
                smol::Timer::after(core::time::Duration::from_secs(1)).await;

                let is_renewal = case.credential_type == CredentialType::X509;

                let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                    &alice.transaction,
                    &case,
                    x509_test_chain,
                    &alice.get_e2ei_client_id().await.to_uri(),
                    is_renewal,
                    e2ei_utils::init_activation_or_rotation,
                    e2ei_utils::noop_restore,
                )
                .await
                .unwrap();

                let (credential_ref, _) = alice
                    .transaction
                    .save_x509_credential(&mut enrollment, cert)
                    .await
                    .unwrap();

                // So alice has a new Credential as expected
                let credential = credential_ref
                    .load(&alice.transaction.database().await.unwrap())
                    .await
                    .unwrap();
                let identity = credential
                    .to_mls_credential_with_key()
                    .extract_identity(case.ciphersuite(), None)
                    .unwrap();
                assert_eq!(
                    identity.x509_identity.as_ref().unwrap().display_name,
                    e2ei_utils::NEW_DISPLAY_NAME
                );
                assert_eq!(
                    identity.x509_identity.as_ref().unwrap().handle,
                    format!("wireapp://%40{}@world.com", e2ei_utils::NEW_HANDLE)
                );

                // but keeps her old one since it's referenced from some KeyPackages
                let old_spk = SignaturePublicKey::from(initial_cred_ref.public_key());
                let old_cb_found = alice.find_credential(&old_spk).await.unwrap();
                assert_eq!(std::sync::Arc::new(old_cb), old_cb_found);
                let old_nb_identities = {
                    // Let's simulate an app crash, client gets deleted and restored from keystore
                    let all_credentials = CredentialRef::get_all(&alice.transaction.database().await.unwrap())
                        .await
                        .unwrap();

                    assert_eq!(all_credentials.len(), 2);
                    all_credentials.len()
                };
                let keystore = &alice.transaction.database().await.unwrap();
                keystore.commit_transaction().await.unwrap();
                keystore.new_transaction().await.unwrap();

                alice.reinit_session(alice.identifier.clone()).await;

                let new_session = alice.session().await;
                // Verify that Alice has the same credentials
                let cb = new_session
                    .find_credential_by_public_key(&credential.to_mls_credential_with_key().signature_key)
                    .await
                    .unwrap();
                let identity = cb
                    .to_mls_credential_with_key()
                    .extract_identity(case.ciphersuite(), None)
                    .unwrap();

                assert_eq!(
                    identity.x509_identity.as_ref().unwrap().display_name,
                    e2ei_utils::NEW_DISPLAY_NAME
                );
                assert_eq!(
                    identity.x509_identity.as_ref().unwrap().handle,
                    format!("wireapp://%40{}@world.com", e2ei_utils::NEW_HANDLE)
                );

                assert_eq!(
                    CredentialRef::get_all(new_session.database()).await.unwrap().len(),
                    old_nb_identities
                );
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn rotate_should_roundtrip(case: TestContext) {
            let [alice, bob] = case.sessions_with_pki_env().await;
            Box::pin(async move {
                let x509_test_chain = alice.x509_chain_unchecked();

                let conversation = case.create_conversation([&alice, &bob]).await;
                // Alice's turn
                const ALICE_NEW_HANDLE: &str = "new_alice_wire";
                const ALICE_NEW_DISPLAY_NAME: &str = "New Alice Smith";

                fn init_alice(wrapper: e2ei_utils::E2eiInitWrapper<'_>) -> e2ei_utils::InitFnReturn<'_> {
                    Box::pin(async move {
                        let e2ei_utils::E2eiInitWrapper { context: cc, case } = wrapper;
                        let cs = case.ciphersuite();
                        match case.credential_type {
                            CredentialType::Basic => {
                                cc.e2ei_new_activation_enrollment(
                                    ALICE_NEW_DISPLAY_NAME.to_string(),
                                    ALICE_NEW_HANDLE.to_string(),
                                    Some(TEAM.to_string()),
                                    E2EI_EXPIRY,
                                    cs,
                                )
                                .await
                            }
                            CredentialType::X509 => {
                                cc.e2ei_new_rotate_enrollment(
                                    Some(ALICE_NEW_DISPLAY_NAME.to_string()),
                                    Some(ALICE_NEW_HANDLE.to_string()),
                                    Some(TEAM.to_string()),
                                    E2EI_EXPIRY,
                                    cs,
                                )
                                .await
                            }
                        }
                        .map_err(RecursiveError::transaction("creating new enrollment"))
                        .map_err(Into::into)
                    })
                }

                let is_renewal = case.credential_type == CredentialType::X509;

                let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                    &alice.transaction,
                    &case,
                    x509_test_chain,
                    &alice.get_e2ei_client_id().await.to_uri(),
                    is_renewal,
                    init_alice,
                    e2ei_utils::noop_restore,
                )
                .await
                .unwrap();

                // all credentials need to be distinguishable by type, scheme, and timestamp
                // we need to wait a second so the new credential has a distinct timestamp
                // (our DB has a timestamp resolution of 1s)
                smol::Timer::after(std::time::Duration::from_secs(1)).await;

                let (credential_ref, _) = alice
                    .transaction
                    .save_x509_credential(&mut enrollment, cert)
                    .await
                    .unwrap();
                let conversation = conversation
                    .set_credential_by_ref_notify_and_verify_sender(&credential_ref)
                    .await;

                conversation
                    .verify_credential_handle_and_name(ALICE_NEW_HANDLE, ALICE_NEW_DISPLAY_NAME, &credential_ref)
                    .await;

                // Bob's turn
                const BOB_NEW_HANDLE: &str = "new_bob_wire";
                const BOB_NEW_DISPLAY_NAME: &str = "New Bob Smith";

                fn init_bob(wrapper: e2ei_utils::E2eiInitWrapper<'_>) -> e2ei_utils::InitFnReturn<'_> {
                    Box::pin(async move {
                        let e2ei_utils::E2eiInitWrapper { context: cc, case } = wrapper;
                        let cs = case.ciphersuite();
                        match case.credential_type {
                            CredentialType::Basic => {
                                cc.e2ei_new_activation_enrollment(
                                    BOB_NEW_DISPLAY_NAME.to_string(),
                                    BOB_NEW_HANDLE.to_string(),
                                    Some(TEAM.to_string()),
                                    E2EI_EXPIRY,
                                    cs,
                                )
                                .await
                            }
                            CredentialType::X509 => {
                                cc.e2ei_new_rotate_enrollment(
                                    Some(BOB_NEW_DISPLAY_NAME.to_string()),
                                    Some(BOB_NEW_HANDLE.to_string()),
                                    Some(TEAM.to_string()),
                                    E2EI_EXPIRY,
                                    cs,
                                )
                                .await
                            }
                        }
                        .map_err(RecursiveError::transaction("creating new enrollment"))
                        .map_err(Into::into)
                    })
                }
                let is_renewal = case.credential_type == CredentialType::X509;

                let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                    &bob.transaction,
                    &case,
                    x509_test_chain,
                    &bob.get_e2ei_client_id().await.to_uri(),
                    is_renewal,
                    init_bob,
                    e2ei_utils::noop_restore,
                )
                .await
                .unwrap();

                let (cred_ref, _) = bob
                    .transaction
                    .save_x509_credential(&mut enrollment, cert)
                    .await
                    .unwrap();

                let conversation = conversation
                    .acting_as(&bob)
                    .await
                    .set_credential_by_ref_notify_and_verify_sender(&cred_ref)
                    .await;

                conversation
                    .acting_as(&bob)
                    .await
                    .verify_credential_handle_and_name(BOB_NEW_HANDLE, BOB_NEW_DISPLAY_NAME, &cred_ref)
                    .await;
            })
            .await
        }
    }

    mod one {
        use super::*;
        use crate::{CredentialRef, mls::conversation::Conversation as _};

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

                    let credential_ref = CredentialRef::from_credential(&cb);
                    // Alice issues an Update commit to replace her current identity
                    let conversation = conversation
                        .set_credential_by_ref_notify_and_verify_sender(&credential_ref)
                        .await;

                    // Finally, Alice merges her commit and verifies her new identity gets applied
                    conversation
                        .verify_credential_handle_and_name(new_handle, new_display_name, &credential_ref)
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
                let credential = alice
                    .save_new_credential(&case, new_handle, new_display_name, intermediate_ca)
                    .await;

                // Alice issues an Update commit to replace her current identity
                let conversation = conversation.set_credential_unmerged(&credential).await.finish();

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
                //
                let credential_ref = CredentialRef::from_credential(&credential);
                let conversation = commit
                    .finish()
                    .commit_pending_proposals()
                    .await
                    .notify_members_and_verify_sender_with_credential(&credential_ref)
                    .await;

                // Finally, Alice merges her commit and verifies her new identity gets applied
                conversation
                    .verify_credential_handle_and_name(new_handle, new_display_name, &credential_ref)
                    .await;

                let final_count = alice.transaction.count_entities().await;
                assert_eq!(init_count.encryption_keypair, final_count.encryption_keypair);
                // TODO: there is no efficient way to clean a credential when alice merges her pending commit. Tracking
                // issue: WPB-9594 One option would be to fetch all conversations and see if Alice is
                // never represented with the said Credential but let's be honest this is not very
                // efficient. The other option would be to get rid of having an implicit KeyPackage for
                // the creator of a conversation assert_eq!(init_count.credential,
                // final_count.credential);
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
                let alice_cred_ref = &alice.initial_credential;
                let bob_cred_ref = &bob.initial_credential;
                let conversation = case
                    .create_conversation_with_credentials([(&alice, alice_cred_ref), (&bob, bob_cred_ref)])
                    .await;
                let id = conversation.id().clone();

                let x509_test_chain = alice.x509_chain_unchecked();
                let intermediate_ca = x509_test_chain.find_local_intermediate_ca();

                // Alice creates a new Credential, updating her handle/display_name
                let alice_cid = alice.get_client_id().await;
                let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                let credential = alice
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
                let credential_ref = CredentialRef::from_credential(&credential);
                let conversation = conversation
                    .set_credential_by_ref_notify_and_verify_sender(&credential_ref)
                    .await;

                // Finally, Alice merges her commit and verifies her new identity gets applied
                conversation
                    .verify_credential_handle_and_name(new_handle, new_display_name, &credential_ref)
                    .await;
            })
            .await
        }
    }
}
